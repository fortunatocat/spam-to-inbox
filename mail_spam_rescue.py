#!/usr/bin/env python3
"""Configurable Spam -> Inbox helper. Python 3.10+, standard library only."""
import argparse
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
import hashlib
import imaplib
import json
import os
from pathlib import Path
import poplib
import re
import sqlite3
import ssl
import sys
import time


class MailError(Exception):
    pass


def checked(result, operation):
    status, data = result
    if status != 'OK':
        raise MailError(operation + ' rejected by server')
    return data


def folder_arg(name):
    """Quote a mailbox using IMAP modified UTF-7, including localized names."""
    if not isinstance(name, str) or not name or any(ord(c) < 32 for c in name):
        raise ValueError('invalid folder name')
    result, pending = [], []

    def flush():
        if pending:
            encoded = base64.b64encode(''.join(pending).encode('utf-16-be')).decode()
            result.append('&' + encoded.rstrip('=').replace('/', ',') + '-')
            pending.clear()

    for char in name:
        if 32 <= ord(char) <= 126:
            flush()
            result.append('&-' if char == '&' else char)
        else:
            pending.append(char)
    flush()
    return '"' + ''.join(result).replace('\\', '\\\\').replace('"', '\\"') + '"'


def read_accounts(path):
    """Supplier-style login:password lines; never include line contents in errors."""
    accounts = {}
    for number, raw in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        fields = re.split(r'[:;\t]', line, maxsplit=1)
        if len(fields) != 2 or not fields[0].strip() or not fields[1].strip():
            raise ValueError(f'invalid accounts line {number}')
        username, password = (field.strip() for field in fields)
        if any(char.isspace() for char in username):
            raise ValueError(f'invalid username on line {number}')
        key = username.lower()
        if key in accounts and accounts[key]['password'] != password:
            raise ValueError(f'conflicting duplicate on line {number}')
        accounts.setdefault(key, dict(username=username, password=password, password_env=''))
    if not accounts:
        raise ValueError('accounts file is empty')
    return list(accounts.values())


def load_config(path):
    path = Path(path)
    config = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(config, dict):
        raise ValueError('config must be an object')
    for name, default, low, high in [('days', 3, 1, 365), ('interval_seconds', 600, 60, 86400),
                                     ('threads', 2, 1, 8), ('timeout_seconds', 30, 1, 120)]:
        value = config.setdefault(name, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError('invalid setting: ' + name)
    if 'accounts_file' in config:
        if 'accounts' in config:
            raise ValueError('choose accounts_file or accounts')
        if not isinstance(config['accounts_file'], str) or not config['accounts_file']:
            raise ValueError('accounts_file must be a path')
        account_path = Path(config['accounts_file']).expanduser()
        if not account_path.is_absolute():
            account_path = path.resolve().parent / account_path
        config['accounts'] = read_accounts(account_path)
        for account in config['accounts']:
            for protocol in ('imap', 'pop3'):
                if protocol in config:
                    account[protocol] = copy.deepcopy(config[protocol])
    accounts = config.get('accounts')
    if not isinstance(accounts, list) or not accounts:
        raise ValueError('accounts must be a nonempty list')
    seen = set()
    for account in accounts:
        if not isinstance(account, dict) or not isinstance(account.get('username'), str) or not account['username']:
            raise ValueError('each account needs username')
        for protocol in ('imap', 'pop3'):
            server = account.get(protocol)
            if protocol == 'pop3' and server is None:
                continue
            if not isinstance(server, dict) or not isinstance(server.get('host'), str) or not server['host']:
                raise ValueError('missing server: ' + protocol)
            if server.get('security', 'ssl') not in {'ssl', 'starttls'}:
                raise ValueError('security must be ssl or starttls')
            default = (993 if protocol == 'imap' else 995) if server.get('security', 'ssl') == 'ssl' else (143 if protocol == 'imap' else 110)
            port = server.setdefault('port', default)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('invalid port: ' + protocol)
            if protocol == 'imap':
                folders = server.setdefault('spam_folders', ['Spam', 'Junk'])
                if not isinstance(folders, list) or not folders:
                    raise ValueError('spam_folders must be a nonempty list')
                for folder in folders:
                    folder_arg(folder)
                folder_arg(server.setdefault('inbox_folder', 'INBOX'))
                if any(folder.casefold() == server['inbox_folder'].casefold() for folder in folders):
                    raise ValueError('spam and inbox folders must differ')
        identity = (account['imap']['host'].lower(), account['imap']['port'], account['username'].lower())
        if identity in seen:
            raise ValueError('duplicate account')
        seen.add(identity)
    return config


def password_for(account):
    env_name = account.get('password_env', '')
    password = os.environ.get(env_name, '') if env_name else ''
    password = password or account.get('password', '')
    if not isinstance(password, str) or not password:
        raise MailError('password missing; set password_env or password in config')
    return password


def connect_imap(account, timeout):
    settings = account['imap']
    context = ssl.create_default_context()
    box = None
    try:
        if settings.get('security', 'ssl') == 'ssl':
            box = imaplib.IMAP4_SSL(settings['host'], settings['port'], ssl_context=context, timeout=timeout)
        else:
            box = imaplib.IMAP4(settings['host'], settings['port'], timeout=timeout)
            checked(box.starttls(ssl_context=context), 'STARTTLS')
        checked(box.login(account['username'], password_for(account)), 'LOGIN')
        return box
    except Exception:
        if box is not None:
            try:
                box.logout()
            except Exception:
                pass
        raise


def account_key(account, folder):
    identity = [account['imap']['host'], account['imap']['port'], account['username'], folder]
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()


def open_state(folder):
    folder.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(folder / 'pending.sqlite', timeout=30)
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS pending(account TEXT, validity TEXT, uid TEXT, '
               'PRIMARY KEY(account,validity,uid))')
    return db


def move_one_uid(box, uid, destination, caps, db, key, validity):
    copied = db.execute('SELECT 1 FROM pending WHERE account=? AND validity=? AND uid=?',
                        (key, validity, uid)).fetchone()
    if 'MOVE' in caps and not copied:
        checked(box.uid('MOVE', uid, destination), 'UID MOVE')
        return
    if 'UIDPLUS' not in caps:
        raise MailError('pending COPY needs UIDPLUS to finish without another copy')
    if not copied:
        checked(box.uid('COPY', uid, destination), 'UID COPY')
        db.execute('INSERT INTO pending VALUES(?,?,?)', (key, validity, uid))
        db.commit()
    checked(box.uid('STORE', uid, '+FLAGS.SILENT', '(\\Deleted)'), 'UID STORE')
    checked(box.uid('EXPUNGE', uid), 'UID EXPUNGE')
    db.execute('DELETE FROM pending WHERE account=? AND validity=? AND uid=?', (key, validity, uid))
    db.commit()


def rescue(account, config, state_dir, dry_run=False):
    box, db = None, None
    found = moved = 0
    try:
        box = connect_imap(account, config['timeout_seconds'])
        folder = None
        for candidate in account['imap']['spam_folders']:
            if box.select(folder_arg(candidate), readonly=dry_run)[0] == 'OK':
                folder = candidate
                break
        if folder is None:
            raise MailError('spam folder not found; adjust spam_folders')
        # Fixed English month names: IMAP dates must not depend on OS locale.
        since = date.today() - timedelta(days=config['days'])
        months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
        since_text = f'{since.day:02d}-{months[since.month-1]}-{since.year}'
        data = checked(box.uid('SEARCH', None, 'UNDELETED', 'SINCE', since_text), 'UID SEARCH')
        uids = [x.decode('ascii') for x in data[0].split()] if data and data[0] else []
        if any(not uid.isdigit() for uid in uids):
            raise MailError('invalid UID response')
        found = len(uids)
        if dry_run:
            return dict(found=found, moved=0, error='')
        capdata = checked(box.capability(), 'CAPABILITY')
        caps = set(b' '.join(capdata).decode('ascii').upper().split())
        if not {'MOVE', 'UIDPLUS'} & caps:
            raise MailError('server needs MOVE or UIDPLUS; no messages changed')
        response = box.response('UIDVALIDITY')[1]
        if not response or not response[0] or not response[0].isdigit():
            raise MailError('UIDVALIDITY missing; no messages changed')
        validity = response[0].decode('ascii')
        key = account_key(account, folder)
        db = open_state(state_dir)
        db.execute('DELETE FROM pending WHERE account=? AND validity<>?', (key, validity))
        db.commit()
        pending = [r[0] for r in db.execute('SELECT uid FROM pending WHERE account=? AND validity=?', (key, validity))]
        if pending:
            data = checked(box.uid('SEARCH', None, 'UID', ','.join(pending)), 'pending UID SEARCH')
            present = set(x.decode('ascii') for x in data[0].split()) if data and data[0] else set()
            for uid in set(pending) - present:
                db.execute('DELETE FROM pending WHERE account=? AND validity=? AND uid=?', (key, validity, uid))
            db.commit()
            uids = sorted(set(uids) | present, key=int)
        target = folder_arg(account['imap']['inbox_folder'])
        for uid in uids:
            move_one_uid(box, uid, target, caps, db, key, validity)
            moved += 1
        return dict(found=found, moved=moved, error='')
    except MailError as error:
        return dict(found=found, moved=moved, error=str(error))
    except Exception as error:
        # Never print raw server replies, credentials, account addresses or paths.
        return dict(found=found, moved=moved, error=type(error).__name__)
    finally:
        if db is not None:
            db.close()
        if box is not None:
            try:
                box.logout()  # No CLOSE: CLOSE could expunge unrelated messages.
            except Exception:
                pass


def check_pop3(account, timeout):
    box = None
    try:
        settings = account.get('pop3')
        if not settings:
            raise MailError('pop3 section missing')
        context = ssl.create_default_context()
        if settings.get('security', 'ssl') == 'ssl':
            box = poplib.POP3_SSL(settings['host'], settings['port'], timeout=timeout, context=context)
        else:
            box = poplib.POP3(settings['host'], settings['port'], timeout=timeout)
            box.stls(context=context)
        box.user(account['username'])
        box.pass_(password_for(account))
        return dict(count=box.stat()[0], error='')
    except MailError as error:
        return dict(count=0, error=str(error))
    except Exception as error:
        return dict(count=0, error=type(error).__name__)
    finally:
        if box is not None:
            try:
                box.quit()
            except Exception:
                pass


class SingleInstance:
    def __init__(self, state):
        self.path = state / 'run.lock'
        self.file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open('a+b')
        if self.file.seek(0, 2) == 0:
            self.file.write(b'0')
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise MailError('another instance uses this state directory') from None
        return self

    def __exit__(self, *args):
        self.file.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('config.json'))
    parser.add_argument('--dry-run', action='store_true', help='read-only count in Spam')
    parser.add_argument('--check-pop3', action='store_true', help='read-only Inbox count over POP3')
    parser.add_argument('--loop', action='store_true', help='repeat after configured interval')
    default_state = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local/state'))) / 'SpamToInbox'
    parser.add_argument('--state-dir', type=Path, default=default_state)
    args = parser.parse_args()
    if args.dry_run and args.check_pop3:
        parser.error('choose --dry-run or --check-pop3')
    try:
        config = load_config(args.config)
    except (ValueError, OSError, TypeError):
        print('Configuration error. Check config.json against the example; no mail changed.', flush=True)
        return 2
    try:
        with SingleInstance(args.state_dir):
            while True:
                with ThreadPoolExecutor(max_workers=config['threads']) as pool:
                    if args.check_pop3:
                        results = list(pool.map(lambda a: check_pop3(a, config['timeout_seconds']), config['accounts']))
                    else:
                        results = list(pool.map(lambda a: rescue(a, config, args.state_dir, args.dry_run), config['accounts']))
                errors = 0
                for number, result in enumerate(results, 1):
                    if result['error']:
                        errors += 1
                        detail = 'ERROR ' + result['error']
                        if 'moved' in result:
                            detail += f"; completed moves={result['moved']}"
                    elif args.check_pop3:
                        detail = f"POP3 Inbox messages={result['count']} (read-only)"
                    else:
                        detail = f"found={result['found']}; moved={result['moved']}" + (' (read-only)' if args.dry_run else '')
                    print(f'{datetime.now():%Y-%m-%d %H:%M:%S} account-{number}: {detail}', flush=True)
                print(f'Accounts={len(results)}; errors={errors}', flush=True)
                if not args.loop:
                    return 1 if errors else 0
                time.sleep(config['interval_seconds'])
    except MailError as error:
        print('ERROR ' + str(error), flush=True)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
