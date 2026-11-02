@echo off
cd /d "%~dp0"
py -3 mail_spam_rescue.py --config config.json --loop
pause
