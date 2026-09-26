@echo off
rem SSH passwordless-login setup tool - GUI launcher
rem double-click to start Setup-SSHKeyAuthGui.ps1 (STA + bypass policy)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -STA -File "Setup-SSHKeyAuthGui.ps1"
