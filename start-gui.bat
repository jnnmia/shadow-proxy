@echo off
cd /d "%~dp0"
if exist "%~dp0start-gui.vbs" (
    start "" wscript.exe "%~dp0start-gui.vbs"
) else (
    start "" "%~dp0bin\shadow-gui.exe"
)
