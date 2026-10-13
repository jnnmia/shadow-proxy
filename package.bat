@echo off
chcp 65001 >nul
cd /d "%~dp0"
python scripts\package.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [错误] 打包脚本执行失败，代码: %ERRORLEVEL%
    pause
    exit /b %ERRORLEVEL%
)
pause
