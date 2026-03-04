@echo off
echo Starting ByPass on Windows...
echo Make sure you run as Administrator!

:: Проверка прав администратора
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as Administrator"
    pause
    exit /b 1
)

:: Создать необходимые директории
if not exist "configs\strategies" mkdir configs\strategies
if not exist "configs\lists" mkdir configs\lists

:: Копировать стратегии если нужно
if not exist "configs\strategies\strategies.json" (
    echo [] > configs\strategies\strategies.json
)

:: Запустить приложение
bin\bypass.exe -config configs\windows.yaml

pause
