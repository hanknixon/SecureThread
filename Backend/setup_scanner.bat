@echo off
REM Backend/setup_scanner.bat
REM Setup script for the GitHub Repository Scanner (Windows)

echo 🔧 Setting up SecureThread Repository Scanner...
echo ================================================

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed. Please install Python first.
    pause
    exit /b 1
)

REM Check if Git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git is not installed. Please install Git first.
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js first.
    pause
    exit /b 1
)

echo ✅ All required system dependencies are available
echo.

REM Install Python dependencies
echo 📦 Installing Python dependencies...
pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo ✅ Python dependencies installed successfully
) else (
    echo ❌ Failed to install Python dependencies
    pause
    exit /b 1
)

echo.
echo 🎉 Setup completed successfully!
echo.
echo 🚀 You can now test the scanner with:
echo    python repo_scanner.py https://github.com/octocat/Hello-World
echo.
echo 🧪 Or run the test suite with:
echo    python test_scanner.py
echo.
echo 💡 Example usage:
echo    python repo_scanner.py https://github.com/bridgecrewio/example_vulnerable_app

pause