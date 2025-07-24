@echo off
REM Backend/setup_enterprise.bat
REM Enterprise setup script for SecureThread Scanner

echo.
echo ================================================================================
echo                        SecureThread Enterprise Scanner Setup
echo ================================================================================
echo.

REM Check system requirements
echo 🔍 Checking system requirements...
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    echo    Please install Python 3.8+ from https://python.org
    echo    Ensure Python is added to your PATH environment variable
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('python --version') do echo ✅ Found %%i
)

REM Check Git
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git is not installed or not in PATH
    echo    Please install Git from https://git-scm.com
    echo    Ensure Git is added to your PATH environment variable
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('git --version') do echo ✅ Found %%i
)

REM Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed or not in PATH
    echo    Please install Node.js LTS from https://nodejs.org
    echo    Ensure Node.js is added to your PATH environment variable
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('node --version') do echo ✅ Found Node.js %%i
)

REM Check npm
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ npm is not installed or not in PATH
    echo    npm should be installed with Node.js
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('npm --version') do echo ✅ Found npm %%i
)

echo.
echo ✅ All system requirements are satisfied
echo.

REM Install Python dependencies
echo 📦 Installing Python dependencies...
echo.

pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ❌ Failed to install Python dependencies
    echo    Please check your internet connection and Python installation
    pause
    exit /b 1
)

echo.
echo ✅ Python dependencies installed successfully
echo.

REM Verify scanner installation
echo 🧪 Verifying scanner installation...
echo.

python -m cli.main info --scanners
if %errorlevel% neq 0 (
    echo ❌ Scanner verification failed
    echo    Please check the installation logs above
    pause
    exit /b 1
)

echo.
echo ✅ Scanner verification completed
echo.

REM Run basic tests
echo 🧪 Running basic functionality tests...
echo.

python -c "
try:
    from scanner.core.scanner_manager import SecurityScannerManager
    from scanner.models.scan_result import ScanResult, ScanStatus
    from scanner.utils.language_detector import LanguageDetector
    print('✅ All core modules imported successfully')
    
    # Test scanner manager
    manager = SecurityScannerManager()
    print('✅ Scanner manager initialized')
    
    # Test URL validation
    valid = manager.validate_repository_url('https://github.com/octocat/Hello-World')
    if valid:
        print('✅ URL validation working')
    else:
        print('❌ URL validation failed')
        exit(1)
    
    print('✅ Basic functionality tests passed')
    
except Exception as e:
    print(f'❌ Test failed: {str(e)}')
    exit(1)
"

if %errorlevel% neq 0 (
    echo ❌ Basic functionality tests failed
    pause
    exit /b 1
)

REM Security check
echo 🛡️ Running security self-check...
echo.

bandit -r . -c .bandit >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Security self-check passed
) else (
    echo ⚠️ Security self-check found issues (this is expected in development)
)

echo.
echo ================================================================================
echo                                Setup Complete!
echo ================================================================================
echo.
echo 🎉 SecureThread Scanner is now ready for use!
echo.
echo 📋 Quick Start Commands:
echo.
echo   View scanner information:
echo     python -m cli.main info
echo.
echo   Scan a repository:
echo     python -m cli.main scan https://github.com/user/repository
echo.
echo   Get help:
echo     python -m cli.main --help
echo.
echo   Run tests:
echo     python -m tests.test_scanner
echo.
echo 📚 Documentation:
echo   - README.md for detailed usage instructions
echo   - config/scanner_config.py for configuration options
echo   - Enterprise documentation portal for advanced features
echo.
echo 🔧 Configuration:
echo   - Set environment variables for custom configuration
echo   - Edit .bandit file for Bandit-specific settings
echo   - Modify config/scanner_config.py for default settings
echo.
echo 🏢 Enterprise Features:
echo   - Modular architecture for easy extension
echo   - Comprehensive logging and error handling
echo   - CI/CD integration ready
echo   - Configurable via environment variables
echo.
echo ================================================================================
echo.

pause