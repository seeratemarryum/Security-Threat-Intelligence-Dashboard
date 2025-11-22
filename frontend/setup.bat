@echo off
echo Setting up Security Dashboard Frontend...

:: Clean previous installations
if exist node_modules rmdir /s /q node_modules
if exist package-lock.json del package-lock.json

:: Install dependencies
echo Installing dependencies...
npm install

:: Check if installation was successful
if %errorlevel% equ 0 (
    echo ✅ Dependencies installed successfully!
    echo.
    echo Starting the development server...
    npm start
) else (
    echo ❌ Installation failed. Trying alternative method...
    npm cache clean --force
    npm install
)

pause