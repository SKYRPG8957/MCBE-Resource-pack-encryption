@echo off
echo [*] Compiling recovery_gui.cpp using MinGW g++...
echo [*] Please wait, this might take a moment...

:: If the previous binary is running, linking will fail with Permission denied.
:: Best-effort: kill and remove old binary.
taskkill /IM recovery_gui.exe /F >nul 2>&1
del /F /Q recovery_gui.exe >nul 2>&1

:: Adding -lgdi32 and -lcomctl32 for Windows API/GDI/Common Controls
:: Adding -maes -msse4.2 for AES-NI hardware acceleration (100x speedup)
g++ -O3 -Ofast -march=native -maes -msse4.2 -pthread recovery_gui.cpp -o recovery_gui.exe -lcomdlg32 -lopengl32 -lgdi32 -lcomctl32

if %ERRORLEVEL% EQU 0 (
    echo [OK] Compilation successful!
    echo [*] Launching recovery_gui.exe...
    start recovery_gui.exe
) else (
    echo [ERROR] Compilation failed. 
    echo Check if MinGW g++ is installed and in your PATH.
    pause
)
