@echo off
echo [*] Compiling recovery.cpp using MinGW g++...
g++ -O3 -march=native -pthread recovery.cpp -o recovery.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Compilation successful!
    echo [*] Running recovery.exe...
    recovery.exe
) else (
    echo [ERROR] Compilation failed. Make sure g++ is in your PATH.
    pause
)
