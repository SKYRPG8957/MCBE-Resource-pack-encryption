@echo off
echo ============================================
echo    CUDA AES-256 Brute-Force Builder
echo ============================================
echo.

:: Check nvcc
where nvcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] nvcc not found!
    echo.
    echo Please install NVIDIA CUDA Toolkit:
    echo https://developer.nvidia.com/cuda-downloads
    echo.
    echo After installation, make sure nvcc is in your PATH.
    pause
    exit /b 1
)

:: Get GPU architecture
echo [*] Detecting GPU...
nvcc --version | findstr /C:"release"

echo.
echo [*] Compiling cuda_bruteforce.cu...
echo [*] This may take 30-60 seconds...
echo.

:: Compile - try multiple architectures
:: Use MinGW g++ as host compiler instead of cl.exe
:: sm_89 = RTX 4080/4090
:: sm_86 = RTX 3080/3090
:: sm_75 = RTX 2080
nvcc -O3 -arch=sm_89 -ccbin "g++" cuda_bruteforce.cu -o cuda_bruteforce.exe 2>nul

if %ERRORLEVEL% NEQ 0 (
    echo [*] sm_89 failed, trying sm_86...
    nvcc -O3 -arch=sm_86 -ccbin "g++" cuda_bruteforce.cu -o cuda_bruteforce.exe 2>nul
)

if %ERRORLEVEL% NEQ 0 (
    echo [*] sm_86 failed, trying sm_75...
    nvcc -O3 -arch=sm_75 -ccbin "g++" cuda_bruteforce.cu -o cuda_bruteforce.exe 2>nul
)

if %ERRORLEVEL% NEQ 0 (
    echo [*] sm_75 failed, trying sm_61...
    nvcc -O3 -arch=sm_61 -ccbin "g++" cuda_bruteforce.cu -o cuda_bruteforce.exe
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo [OK] Compilation successful!
    echo ============================================
    echo.
    echo Usage: cuda_bruteforce.exe ^<contents.json path^>
    echo.
    echo Example:
    echo   cuda_bruteforce.exe C:\path\to\contents.json
    echo.
) else (
    echo [ERROR] Compilation failed.
    echo Check nvcc installation and GPU compatibility.
    pause
)
