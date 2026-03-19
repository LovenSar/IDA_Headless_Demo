@echo off
REM 快速单测：直接让 idat 加载本目录下的 ExtractAll_IDA.py 与样本（不创建工作目录）。
REM 1) 修改 IDA_CMD 为本机 idat.exe
REM 2) 可选：拖放二进制到本 bat，或默认使用同目录下的 re1

setlocal
set "IDA_CMD=C:\Program Files\IDA Professional 9.2\idat.exe"
set "SCRIPT_DIR=%~dp0"
set "SAMPLE=%~1"
if "%SAMPLE%"=="" set "SAMPLE=%SCRIPT_DIR%re1"

if not exist "%SAMPLE%" (
    echo 未找到样本: "%SAMPLE%"
    echo 用法: %~nx0 "C:\path\to\binary.exe"
    exit /b 1
)
if not exist "%SCRIPT_DIR%ExtractAll_IDA.py" (
    echo 未找到 "%SCRIPT_DIR%ExtractAll_IDA.py"
    exit /b 1
)

echo IDA_CMD=%IDA_CMD%
echo SCRIPT=%SCRIPT_DIR%ExtractAll_IDA.py
echo SAMPLE=%SAMPLE%
"%IDA_CMD%" -A -c -S"%SCRIPT_DIR%ExtractAll_IDA.py" "%SAMPLE%"
endlocal
