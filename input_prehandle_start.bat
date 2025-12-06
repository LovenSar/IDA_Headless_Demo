@echo off
setlocal enabledelayedexpansion

REM ================================================================
REM  IDA_Headless_Demo - input_prehandle_start.bat
REM
REM  Purpose:
REM    - Allow drag-and-drop of a single binary file onto this .bat
REM    - Automatically create [file]_idademo as working/output dir
REM    - Copy IDA Python scripts from this directory into that folder
REM    - Call idat.exe in (mostly) headless mode to run 3 scripts:
REM         * ExtractBinaryInfo_IDA.py   -> symbols/strings/segments/xrefs
REM         * ExtractDisassembly_IDA.py  -> per-function disassembly
REM         * ExtractPseudocode_IDA.py   -> per-function pseudocode
REM    - Clean up temporary copied scripts and input file afterwards
REM
REM  Usage:
REM    Drag an .exe/.dll (or other binary) onto this .bat, or run:
REM      input_prehandle_start.bat "C:\path\to\binary.exe"
REM ================================================================

REM --- Configuration: adjust IDA_CMD path to your environment ---
set "IDA_CMD=C:\Program Files\IDA Professional 9.2\idat.exe"

REM --- Directory where this batch file resides ---
set "SCRIPT_DIR=%~dp0"
if not "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR%\"

REM --- Argument check ---
if "%~1"=="" (
    echo Error: Please drag and drop a file onto this script.
    pause
    exit /b 1
)

set "INPUT_TARGET=%~f1"

if not exist "%INPUT_TARGET%" (
    echo Error: Input file does not exist: "%INPUT_TARGET%"
    pause
    exit /b 1
)

REM --- Only accept a single file, not a directory ---
set "IS_DIR=0"
if exist "%INPUT_TARGET%\" set "IS_DIR=1"
if %IS_DIR%==1 (
    echo Error: Input is a folder. This script only supports processing single files.
    echo Please drag and drop a file, not a folder.
    pause
    exit /b 1
)

REM --- Parse input path information ---
set "INPUT_PARENT_DIR=%~dp1"
set "INPUT_NAME=%~n1"
set "INPUT_EXT=%~x1"
set "INPUT_FILENAME=%~nx1"

REM Working/output base directory: same folder as input file, named [file]_idademo
set "WORK_OUTPUT_DIR=%INPUT_PARENT_DIR%\%INPUT_NAME%_idademo"

echo.
echo Preparing working directory: "%WORK_OUTPUT_DIR%"
if not exist "%WORK_OUTPUT_DIR%" (
    echo Creating directory...
    mkdir "%WORK_OUTPUT_DIR%"
    if errorlevel 1 (
        echo Error: Failed to create working/output directory. Check permissions.
        pause
        exit /b 1
    )
) else (
    echo Directory already exists. Files may be overwritten.
)

REM Copy IDA Python scripts from this folder to working dir
echo Copying IDA Python scripts (*.py) from "%SCRIPT_DIR%"...
copy /Y "%SCRIPT_DIR%*.py" "%WORK_OUTPUT_DIR%" > nul
if errorlevel 1 (
    echo Warning: Failed to copy Python scripts. Please ensure scripts exist in "%SCRIPT_DIR%".
)

REM Copy input file into working dir
echo Copying input file to working directory...
echo   "%INPUT_TARGET%" ^> "%WORK_OUTPUT_DIR%\%INPUT_FILENAME%"
copy /Y "%INPUT_TARGET%" "%WORK_OUTPUT_DIR%" > nul
if errorlevel 1 (
    echo Error: Failed to copy input file.
    pause
    exit /b 1
)

REM --- Generate a sanitized name (currently only for display/logging) ---
set "ORIGINAL_NAME=%INPUT_FILENAME%"
set "NEW_NAME="
set "ALLOWED_CHARS=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
set "TEMP_NAME=!ORIGINAL_NAME!"
:char_loop
if not defined TEMP_NAME goto :end_char_loop
set "char=!TEMP_NAME:~0,1!"
set "TEMP_NAME=!TEMP_NAME:~1!"
echo "!ALLOWED_CHARS!" | findstr /i /c:"!char!" > nul
if errorlevel 1 (
    set "NEW_NAME=!NEW_NAME!_"
) else (
    set "NEW_NAME=!NEW_NAME!!char!"
)
goto :char_loop
:end_char_loop
set "NAME_X=!NEW_NAME!"
echo Original Filename: %ORIGINAL_NAME%
echo Processed Filename: !NAME_X!
echo.

REM --- Change to working dir and call IDA scripts in sequence ---
pushd "%WORK_OUTPUT_DIR%"

echo =====================================================================
echo [1/3] Running IDA - ExtractBinaryInfo_IDA.py ...
echo =====================================================================
echo   IDA_CMD = "%IDA_CMD%"
echo   Working dir = "%CD%"
echo   Input file = "%INPUT_FILENAME%"
call "%IDA_CMD%" -A -c -L"%WORK_OUTPUT_DIR%\ida_1_binaryinfo.log" -S"ExtractBinaryInfo_IDA.py" "%INPUT_FILENAME%"
echo.

echo =====================================================================
echo [2/3] Running IDA - ExtractDisassembly_IDA.py ...
echo =====================================================================
call "%IDA_CMD%" -A -c -L"%WORK_OUTPUT_DIR%\ida_2_disassembly.log" -S"ExtractDisassembly_IDA.py" "%INPUT_FILENAME%"
echo.

echo =====================================================================
echo [3/3] Running IDA - ExtractPseudocode_IDA.py ...
echo =====================================================================
call "%IDA_CMD%" -A -c -L"%WORK_OUTPUT_DIR%\ida_3_pseudocode.log" -S"ExtractPseudocode_IDA.py" "%INPUT_FILENAME%"
echo.

popd

REM --- 清理临时拷贝的脚本和输入文件（保留 IDA 生成的 IDB/I64 等文件以便后续打开） ---
echo Cleaning up temporary Python scripts and copied input file...
del /Q /F "%WORK_OUTPUT_DIR%\*.py" > nul 2>&1
del /Q /F "%WORK_OUTPUT_DIR%\%INPUT_FILENAME%" > nul 2>&1

echo.
echo =====================================================================
echo All processing completed!
echo Output root directory:
echo   "%WORK_OUTPUT_DIR%"
echo
echo Inside this directory you should see (depending on IDA analysis):
echo   - ^<name^>_disassembly\   ; per-function assembly
echo   - ^<name^>_output\        ; symbols/strings/segments/xrefs (CSV)
echo   - ^<name^>_pseudocode\    ; per-function pseudocode (if Hex-Rays available)
echo =====================================================================
echo.
pause
endlocal
exit /b 0

