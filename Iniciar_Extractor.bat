@echo off
setlocal
cd /d "%~dp0"

rem Abre la ventana del extractor sin dejar una consola negra abierta.
rem Si la ventana no aparece, ejecuta este archivo desde una consola para ver el error.

where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw -3 "%~dp0pkg_extractor_gui.py" %*
    exit /b 0
)
where pythonw >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%~dp0pkg_extractor_gui.py" %*
    exit /b 0
)
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0pkg_extractor_gui.py" %*
    exit /b
)
where python >nul 2>nul
if not errorlevel 1 (
    python "%~dp0pkg_extractor_gui.py" %*
    exit /b
)

echo No se encontro Python en este equipo.
echo Descargalo desde https://www.python.org/downloads/ y durante la instalacion
echo marca la casilla "Add python.exe to PATH". Despues vuelve a abrir este archivo.
echo.
pause
exit /b 1
