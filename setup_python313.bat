@echo off
REM Script de configuración automática para Python 3.13
REM Ejecutar después de instalar Python 3.13.0

echo ========================================
echo SKYNET - Python 3.13 Setup
echo ========================================
echo.

REM Verificar Python 3.13
echo [1/7] Verificando Python 3.13...
py -3.13 --version
if errorlevel 1 (
    echo ERROR: Python 3.13 no encontrado. Por favor instala Python 3.13.0 primero.
    pause
    exit /b 1
)
echo OK - Python 3.13 encontrado
echo.

REM Crear nuevo entorno virtual
echo [2/7] Creando entorno virtual .venv313...
if exist .venv313 (
    echo Eliminando .venv313 existente...
    rmdir /s /q .venv313
)
py -3.13 -m venv .venv313
if errorlevel 1 (
    echo ERROR: No se pudo crear el entorno virtual
    pause
    exit /b 1
)
echo OK - Entorno virtual creado
echo.

REM Activar entorno virtual
echo [3/7] Activando entorno virtual...
call .venv313\Scripts\activate.bat
echo OK - Entorno activado
echo.

REM Actualizar pip
echo [4/7] Actualizando pip...
python -m pip install --upgrade pip
echo OK - pip actualizado
echo.

REM Instalar paquete con todas las dependencias
echo [5/7] Instalando SKYNET con todas las dependencias...
pip install -e .[tracing,viz,voice]
if errorlevel 1 (
    echo ERROR: Falló instalación del paquete
    pause
    exit /b 1
)
echo OK - Paquete instalado
echo.

REM Instalar dependencias de desarrollo
echo [6/7] Instalando dependencias de desarrollo...
pip install pytest pytest-cov pytest-asyncio pytest-mock inline-snapshot graphviz coverage
if errorlevel 1 (
    echo ERROR: Falló instalación de dev dependencies
    pause
    exit /b 1
)
echo OK - Dev dependencies instaladas
echo.

REM Verificar instalación
echo [7/7] Verificando instalación...
python -c "import skynet; print(f'SKYNET version: {skynet.__version__}')"
python -c "import pytest; print(f'pytest version: {pytest.__version__}')"
python -c "import sys; print(f'Python version: {sys.version}')"
echo.

echo ========================================
echo INSTALACION COMPLETA
echo ========================================
echo.
echo Entorno virtual: .venv313
echo Python version: 3.13.0
echo.
echo Para activar el entorno:
echo   .venv313\Scripts\activate
echo.
echo Para ejecutar tests:
echo   set OPENAI_API_KEY=sk-dummy
echo   pytest -v
echo.
pause
