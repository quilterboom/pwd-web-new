@echo off
setlocal
REM ============================================================
REM  离线依赖一键安装（Windows）
REM  用法：把整个 offline_wheels 目录随项目一起拷到离线机，
REM        在离线机 backend/ 目录里直接双击本脚本或命令行运行：
REM            ..\offline_wheels\install_offline.bat
REM  脚本会自动判断：
REM    - 若离线机已有 pip（全局或已激活 venv）→ 直接安装
REM    - 若离线机是嵌入式/无 pip 的 Python → 自动建 without-pip
REM      venv 并解压 pip wheel 引导，再安装
REM ============================================================
set "WHL=%~dp0"
set "REQ=%WHL%..\backend\requirements.txt"
if not exist "%REQ%" (
  echo [错误] 找不到依赖清单：%REQ%
  pause & exit /b 1
)

echo [探测] 检查离线机是否存在可用 pip ...
python -m pip --version >nul 2>&1
if errorlevel 1 (
  echo [模式] 未检测到 pip，使用 venv 引导模式（适用于嵌入式 Python）
  set "VENV=%WHL%..\.venv"
  python -m venv --without-pip "%VENV%"
  if errorlevel 1 (
    echo [失败] 创建 venv 失败，请确认 python 可正常执行： python --version
    pause & exit /b 1
  )
  call "%VENV%\Scripts\activate.bat"
  REM 解压 pip wheel 到 venv，bootstrap 出 pip
  for %%f in ("%WHL%pip-*.whl") do (
    python -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "%%f" "%VENV%\Lib\site-packages"
  )
  echo [引导] venv 内 pip 已就绪
) else (
  echo [模式] 使用已存在的 pip（全局或已激活 venv）
)

echo [1/2] 离线安装构建后端 setuptools / wheel ...
python -m pip install --no-index --find-links "%WHL%" setuptools wheel
if errorlevel 1 (
  echo [失败] setuptools/wheel 安装出错，请检查 offline_wheels 目录完整性。
  pause & exit /b 1
)

echo [2/2] 离线安装项目依赖（PGPy 0.6.0 将从源码包构建）...
python -m pip install --no-index --no-build-isolation --find-links "%WHL%" -r "%REQ%"
if errorlevel 1 (
  echo [失败] 依赖安装出错。常见原因：
  echo    - Python 版本非 3.11/3.13（requirements 锁定的 fastapi/SQLAlchemy 需要）
  echo    - offline_wheels 目录不完整（请确认含 pip-*.whl 与所有 .whl）
  pause & exit /b 1
)

echo.
echo [完成] 依赖已离线安装。
if defined VIRTUAL_ENV (
  echo   启动（当前已在 venv 中）： python run.py
) else (
  echo   启动： python run.py
)
echo   浏览器访问： http://localhost:9010  （HTTPS 需另行配置证书）
endlocal
