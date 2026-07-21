# 离线依赖包（offline_wheels）

本目录包含密码管理系统的全部 Python 运行时依赖的**离线安装包**，供无外网环境（如内网离线电脑）通过 VSCode / 命令行裸机运行本项目使用。

## 包含内容

- **48 个文件 / 约 22 MB**
- 覆盖 **Python 3.11 与 3.13**（Windows x86_64 / `win_amd64`）
- 编译型包（bcrypt、cryptography、SQLAlchemy、greenlet、httptools、watchfiles、websockets、cffi）均已提供对应版本的预编译 wheel；`bcrypt`/`cryptography` 为 `abi3` 跨版本 wheel
- `PGPy==0.6.0` 在 PyPI **仅有源码包（sdist）**，无预编译 wheel，本目录已放入 `PGPy-0.6.0.tar.gz`，离线安装时会从源码构建（纯 Python，无需 C 编译器，但需构建后端 `setuptools`/`wheel`）
- 已附带 `setuptools`、`wheel`、`packaging`、`pip-*`（PGPy 源码包构建后端；`pip` 用于无 pip 的嵌入式 Python 引导）

## 离线安装（推荐：一键脚本，自动判断模式）

把整个 `offline_wheels` 目录随项目一起拷到离线机，然后在离线机的 `backend/` 目录里运行：

```bat
..\offline_wheels\install_offline.bat
```

脚本会自动判断离线机的 Python 状态：
- **若离线机已有 pip**（完整安装版 / 已激活 venv）→ 直接用其离线安装
- **若离线机是嵌入式 Python（无 pip）** → 自动 `python -m venv --without-pip` 建 venv，解压 `pip-*.whl` 引导出 pip，再离线安装

> 这一机制已在本机用「`--without-pip` venv + 解压 pip wheel」完整验证：PGPy 0.6.0 从源码包成功构建，全部 11 个依赖与传递依赖均安装成功。

## 离线安装（手动，分步）

### 情况 A：离线机已有 pip
在 `backend/` 下直接：
```bat
python -m pip install --no-index --find-links ..\offline_wheels setuptools wheel
python -m pip install --no-index --no-build-isolation --find-links ..\offline_wheels -r requirements.txt
```

### 情况 B：离线机无 pip（报错 `ensurepip` / `No module named pip`）
例如嵌入式 Python（embeddable zip）。用无 pip 的 venv + 解压 pip wheel 引导：
```bat
cd backend
python -m venv --without-pip ..\.venv
..\venv\Scripts\activate
REM 解压 pip wheel 到 venv（关键一步）
python -c "import zipfile,glob; zipfile.ZipFile(glob.glob(r'..\offline_wheels\pip-*.whl')[0]).extractall(r'..\venv\Lib\site-packages')"
python -m pip install --no-index --find-links ..\offline_wheels setuptools wheel
python -m pip install --no-index --no-build-isolation --find-links ..\offline_wheels -r requirements.txt
```

## 启动项目

依赖装好后，在 `backend/` 下：
```bat
python run.py
```
浏览器访问 `http://<本机IP>:9010`（默认纯 HTTP；仅当配置了 `SSL_CERTFILE`/`SSL_KEYFILE` 才启用 HTTPS）。
默认管理员账号 `admin / admin123`，首次启动自动建库与默认分组。

## 平台与版本说明

- **仅 Windows x86_64**：本目录 wheel 均为 `win_amd64`。若离线机是 Linux x86_64，需另行下载对应 `manylinux` wheel（命令类比：`pip download -r requirements.txt -d offline_wheels_linux --only-binary=:all: --platform manylinux2014_x86_64 --python-version 311`，并单独处理 PGPy 源码包）。
- **Python 版本**：已覆盖 3.11 / 3.13。若离线机是 3.8，部分新依赖（如 fastapi 0.139、SQLAlchemy 2.0）不兼容，需升级 Python 或调整 `requirements.txt` 版本。
- **前端无需本目录**：前端产物 `backend/frontend/dist/` 已预编译，FastAPI 直接静态托管，离线运行无需 `npm install` / `npm build`（除非你改了 `.vue` 源码需重新构建）。
- **4A 接入**：离线环境访问不到 4A 服务端时，后端探活失败会自动回退普通账号密码登录，不影响本项目离线运行。
