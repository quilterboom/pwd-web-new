# 密码管理 - 服务端 GPG/SM2 加解密密码管理器
# 单阶段构建：
#   前端（Vue3 + Vite）在「构建机」上预先用 `npm run build` 编译为静态文件（frontend/dist）。
#   因为静态资源（JS/CSS/HTML）与 CPU 架构无关，在 Mac/Windows 上构建的产物可直接用于 amd64 镜像，
#   无需在容器内再跑 Node 构建，Dockerfile 更简洁、构建更稳。
#   镜像构建期把 frontend/dist 拷入 /app/static（WORKDIR=/app → 即 /app/app/static）由 FastAPI 同源托管。
# 运行时与原来完全一致：容器只跑 `python run.py`，端口 9010，数据卷 /app/data。
#
# 构建前请先生成前端产物（见 backend/offline/build_image.sh）：
#   cd backend/frontend && npm install && npm run build

FROM python:3.13-slim

# 避免 Debian 交互式配置 & 设置 UTF-8 环境
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /app

# 1) 依赖清单
COPY requirements.txt ./

# 2) 离线依赖包（若存在则离线安装；为空则回退到 PyPI 联网安装）。
#    这样镜像既能联网构建，也能用 offline/wheels 完全离线构建。
COPY offline ./offline

# 默认走 PyPI 联网安装；仅当显式传入 --build-arg OFFLINE=1 时才离线安装。
# 注意：离线安装要求 offline/wheels 内含「与目标容器（Linux x86_64, cp313）同平台」的依赖包，
# 不能直接用仓库里默认的 Windows 版 wheels。
# 网络偶发抖动时自动重试，避免构建因单包下载中断而整体失败。
ARG OFFLINE=0
ENV PIP_RETRIES=10 \
    PIP_TIMEOUT=120
RUN if [ "$OFFLINE" = "1" ]; then \
      echo "[密码管理] 离线安装（--no-index），需 offline/wheels 含与目标容器同平台的依赖包"; \
      pip install --no-cache-dir --retries 10 --timeout 120 --no-index --find-links offline/wheels -r requirements.txt; \
    else \
      echo "[密码管理] 联网安装（PyPI）"; \
      pip install --no-cache-dir --retries 10 --timeout 120 -r requirements.txt; \
    fi

# 3) 应用代码
COPY app ./app
COPY run.py ./

# 4) 前端静态产物（构建机预编译的 Vue 构建输出）。
#    应用由 main.py 从 /app/app/static 同源托管（STATIC_DIR = <app 目录>/static）。
COPY frontend/dist ./app/static

# 数据卷：SQLite 数据库与 JWT 密钥均落在 /app/data，挂载到宿主机以便持久化
VOLUME ["/app/data"]

EXPOSE 9010 9080

# run.py 内部已通过 lifespan 完成建表 / 管理员 / 密钥初始化
CMD ["python", "run.py"]
