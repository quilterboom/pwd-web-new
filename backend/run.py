import os

import uvicorn

from app.config import HOST, PORT

if __name__ == "__main__":
    # 可选 HTTPS：当同时提供 SSL_CERTFILE / SSL_KEYFILE 时启用 TLS，
    # 否则维持明文 HTTP（离线内网部署的默认行为，不影响既有功能）。
    ssl_kwargs = {}
    cert = os.getenv("SSL_CERTFILE")
    key = os.getenv("SSL_KEYFILE")
    if cert and key:
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False, **ssl_kwargs)
