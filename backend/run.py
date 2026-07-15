import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import uvicorn

from app.config import HOST, PORT


def _make_redirect_handler(tls_port: int):
    """构造一个明文 HTTP 处理器：把所有请求 307 跳转到 https://<host>:<tls_port>。

    重定向目标的主机名取自请求 Host 头（去掉端口），因此无论用户用 IP 还是域名
    访问明文地址，都会被正确导向对应的 HTTPS 站点，无需硬编码。
    """

    class _RedirectHandler(BaseHTTPRequestHandler):
        def _redirect(self):
            host = (self.headers.get("Host") or "localhost").split(":")[0] or "localhost"
            target = f"https://{host}:{tls_port}{self.path}"
            self.send_response(307)
            self.send_header("Location", target)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()

        def do_GET(self):
            self._redirect()

        def do_POST(self):
            self._redirect()

        def do_PUT(self):
            self._redirect()

        def do_DELETE(self):
            self._redirect()

        def do_HEAD(self):
            self._redirect()

        def log_message(self, *args):  # 静默访问日志，避免污染容器输出
            return

    return _RedirectHandler


def start_redirect_server(http_port: int, tls_port: int):
    handler = _make_redirect_handler(tls_port)
    server = ThreadingHTTPServer(("0.0.0.0", http_port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[redirect] 明文 HTTP :{http_port} -> https://<host>:{tls_port} (307)")


if __name__ == "__main__":
    # 可选 HTTPS：当同时提供 SSL_CERTFILE / SSL_KEYFILE 时启用 TLS，
    # 否则维持明文 HTTP（离线内网部署的默认行为，不影响既有功能）。
    ssl_kwargs = {}
    cert = os.getenv("SSL_CERTFILE")
    key = os.getenv("SSL_KEYFILE")
    if cert and key:
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}
        # 明文 HTTP -> HTTPS 重定向（默认开启，可用 SSL_REDIRECT=0 关闭）
        if os.getenv("SSL_REDIRECT", "1") != "0":
            http_port = int(os.getenv("HTTP_PORT", "9080"))
            start_redirect_server(http_port, PORT)

    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False, **ssl_kwargs)
