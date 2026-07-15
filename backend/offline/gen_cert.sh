#!/usr/bin/env bash
# ============================================================================
#  生成自签名 TLS 证书（离线内网用，无需 CA）
#  用法（在「目标 Linux 部署服务器」上执行，需已安装 openssl）：
#      bash backend/offline/gen_cert.sh <服务器IP> <域名>
#  例：
#      bash backend/offline/gen_cert.sh 192.168.1.10 pm.internal.com
#  产物（输出到 backend/ssl/）：
#      server.key   私钥
#      server.crt   证书（SAN 含 域名、localhost、服务器IP、127.0.0.1）
#  然后：在项目根目录的 .env 里设置 SSL_CERTFILE=/app/ssl/server.crt、SSL_KEYFILE=/app/ssl/server.key，
#        重新 docker compose up -d 即可走 HTTPS。
#  浏览器会提示「自签名证书不受信任」，需手动「继续/添加例外」（内网工具属正常）。
# ============================================================================
set -euo pipefail

IP="${1:-127.0.0.1}"
DOMAIN="${2:-localhost}"
# 脚本位于 backend/offline/，证书统一输出到 backend/ssl/
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/ssl"
mkdir -p "$OUT_DIR"

KEY="$OUT_DIR/server.key"
CRT="$OUT_DIR/server.crt"
CFG="$OUT_DIR/_san.cnf"

cat > "$CFG" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
C = CN
ST = Local
L = Local
O = PasswordManager
CN = ${DOMAIN}
[v3_req]
subjectAltName = @alt
[alt]
DNS.1 = ${DOMAIN}
DNS.2 = localhost
IP.1  = ${IP}
IP.2  = 127.0.0.1
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CRT" -days 3650 \
  -subj "/C=CN/ST=Local/L=Local/O=PasswordManager/CN=${DOMAIN}" \
  -extensions v3_req -config "$CFG"

echo
echo "✅ 证书已生成："
echo "   私钥 : $KEY"
echo "   证书 : $CRT"
echo "   SAN  : DNS=${DOMAIN}, DNS=localhost, IP=${IP}, IP=127.0.0.1"
echo "   有效期: 10 年 (3650 天)"
echo
echo "下一步："
echo "   1) 在项目根目录的 .env 设置 SSL_CERTFILE=/app/ssl/server.crt、SSL_KEYFILE=/app/ssl/server.key"
echo "   2) docker compose up -d"
echo "   3) 浏览器访问 https://${IP}:9010 （自签名需手动信任）"
