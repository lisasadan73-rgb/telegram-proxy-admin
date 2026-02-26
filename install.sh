#!/bin/bash
# 安装项目：MTProxyMax 代理 + 管理后台（依赖已安装 Docker，请先运行 install-docker.sh）
# 用法一（在项目目录）: sudo bash install.sh
# 用法二（从仓库拉取）: export GIT_REPO=https://github.com/lisasadan73-rgb/telegram-proxy-admin && curl -fsSL https://raw.githubusercontent.com/lisasadan73-rgb/telegram-proxy-admin/main/install.sh | sudo -E bash
# 可选: ADMIN_PASSWORD=密码 PROXY_PORT=665 JWT_SECRET=随机串
set -e
export PROXY_PORT="${PROXY_PORT:-665}"
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-changeme}"
export JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 16 2>/dev/null || echo 'change-me-'$(date +%s))}"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行: sudo bash install.sh"
  exit 1
fi

if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
  echo "未检测到 Docker 或 Docker 未就绪。请先运行安装 Docker 的脚本："
  echo "  curl -fsSL https://raw.githubusercontent.com/lisasadan73-rgb/telegram-proxy-admin/main/install-docker.sh | sudo bash"
  echo "或在本机执行: sudo bash install-docker.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/docker-compose.yml" ]; then
  INSTALL_DIR="${INSTALL_DIR:-/root/telegram-proxy-admin}"
  GIT_REPO="${GIT_REPO:-}"
  if [ -z "$GIT_REPO" ]; then
    echo "未检测到项目目录且未设置 GIT_REPO。"
    echo "请任选一种方式："
    echo "  1) 将项目拷到服务器后执行: cd 项目目录 && sudo bash install.sh"
    echo "  2) export GIT_REPO=https://github.com/lisasadan73-rgb/telegram-proxy-admin && curl -fsSL .../install.sh | sudo -E bash"
    exit 1
  fi
  echo "[1/3] 从仓库拉取项目到 ${INSTALL_DIR}..."
  apt-get update -qq && apt-get install -y -qq git 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 "$GIT_REPO" "$INSTALL_DIR" || { echo "拉取失败，请检查 GIT_REPO 与网络"; exit 1; }
  exec bash "$INSTALL_DIR/install.sh"
fi

cd "$SCRIPT_DIR"

echo "[1/3] 安装 MTProxyMax 代理（端口 ${PROXY_PORT}）..."
if [ ! -f /opt/mtproxymax/mtproxymax ] && [ ! -d /opt/mtproxymax ]; then
  curl -fsSL "https://raw.githubusercontent.com/SamNet-dev/MTProxyMax/main/mtproxymax.sh" -o /tmp/mtproxymax.sh
  printf '%s\n' "$PROXY_PORT" "" "1" "" "n" "" "" "default" "n" "" | timeout 300 bash /tmp/mtproxymax.sh install 2>&1 | tail -20
  rm -f /tmp/mtproxymax.sh
else
  echo "  /opt/mtproxymax 已存在，跳过 MTProxyMax 安装"
fi

echo "[2/3] 生成后台挂载配置..."
cat > docker-compose.override.yml << EOF
# 一键脚本生成：挂载宿主机 MTProxyMax 配置
services:
  admin:
    environment:
      - ADMIN_USERNAME=${ADMIN_USERNAME}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - /opt/mtproxymax:/opt/mtproxymax
      - /var/run/docker.sock:/var/run/docker.sock
EOF

echo "[3/3] 构建并启动管理后台..."
docker compose up -d --build 2>&1

sleep 3
if docker compose ps 2>/dev/null | grep -q telegram-proxy-admin; then
  echo ""
  echo "=============================================="
  echo "  部署完成"
  echo "=============================================="
  echo "  管理后台: http://$(curl -s --max-time 2 4.ipify.org 2>/dev/null || echo '你的IP'):8080/"
  echo "  登录用户: ${ADMIN_USERNAME}"
  echo "  登录密码: ${ADMIN_PASSWORD}"
  echo "  代理端口: $(grep -oP "PROXY_PORT='?\K\d+" /opt/mtproxymax/settings.conf 2>/dev/null || echo $PROXY_PORT)"
  echo "----------------------------------------------"
  echo "  请尽快修改密码（重启后台前设置环境变量 ADMIN_PASSWORD 与 JWT_SECRET 后重新 up）"
  echo "  防火墙请放行 TCP ${PROXY_PORT} 与 8080"
  echo "=============================================="
else
  echo "后台启动异常，请检查: docker compose logs admin"
  exit 1
fi
