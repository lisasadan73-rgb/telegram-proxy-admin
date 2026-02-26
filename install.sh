#!/bin/bash
# Telegram 代理 + 管理后台 一键部署
# 用法一（在项目目录）: sudo bash install.sh
# 用法二（任意目录，一条命令）: curl -fsSL 你的脚本地址 | sudo bash
#   需先设置: export GIT_REPO=https://github.com/你的用户名/telegram-proxy-admin
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/docker-compose.yml" ]; then
  # 非项目目录（例如 curl 直接执行）：先拉取项目再执行
  INSTALL_DIR="${INSTALL_DIR:-/root/telegram-proxy-admin}"
  GIT_REPO="${GIT_REPO:-}"
  if [ -z "$GIT_REPO" ]; then
    echo "未检测到项目目录且未设置 GIT_REPO。"
    echo "请任选一种方式："
    echo "  1) 将项目拷到服务器后执行: cd 项目目录 && sudo bash install.sh"
    echo "  2) 设置仓库地址后一键安装: export GIT_REPO=https://github.com/你的用户名/仓库名 && curl -fsSL 脚本URL | sudo -E bash"
    exit 1
  fi
  echo "正在从仓库拉取项目到 ${INSTALL_DIR}..."
  apt-get update -qq && apt-get install -y -qq git 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 "$GIT_REPO" "$INSTALL_DIR" || { echo "拉取失败，请检查 GIT_REPO 与网络"; exit 1; }
  exec bash "$INSTALL_DIR/install.sh"
fi

cd "$SCRIPT_DIR"

# 第一步：先安装并启动 Docker，再继续后续步骤
echo "[1/4] 安装 Docker..."
if ! command -v docker &>/dev/null; then
  echo "  检测到未安装 Docker，正在安装..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker 2>/dev/null || true
  systemctl start docker 2>/dev/null || true
else
  echo "  Docker 已安装，版本: $(docker --version)"
fi
if ! docker compose version &>/dev/null && ! docker-compose version &>/dev/null; then
  echo "  正在安装 Docker Compose 插件..."
  apt-get update -qq && apt-get install -y -qq docker-compose-plugin 2>/dev/null || true
fi
echo "  等待 Docker 就绪..."
for i in 1 2 3 4 5 6 7 8 9 10; do
  if docker info &>/dev/null; then break; fi
  sleep 1
done
if ! docker info &>/dev/null; then
  echo "  Docker 未就绪，请检查: systemctl status docker"
  exit 1
fi
echo "  Docker 已就绪。"

echo "[2/4] 安装 MTProxyMax 代理（端口 ${PROXY_PORT}）..."
if [ ! -f /opt/mtproxymax/mtproxymax ] && [ ! -d /opt/mtproxymax ]; then
  curl -fsSL "https://raw.githubusercontent.com/SamNet-dev/MTProxyMax/main/mtproxymax.sh" -o /tmp/mtproxymax.sh
  printf '%s\n' "$PROXY_PORT" "" "1" "" "n" "" "" "default" "n" "" | timeout 300 bash /tmp/mtproxymax.sh install 2>&1 | tail -20
  rm -f /tmp/mtproxymax.sh
else
  echo "  /opt/mtproxymax 已存在，跳过 MTProxyMax 安装"
fi

echo "[3/4] 生成后台挂载配置..."
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

echo "[4/4] 构建并启动管理后台..."
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
