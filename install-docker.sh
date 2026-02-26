#!/bin/bash
# 仅安装 Docker 与 Docker Compose
# 用法: sudo bash install-docker.sh  或  curl -fsSL https://raw.githubusercontent.com/lisasadan73-rgb/telegram-proxy-admin/main/install-docker.sh | sudo bash
set -e
if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行: sudo bash install-docker.sh"
  exit 1
fi

echo "[1/2] 安装 Docker..."
if ! command -v docker &>/dev/null; then
  echo "  正在安装 Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker 2>/dev/null || true
  systemctl start docker 2>/dev/null || true
else
  echo "  Docker 已安装: $(docker --version)"
fi

if ! docker compose version &>/dev/null && ! docker-compose version &>/dev/null; then
  echo "  正在安装 Docker Compose 插件..."
  apt-get update -qq && apt-get install -y -qq docker-compose-plugin 2>/dev/null || true
fi

echo "[2/2] 等待 Docker 就绪..."
for i in 1 2 3 4 5 6 7 8 9 10; do
  if docker info &>/dev/null; then break; fi
  sleep 1
done
if ! docker info &>/dev/null; then
  echo "  Docker 未就绪，请检查: systemctl status docker"
  exit 1
fi

echo ""
echo "Docker 安装完成。可继续执行项目安装脚本 install.sh"
