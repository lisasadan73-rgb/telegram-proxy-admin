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
  echo "  正在安装 Docker（兼容 Ubuntu 20.04 等旧版）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  CODENAME="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME}")"
  [ -z "$CODENAME" ] && CODENAME="$(lsb_release -cs 2>/dev/null)" || true
  [ -z "$CODENAME" ] && CODENAME="focal"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  # 仅安装核心包，避免 docker-model-plugin 等在新源才有、旧系统没有的包
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
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
