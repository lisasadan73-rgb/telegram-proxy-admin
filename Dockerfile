# Telegram 代理管理后台 - 需挂载 MTProxyMax 配置目录与 Docker socket
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    bash \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# 安装 Docker CLI（供 mtproxymax restart 使用）
RUN install -m 0755 -d /usr/share/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /usr/share/keyrings/docker.asc \
    && chmod a+r /usr/share/keyrings/docker.asc \
    && echo "deb [signed-by=/usr/share/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# 下载 MTProxyMax 脚本（方式 A：后台通过 CLI 管理）
RUN curl -fsSL "https://raw.githubusercontent.com/SamNet-dev/MTProxyMax/main/mtproxymax.sh" -o /usr/local/bin/mtproxymax \
    && chmod +x /usr/local/bin/mtproxymax

WORKDIR /app
COPY admin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY admin/ .

EXPOSE 80
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
