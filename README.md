# Telegram 代理管理后台

使用 Docker 运行一个需**账号密码登录**的 Web 后台，用于管理 [MTProxyMax](https://github.com/SamNet-dev/MTProxyMax) 代理用户：控制每个使用代理的人**能用多少流量**、**能用多久**（有效期）。

## 架构说明

- **代理层**：需在宿主机上先安装 MTProxyMax（一键脚本），代理以 Docker 容器运行，配置位于 `/opt/mtproxymax`。
- **后台层**：本仓库提供 Docker 镜像与 Compose，运行 Web 管理界面；后台挂载 MTProxyMax 的配置目录并调用其 CLI，实现用户与流量/时长管理。

## 一键部署（新机一条命令）

### 方式 A：项目已在服务器上

将本仓库拷贝到目标机后，进入项目目录执行：

```bash
cd /root/telegram-proxy-admin   # 或你的项目目录
sudo bash install.sh
```

### 方式 B：真正一条命令（从仓库拉取）

若项目已推送到 GitHub（或其它 git 仓库），在新服务器**任意目录**执行一条命令即可完成部署：

```bash
export GIT_REPO=https://github.com/你的用户名/telegram-proxy-admin
curl -fsSL https://raw.githubusercontent.com/你的用户名/telegram-proxy-admin/main/install.sh | sudo -E bash
```

脚本会：拉取项目到 `/root/telegram-proxy-admin` → 安装 Docker → 安装 MTProxyMax → 启动管理后台。

---

脚本会依次：安装 Docker（若未安装）→ 非交互安装 MTProxyMax（默认代理端口 665）→ 生成挂载配置并启动管理后台。完成后在浏览器访问脚本输出的地址（如 `http://你的IP:8080/`），使用默认账号 `admin` / 密码 `changeme` 登录，**请尽快修改密码**。

可选环境变量（在运行前设置，方式 B 需加 `-E` 保留变量）：

| 变量 | 说明 | 默认 |
|------|------|------|
| `GIT_REPO` | 方式 B 必填：项目 git 地址 | - |
| `INSTALL_DIR` | 方式 B 拉取到的目录 | `/root/telegram-proxy-admin` |
| `PROXY_PORT` | MTProxy 监听端口 | `665` |
| `ADMIN_USERNAME` | 后台管理员用户名 | `admin` |
| `ADMIN_PASSWORD` | 后台管理员密码 | `changeme` |
| `JWT_SECRET` | JWT 签名密钥（不设则自动生成） | 自动 |

示例：自定义端口与密码

```bash
export PROXY_PORT=443
export ADMIN_PASSWORD=你的强密码
sudo -E bash install.sh
```

若要通过 `http://IP/admin66/` 且不写端口，需在 Nginx 中增加 `location /admin66 { proxy_pass http://127.0.0.1:8080; }` 等配置。

## 前置条件

1. 已在目标 Linux 宿主机上安装 MTProxyMax：
   ```bash
   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SamNet-dev/MTProxyMax/main/install.sh)"
   ```
   按向导设置端口（建议 443）、FakeTLS 域名、第一个代理用户等。安装完成后，配置与脚本位于 `/opt/mtproxymax`。

2. 宿主机已安装 Docker 与 Docker Compose。

## 快速启动

1. 克隆或复制本仓库到宿主机。

2. 生产环境请挂载宿主机上的 MTProxyMax 配置目录，并设置管理员账号与 JWT 密钥：
   ```bash
   export ADMIN_USERNAME=admin
   export ADMIN_PASSWORD=你的强密码
   export JWT_SECRET=随机长字符串
   ```
   编辑 `docker-compose.yml`，将 `mtproxymax_data` 改为宿主机路径：
   ```yaml
   volumes:
     - /opt/mtproxymax:/opt/mtproxymax
     - /var/run/docker.sock:/var/run/docker.sock
   ```
   并删除文件末尾的 `volumes: mtproxymax_data:` 段（或保留仅用于开发时空数据卷）。

3. 启动后台：
   ```bash
   cd telegram-proxy-admin
   docker compose up -d --build
   ```

4. 浏览器访问 `http://<宿主机IP>:8080`，使用上面设置的**用户名和密码**登录。

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ADMIN_USERNAME` | 管理员登录用户名 | `admin` |
| `ADMIN_PASSWORD` | 管理员登录密码（明文） | `changeme` |
| `ADMIN_PASSWORD_HASH` | 管理员密码 bcrypt 哈希（若设置则优先于 `ADMIN_PASSWORD`） | - |
| `JWT_SECRET` | JWT 签名密钥，生产环境务必修改 | `change-this-secret-in-production` |
| `MTPROXYMAX_INSTALL_DIR` | MTProxyMax 配置目录在容器内的路径 | `/opt/mtproxymax` |

## 后台功能

- **登录**：账号密码认证，返回 JWT，仅登录后可访问管理接口。
- **代理用户管理**（对应 MTProxyMax 的 secret）：
  - **列表**：展示所有代理用户、流量上限、有效期、启用状态。
  - **添加用户**：输入 label（用户名），可同时设置流量上限（如 `10G`、`500M`）、有效期（`YYYY-MM-DD`）、最大 IP 数。
  - **编辑**：修改某用户的流量上限、有效期、启用/禁用。
  - **删除**：移除该代理用户（对应 secret 删除）。
- **链接与二维码**：查看每个用户的 tg 链接、HTTPS 链接及二维码，便于分发给使用代理的人。
- **流量统计**（可选）：点击「流量统计」拉取 `mtproxymax traffic` 输出，查看各用户已用流量。

## 如何设置管理员账号与首次添加代理用户

1. **设置管理员账号**：通过环境变量 `ADMIN_USERNAME`、`ADMIN_PASSWORD` 传入（或 `ADMIN_PASSWORD_HASH` 传入 bcrypt 哈希）。生产环境务必使用强密码，并设置 `JWT_SECRET`。

2. **首次添加代理用户**：登录后台后点击「添加用户」，填写：
   - **用户名**：英文/数字/下划线（如 `user1`），对应 MTProxyMax 的 secret label。
   - **流量**：如 `10G`、`500M`，填 `0` 表示不限。
   - **有效期**：选日期或留空表示不限；到期后该链接自动失效。
   - **最大 IP 数**：允许的终端数，`0` 表示不限。

添加后可在列表中查看、编辑、删除，或通过「链接/二维码」将代理链接发给使用人。

## 安全与运维建议

- 后台仅在内网或通过 VPN/反向代理（HTTPS）访问，避免暴露在公网。
- 不要将 `ADMIN_PASSWORD`、`JWT_SECRET` 写死在镜像或代码中，使用环境变量或 Docker secrets。
- 挂载 `/var/run/docker.sock` 后，后台可执行 `mtproxymax restart` 重启代理容器，请评估权限与攻击面；若需更保守，可不挂载 socket，由宿主机 cron 或 systemd 在配置变更后执行 `mtproxymax restart`。

## 项目结构

```
telegram-proxy-admin/
├── install.sh           # 一键部署脚本（Docker + MTProxyMax + 后台）
├── docker-compose.yml   # 后台服务与卷挂载
├── Dockerfile           # 后台镜像（Python + MTProxyMax 脚本 + Docker CLI）
├── admin/
│   ├── main.py          # FastAPI 应用（登录、用户 CRUD、链接/二维码、流量）
│   └── requirements.txt
├── .dockerignore
└── README.md
```

## 开发时本地运行（不依赖 Docker）

```bash
cd admin
pip install -r requirements.txt
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=changeme
# 若本机已安装 MTProxyMax，确保 /opt/mtproxymax 存在且可读
uvicorn main:app --reload --port 8000
```

访问 `http://127.0.0.1:8000`。注意：添加/编辑/删除用户会调用 `mtproxymax` CLI，需本机已安装 MTProxyMax 且可执行 `mtproxymax` 命令。
