"""
Telegram 代理管理后台 - FastAPI 应用
需账号密码登录，管理 MTProxyMax 代理用户（流量、有效期等）。
"""
import os
import subprocess
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

# 配置
INSTALL_DIR = os.environ.get("MTPROXYMAX_INSTALL_DIR", "/opt/mtproxymax")
MTPROXYMAX_SCRIPT = os.environ.get("MTPROXYMAX_SCRIPT", "/usr/local/bin/mtproxymax")
SECRETS_FILE = os.path.join(INSTALL_DIR, "secrets.conf")
SETTINGS_FILE = os.path.join(INSTALL_DIR, "settings.conf")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-secret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")  # 若设置则覆盖 ADMIN_PASSWORD
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)


def get_password_hash(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def _admin_verified(username: str, password: str) -> bool:
    if ADMIN_PASSWORD_HASH:
        return username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH)
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD


def create_access_token(username: str) -> str:
    import datetime
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": username, "exp": expire},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> str:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未提供认证信息",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username = decode_token(credentials.credentials)
    if not username or username != ADMIN_USERNAME:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效或过期的令牌",
        )
    return username


# ---------- MTProxyMax CLI 封装 ----------
def _run_mtproxymax(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    """执行 mtproxymax 子命令，返回 (returncode, stdout, stderr)。"""
    cmd = ["bash", MTPROXYMAX_SCRIPT] + list(args)
    env = os.environ.copy()
    env["INSTALL_DIR"] = INSTALL_DIR
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=INSTALL_DIR,
            env=env,
        )
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except FileNotFoundError:
        return -1, "", f"未找到 {MTPROXYMAX_SCRIPT}"
    except subprocess.TimeoutExpired:
        return -1, "", "执行超时"


def _parse_settings_file() -> dict:
    """从 settings.conf 解析代理配置（如 AD_TAG、PROXY_DOMAIN、PROXY_PORT）。"""
    out = {"ad_tag": "", "proxy_domain": "", "proxy_port": 443}
    if not os.path.isfile(SETTINGS_FILE):
        return out
    import re
    with open(SETTINGS_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^\s*AD_TAG\s*=\s*["\']?([^"\']*)["\']?\s*$', line)
            if m:
                out["ad_tag"] = (m.group(1) or "").strip()
            m = re.match(r'^\s*PROXY_DOMAIN\s*=\s*["\']?([^"\']*)["\']?\s*$', line)
            if m:
                out["proxy_domain"] = (m.group(1) or "").strip()
            m = re.match(r"^\s*PROXY_PORT\s*=\s*['\"]?(\d+)['\"]?\s*$", line.strip())
            if m:
                p = int(m.group(1))
                if 1 <= p <= 65535:
                    out["proxy_port"] = p
    return out


def _run_mtproxymax_with_stdin(stdin_text: str, *args: str, timeout: int = 30) -> tuple[int, str, str]:
    """执行 mtproxymax 并传入 stdin（用于 adtag set 等交互式命令）。"""
    cmd = ["bash", MTPROXYMAX_SCRIPT] + list(args)
    env = os.environ.copy()
    env["INSTALL_DIR"] = INSTALL_DIR
    try:
        r = subprocess.run(
            cmd,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=INSTALL_DIR,
            env=env,
        )
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except FileNotFoundError:
        return -1, "", f"未找到 {MTPROXYMAX_SCRIPT}"
    except subprocess.TimeoutExpired:
        return -1, "", "执行超时"


def _parse_secrets_file() -> list[dict]:
    """从 secrets.conf 解析用户列表（不依赖 CLI）。"""
    if not os.path.isfile(SECRETS_FILE):
        return []
    users = []
    with open(SECRETS_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 8:
                continue
            label, key, created, enabled, max_conns, max_ips, quota, expires = (
                parts[0], parts[1], parts[2], parts[3],
                parts[4], parts[5], parts[6], parts[7],
            )
            users.append({
                "label": label,
                "secret": key,
                "created": created,
                "enabled": enabled == "true",
                "max_conns": int(max_conns) if max_conns.isdigit() else 0,
                "max_ips": int(max_ips) if max_ips.isdigit() else 0,
                "quota_bytes": int(quota) if quota.isdigit() else 0,
                "expires": expires if expires and expires != "0" else None,
            })
    return users


def _format_quota(bytes_val: int) -> str:
    if not bytes_val:
        return "不限"
    for u, s in [("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)]:
        if bytes_val >= s:
            return f"{bytes_val / s:.1f}{u}"
    return f"{bytes_val}B"


# ---------- Pydantic 模型 ----------
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    max_conns: int = Field(0, ge=0)
    max_ips: int = Field(0, ge=0)
    quota: str = Field("0")  # 如 10G, 500M, 0
    expires: str | None = None  # YYYY-MM-DD 或 0


class UserUpdate(BaseModel):
    max_conns: int | None = None
    max_ips: int | None = None
    quota: str | None = None
    expires: str | None = None
    enabled: bool | None = None


class UserItem(BaseModel):
    label: str
    enabled: bool
    max_conns: int
    max_ips: int
    quota_display: str
    expires: str | None
    link_tg: str | None = None
    link_https: str | None = None


class ProxySettings(BaseModel):
    ad_tag: str = ""
    proxy_domain: str = ""
    proxy_port: int = 443


class ProxySettingsUpdate(BaseModel):
    ad_tag: str | None = None
    proxy_domain: str | None = None
    proxy_port: int | None = None


# ---------- App ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.path.isdir(INSTALL_DIR):
        print(f"Warning: MTPROXYMAX 目录不存在: {INSTALL_DIR}")
    yield


# 后台子应用（挂载到 /admin66 后可通过 http://域名/admin66 访问，无需单独端口）
admin_app = FastAPI(title="Telegram 代理管理后台", lifespan=lifespan)
admin_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class NoCacheMiddleware(BaseHTTPMiddleware):
    """禁止浏览器缓存 API 响应，刷新页面时能拿到最新配置。"""
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response


admin_app.add_middleware(NoCacheMiddleware)


@admin_app.post("/api/login", response_model=LoginResponse)
def login(req: LoginRequest):
    if not _admin_verified(req.username, req.password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    return LoginResponse(access_token=create_access_token(req.username))


@admin_app.get("/api/users", response_model=list[UserItem])
def list_users(_: str = Depends(get_current_user)):
    users = _parse_secrets_file()
    result = []
    for u in users:
        result.append(UserItem(
            label=u["label"],
            enabled=u["enabled"],
            max_conns=u["max_conns"],
            max_ips=u["max_ips"],
            quota_display=_format_quota(u["quota_bytes"]),
            expires=u["expires"][:10] if u["expires"] else None,
        ))
    return result


@admin_app.post("/api/users", response_model=UserItem)
def add_user(body: UserCreate, _: str = Depends(get_current_user)):
    code, out, err = _run_mtproxymax("secret", "add", body.label)
    if code != 0:
        raise HTTPException(status_code=400, detail=err.strip() or out.strip() or "添加失败")
    if body.max_conns or body.max_ips or (body.quota and body.quota != "0") or body.expires:
        args = [
            "secret", "setlimits", body.label,
            str(body.max_conns), str(body.max_ips),
            body.quota, body.expires or "0",
        ]
        _run_mtproxymax(*args)
    _run_mtproxymax("restart")
    users = _parse_secrets_file()
    u = next((x for x in users if x["label"] == body.label), None)
    if not u:
        return UserItem(
            label=body.label,
            enabled=True,
            max_conns=body.max_conns,
            max_ips=body.max_ips,
            quota_display=body.quota if body.quota != "0" else "不限",
            expires=body.expires,
        )
    return UserItem(
        label=u["label"],
        enabled=u["enabled"],
        max_conns=u["max_conns"],
        max_ips=u["max_ips"],
        quota_display=_format_quota(u["quota_bytes"]),
        expires=u["expires"][:10] if u["expires"] else None,
    )


@admin_app.patch("/api/users/{label}")
def update_user(label: str, body: UserUpdate, _: str = Depends(get_current_user)):
    users = _parse_secrets_file()
    u = next((x for x in users if x["label"] == label), None)
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    max_conns = body.max_conns if body.max_conns is not None else u["max_conns"]
    max_ips = body.max_ips if body.max_ips is not None else u["max_ips"]
    quota = body.quota if body.quota is not None else _format_quota(u["quota_bytes"])
    if body.quota is not None and body.quota == "0":
        quota = "0"
    expires = body.expires if body.expires is not None else (u["expires"] or "0")
    if not expires or expires == "0" or expires.lower() == "never":
        expires = "0"
    elif len(expires) == 10:
        expires = f"{expires}T23:59:59Z"
    code, out, err = _run_mtproxymax(
        "secret", "setlimits", label,
        str(max_conns), str(max_ips), quota, expires,
    )
    if code != 0:
        raise HTTPException(status_code=400, detail=err.strip() or out.strip())
    if body.enabled is not None:
        _run_mtproxymax("secret", "enable" if body.enabled else "disable", label)
    _run_mtproxymax("restart")
    return {"ok": True}


@admin_app.delete("/api/users/{label}")
def delete_user(label: str, _: str = Depends(get_current_user)):
    code, out, err = _run_mtproxymax("secret", "remove", label)
    if code != 0:
        raise HTTPException(status_code=400, detail=err.strip() or out.strip())
    _run_mtproxymax("restart")
    return {"ok": True}


def _normalize_proxy_link(link: str) -> str:
    """修复 MTProxy 链接中缺失的 &port=，例如 server=1.2.3.4port=665 -> server=1.2.3.4&port=665"""
    if not link:
        return link
    import re
    return re.sub(r"(server=[^&]+)port=", r"\1&port=", link, count=1)


def _make_qr_png_bytes(link: str) -> bytes | None:
    """根据链接生成二维码 PNG 字节，失败返回 None。"""
    if not link:
        return None
    import io
    import qrcode
    try:
        qr = qrcode.QRCode(version=1, box_size=8, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        try:
            img = qrcode.make(link)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except Exception:
            return None


def _make_qr_base64(link: str) -> str | None:
    """根据链接生成二维码 PNG 的 base64，失败返回 None。"""
    raw = _make_qr_png_bytes(link)
    if not raw:
        return None
    import base64
    return base64.b64encode(raw).decode()


@admin_app.get("/api/users/{label}/link")
def get_link(label: str, _: str = Depends(get_current_user)):
    code, out, err = _run_mtproxymax("secret", "link", label)
    if code != 0:
        raise HTTPException(status_code=404, detail=err.strip() or "未找到")
    lines = out.strip().splitlines()
    tg = ""
    https = ""
    for line in lines:
        if line.startswith("tg://"):
            tg = _normalize_proxy_link(line.strip())
        if "t.me/proxy" in line:
            https = _normalize_proxy_link(line.strip())
    link_to_use = tg or https
    qr_b64 = _make_qr_base64(link_to_use) if link_to_use else None
    return {"tg": tg, "https": https, "qr_png_base64": qr_b64}


def _get_link_sync(label: str) -> tuple[str, str]:
    code, out, err = _run_mtproxymax("secret", "link", label)
    if code != 0:
        return "", ""
    tg = https = ""
    for line in out.strip().splitlines():
        if line.startswith("tg://"):
            tg = _normalize_proxy_link(line.strip())
        if "t.me/proxy" in line:
            https = _normalize_proxy_link(line.strip())
    return tg, https


@admin_app.get("/api/proxy-secret")
def get_proxy_secret(_: str = Depends(get_current_user)):
    """返回第一个代理用户的密钥（32 位 hex），用于 @MTProxyBot 登记或给用户连接。"""
    users = _parse_secrets_file()
    if not users:
        return {"label": "", "secret": ""}
    u = users[0]
    return {"label": u["label"], "secret": u["secret"]}


@admin_app.get("/api/settings", response_model=ProxySettings)
def get_settings(_: str = Depends(get_current_user)):
    """获取代理配置（广告标签、FakeTLS 域名、端口等）。"""
    s = _parse_settings_file()
    return ProxySettings(ad_tag=s["ad_tag"], proxy_domain=s["proxy_domain"], proxy_port=s["proxy_port"])


@admin_app.patch("/api/settings")
def update_settings(body: ProxySettingsUpdate, _: str = Depends(get_current_user)):
    """更新代理配置（广告标签、端口等）。"""
    current = _parse_settings_file()
    ad_tag = body.ad_tag if body.ad_tag is not None else current["ad_tag"]
    proxy_domain = body.proxy_domain if body.proxy_domain is not None else current["proxy_domain"]
    proxy_port = body.proxy_port if body.proxy_port is not None else current["proxy_port"]

    if body.ad_tag is not None:
        if not ad_tag.strip():
            code, out, err = _run_mtproxymax("adtag", "remove")
            if code != 0 and "not found" not in (err + out).lower():
                _update_settings_file("AD_TAG", "")
        else:
            code, out, err = _run_mtproxymax_with_stdin(ad_tag.strip(), "adtag", "set")
            if code != 0:
                _update_settings_file("AD_TAG", ad_tag.strip())
        _run_mtproxymax("restart")

    if body.proxy_domain is not None:
        _update_settings_file("PROXY_DOMAIN", proxy_domain.strip() or "cloudflare.com")
        _run_mtproxymax("restart")

    if body.proxy_port is not None:
        if not (1 <= proxy_port <= 65535):
            raise HTTPException(status_code=400, detail="端口须在 1–65535 之间")
        code, out, err = _run_mtproxymax("port", str(proxy_port))
        if code != 0:
            _update_settings_file_numeric("PROXY_PORT", proxy_port)
        _run_mtproxymax("restart")

    return {"ok": True}


def _update_settings_file(key: str, value: str):
    """在 settings.conf 中设置 KEY="value"，不存在则追加。"""
    if not os.path.isdir(INSTALL_DIR):
        return
    import re
    line_esc = value.replace("\\", "\\\\").replace('"', '\\"')
    new_line = f'{key}="{line_esc}"\n'
    if os.path.isfile(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        found = False
        for i, line in enumerate(lines):
            if re.match(rf"^\s*{re.escape(key)}\s*=", line):
                lines[i] = new_line
                found = True
                break
        if not found:
            lines.append(new_line)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines)
    else:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            f.write(new_line)


def _update_settings_file_numeric(key: str, value: int):
    """在 settings.conf 中设置 KEY=value（数字，无引号）。"""
    if not os.path.isdir(INSTALL_DIR):
        return
    import re
    new_line = f"{key}={value}\n"
    if os.path.isfile(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        found = False
        for i, line in enumerate(lines):
            if re.match(rf"^\s*{re.escape(key)}\s*=", line):
                lines[i] = new_line
                found = True
                break
        if not found:
            lines.append(new_line)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines)
    else:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            f.write(new_line)


@admin_app.get("/api/traffic")
def get_traffic(_: str = Depends(get_current_user)):
    """可选：拉取 mtproxymax traffic 输出，展示各用户已用流量。"""
    code, out, err = _run_mtproxymax("traffic")
    if code != 0:
        return {"text": err or out or "无法获取流量统计（请确认 MTProxyMax 已安装并运行）"}
    return {"text": out or ""}


@admin_app.get("/api/users/{label}/qr")
def get_qr(label: str, _: str = Depends(get_current_user)):
    tg, https = _get_link_sync(label)
    link = tg or https
    if not link:
        raise HTTPException(status_code=404, detail="未找到链接")
    b64 = _make_qr_base64(link)
    if not b64:
        raise HTTPException(status_code=500, detail="生成二维码失败")
    return {"qr_png_base64": b64, "link": link}


@admin_app.get("/api/users/{label}/qr.png", response_class=Response)
def get_qr_png(label: str, _: str = Depends(get_current_user)):
    """直接返回二维码 PNG 图片，前端用 img 或 fetch 加载。"""
    tg, https = _get_link_sync(label)
    link = tg or https
    if not link:
        raise HTTPException(status_code=404, detail="未找到链接")
    png = _make_qr_png_bytes(link)
    if not png:
        raise HTTPException(status_code=500, detail="生成二维码失败")
    return Response(content=png, media_type="image/png")


class QrLinkRequest(BaseModel):
    link: str = Field(..., min_length=1, max_length=1024)


@admin_app.post("/api/qr")
def post_qr_from_link(body: QrLinkRequest, _: str = Depends(get_current_user)):
    """根据任意链接生成二维码（兜底：当 /api/users/{label}/qr 不可用时前端传链接过来）。"""
    import qrcode
    import io
    import base64
    link = _normalize_proxy_link(body.link.strip())
    if not link:
        raise HTTPException(status_code=400, detail="链接为空")
    try:
        img = qrcode.make(link)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return {"qr_png_base64": b64, "link": link}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"生成二维码失败: {e}")


# ---------- 静态前端 ----------
INDEX_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Telegram 代理管理</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { color: #0f3460; margin-bottom: 24px; }
    .card { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    input, button, select { padding: 10px 14px; border-radius: 6px; border: 1px solid #0f3460; margin: 4px; }
    input { background: #1a1a2e; color: #eee; width: 200px; }
    button { background: #e94560; color: #fff; border: none; cursor: pointer; }
    button.secondary { background: #0f3460; }
    button:hover { opacity: 0.9; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #0f3460; }
    .hidden { display: none; }
    .login-form { max-width: 320px; }
    .error { color: #e94560; margin-top: 8px; }
    .token { word-break: break-all; font-size: 12px; color: #888; }
    a { color: #e94560; }
  </style>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
</head>
<body>
  <div class="container">
    <h1>Telegram 代理管理后台</h1>
    <div id="loginCard" class="card login-form">
      <h3>登录</h3>
      <input id="username" placeholder="用户名" type="text" />
      <input id="password" placeholder="密码" type="password" />
      <button onclick="login()">登录</button>
      <p id="loginError" class="error hidden"></p>
    </div>
    <div id="mainCard" class="card hidden">
      <div style="margin-bottom:16px; padding:12px 14px; background:#0f3460; border-radius:8px;">
        <strong>代理密钥</strong> <span id="proxySecretLabel" style="color:#888;"></span>（给 @MTProxyBot 登记或用户连接用，可复制）
        <input id="proxySecretDisplay" type="text" readonly class="token" style="width:100%; max-width:480px; margin-top:8px; padding:8px; font-family:monospace; font-size:14px; word-break:break-all; background:#1a1a2e; border:1px solid #0f3460; color:#eee; border-radius:6px;" />
        <button class="secondary" type="button" onclick="copyProxySecret()" style="margin-top:6px;">复制代理密钥</button>
      </div>
      <details style="margin-bottom:12px; color:#888; font-size:13px;">
        <summary>管理员凭证（接口调用用，一般可忽略）</summary>
        <input id="tokenDisplay" type="text" readonly class="token" style="width:100%; max-width:720px; margin-top:6px; padding:6px; font-size:11px; word-break:break-all; background:#1a1a2e; color:#888; border-radius:4px;" />
        <button class="secondary" type="button" onclick="copyToken()" style="margin-top:4px;">复制</button>
      </details>
      <button class="secondary" onclick="logout()">退出</button>
      <hr style="margin: 16px 0; border-color: #0f3460;" />
      <h3>代理配置</h3>
      <div id="settingsSummary" style="margin-bottom: 14px; padding: 10px 12px; background: #0f3460; border-radius: 6px; font-size: 14px; color: #b8d4e8;">
        <strong>当前已生效的配置：</strong>
        <span id="summaryAdTag">广告标签 —</span>；
        <span id="summaryDomain">伪装域名 —</span>；
        <span id="summaryPort">端口 —</span>
      </div>
      <p style="color: #888; font-size: 14px;">广告标签从 <a href="https://t.me/MTProxyBot" target="_blank">@MTProxyBot</a> 获取，设置后使用代理的用户会看到置顶频道，您可获得收益。留空则关闭广告。</p>
      <div style="margin: 12px 0;">
        <label style="display:block; margin-bottom: 4px;">广告标签 (Ad Tag)</label>
        <input id="settingsAdTag" placeholder="从 @MTProxyBot 获取的 ad-tag，留空则移除" style="width: 100%; max-width: 480px;" />
      </div>
      <div style="margin: 12px 0;">
        <label style="display:block; margin-bottom: 4px;">FakeTLS 伪装域名（可选）</label>
        <input id="settingsProxyDomain" placeholder="如 cloudflare.com，用于流量伪装" style="width: 100%; max-width: 320px;" />
      </div>
      <div style="margin: 12px 0;">
        <label style="display:block; margin-bottom: 4px;">代理端口</label>
        <input id="settingsProxyPort" type="number" min="1" max="65535" placeholder="如 443 或 665" style="width: 120px;" />
        <span style="color:#888; margin-left:8px;">@MTProxyBot 登记时填写的地址为：你的IP:此端口</span>
      </div>
      <button onclick="saveSettings()">保存配置</button>
      <p id="settingsError" class="error hidden"></p>
      <hr style="margin: 16px 0; border-color: #0f3460;" />
      <h3>代理用户</h3>
      <button onclick="showAddUser()">添加用户</button>
      <button class="secondary" onclick="showTraffic()">流量统计</button>
      <div id="addUserForm" class="hidden" style="margin-top: 12px;">
        <input id="newLabel" placeholder="用户名 (英文/数字/下划线)" />
        <input id="newQuota" placeholder="流量 如 10G 或 0" />
        <input id="newExpires" placeholder="有效期 YYYY-MM-DD 或留空" type="date" />
        <input id="newMaxIps" placeholder="最大IP数 0=不限" type="number" min="0" value="0" />
        <button onclick="submitAddUser()">确认添加</button>
        <button class="secondary" onclick="hideAddUser()">取消</button>
      </div>
      <p id="apiError" class="error hidden"></p>
      <table>
        <thead>
          <tr><th>用户</th><th>状态</th><th>流量上限</th><th>有效期</th><th>操作</th></tr>
        </thead>
        <tbody id="userList"></tbody>
      </table>
      <div id="linkQrModal" class="hidden" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:100;align-items:center;justify-content:center;padding:20px;">
        <div style="background:#16213e;border-radius:12px;padding:24px;max-width:400px;width:100%;text-align:center;">
          <h4 style="margin:0 0 16px 0;">代理链接与二维码</h4>
          <div id="linkQrImage" style="margin:0 auto 16px;background:#fff;padding:12px;border-radius:8px;display:inline-block;"></div>
          <div style="margin-bottom:12px;">
            <label style="display:block;text-align:left;margin-bottom:4px;color:#888;">链接（可全选复制）</label>
            <input id="linkQrInput" type="text" readonly style="width:100%;padding:10px;font-size:12px;font-family:monospace;word-break:break-all;background:#1a1a2e;border:1px solid #0f3460;color:#eee;border-radius:6px;" />
          </div>
          <button type="button" class="secondary" onclick="copyLinkFromModal()">复制链接</button>
          <button type="button" style="margin-left:8px;" onclick="closeLinkModal()">关闭</button>
        </div>
      </div>
      <div id="editUserModal" class="hidden" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:101;align-items:center;justify-content:center;padding:20px;">
        <div style="background:#16213e;border-radius:12px;padding:24px;max-width:380px;width:100%;">
          <h4 style="margin:0 0 16px 0;">编辑用户</h4>
          <p id="editUserLabel" style="color:#888;margin-bottom:12px;"></p>
          <div style="margin-bottom:12px;">
            <label style="display:block;margin-bottom:4px;color:#b8d4e8;">新流量上限</label>
            <input id="editUserQuota" type="text" placeholder="如 5G、500M、0 表示不变" style="width:100%;padding:10px;background:#1a1a2e;border:1px solid #0f3460;color:#eee;border-radius:6px;" />
          </div>
          <div style="margin-bottom:16px;">
            <label style="display:block;margin-bottom:4px;color:#b8d4e8;">新有效期</label>
            <input id="editUserExpires" type="text" placeholder="YYYY-MM-DD 或 0 或留空不变" style="width:100%;padding:10px;background:#1a1a2e;border:1px solid #0f3460;color:#eee;border-radius:6px;" />
          </div>
          <p id="editUserError" class="error hidden" style="margin-bottom:8px;"></p>
          <button type="button" onclick="submitEditUser()">确定</button>
          <button type="button" class="secondary" style="margin-left:8px;" onclick="closeEditUserModal()">取消</button>
        </div>
      </div>
      <div id="deleteConfirmModal" class="hidden" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:101;align-items:center;justify-content:center;padding:20px;">
        <div style="background:#16213e;border-radius:12px;padding:24px;max-width:360px;width:100%;">
          <h4 style="margin:0 0 12px 0;">确认删除</h4>
          <p id="deleteConfirmMsg" style="color:#b8d4e8;margin-bottom:20px;"></p>
          <button type="button" onclick="submitDeleteUser()">确定删除</button>
          <button type="button" class="secondary" style="margin-left:8px;" onclick="closeDeleteModal()">取消</button>
        </div>
      </div>
      <div id="toast" class="hidden" style="position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f3460;color:#eee;padding:12px 24px;border-radius:8px;z-index:102;box-shadow:0 4px 12px rgba(0,0,0,0.3);"></div>
    </div>
  </div>
  <script>
    var BASE = (window.location.pathname || '').indexOf('/admin66') === 0 ? '/admin66' : '';
    let token = localStorage.getItem('tg_admin_token');
    let _editLabel = '';
    let _deleteLabel = '';
    function toast(msg) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.classList.remove('hidden');
      el.style.display = 'block';
      setTimeout(function() { el.classList.add('hidden'); el.style.display = 'none'; }, 2500);
    }
    function show(el) { el.classList.remove('hidden'); }
    function hide(el) { el.classList.add('hidden'); }
    function showError(id, msg) { const e = document.getElementById(id); e.textContent = msg; show(e); }
    function clearError(id) { const e = document.getElementById(id); e.textContent = ''; hide(e); }
    function api(url, opts = {}) {
      const h = { ...(opts.headers || {}) };
      if (token) h['Authorization'] = 'Bearer ' + token;
      return fetch(url, { ...opts, headers: h });
    }
    async function login() {
      const u = document.getElementById('username').value;
      const p = document.getElementById('password').value;
      clearError('loginError');
      const r = await fetch(BASE + '/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) { showError('loginError', data.detail || '登录失败'); return; }
      token = data.access_token;
      localStorage.setItem('tg_admin_token', token);
      show(document.getElementById('mainCard'));
      hide(document.getElementById('loginCard'));
      document.getElementById('tokenDisplay').value = token;
      loadUsers();
      loadSettings();
      loadProxySecret();
    }
    async function loadProxySecret() {
      const r = await api(BASE + '/api/proxy-secret');
      if (!r.ok) return;
      const d = await r.json();
      document.getElementById('proxySecretLabel').textContent = d.label ? '（用户 ' + d.label + '）' : '';
      document.getElementById('proxySecretDisplay').value = d.secret || '暂无（请先添加用户）';
    }
    function copyProxySecret() {
      const el = document.getElementById('proxySecretDisplay');
      const val = el.value;
      if (!val || val.indexOf('暂无') >= 0) { toast('无密钥可复制'); return; }
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(val).then(function() { toast('已复制代理密钥'); });
        } else { el.select(); document.execCommand('copy'); toast('已复制代理密钥'); }
      } catch (e) { toast('复制失败'); }
    }
    async function copyToken() {
      const token = document.getElementById('tokenDisplay').value;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(token);
        } else {
          document.getElementById('tokenDisplay').select();
          document.execCommand('copy');
        }
        const btn = document.querySelector('button[onclick="copyToken()"]');
        if (btn) { const t = btn.textContent; btn.textContent = '已复制'; setTimeout(() => { btn.textContent = t; }, 1500); }
      } catch (e) { alert('复制失败，请手动全选复制'); }
    }
    async function loadSettings() {
      const r = await api(BASE + '/api/settings');
      if (!r.ok) return;
      const d = await r.json();
      document.getElementById('settingsAdTag').value = d.ad_tag || '';
      document.getElementById('settingsProxyDomain').value = d.proxy_domain || '';
      document.getElementById('settingsProxyPort').value = d.proxy_port != null ? d.proxy_port : '443';
      document.getElementById('summaryAdTag').textContent = '广告标签 ' + (d.ad_tag && d.ad_tag.trim() ? d.ad_tag.trim() : '未设置');
      document.getElementById('summaryDomain').textContent = '伪装域名 ' + (d.proxy_domain && d.proxy_domain.trim() ? d.proxy_domain.trim() : '未设置');
      document.getElementById('summaryPort').textContent = '端口 ' + (d.proxy_port != null ? d.proxy_port : '443');
    }
    async function saveSettings() {
      clearError('settingsError');
      const adTag = document.getElementById('settingsAdTag').value.trim();
      const proxyDomain = document.getElementById('settingsProxyDomain').value.trim();
      const portVal = document.getElementById('settingsProxyPort').value.trim();
      const proxyPort = portVal ? parseInt(portVal, 10) : null;
      if (proxyPort !== null && (proxyPort < 1 || proxyPort > 65535)) {
        showError('settingsError', '端口须在 1–65535 之间'); return;
      }
      const r = await api(BASE + '/api/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ad_tag: adTag, proxy_domain: proxyDomain || null, proxy_port: proxyPort })
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) { toast('保存失败：' + (data.detail || '请重试')); showError('settingsError', data.detail || '保存失败'); return; }
      toast('保存成功');
      clearError('settingsError');
      loadSettings();
    }
    function logout() {
      token = '';
      localStorage.removeItem('tg_admin_token');
      hide(document.getElementById('mainCard'));
      show(document.getElementById('loginCard'));
    }
    async function loadUsers() {
      const r = await api(BASE + '/api/users');
      const list = await r.json();
      const tbody = document.getElementById('userList');
      tbody.innerHTML = '';
      if (!r.ok) { tbody.innerHTML = '<tr><td colspan="5">加载失败</td></tr>'; return; }
      list.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${u.label}</td>
          <td>${u.enabled ? '启用' : '禁用'}</td>
          <td>${u.quota_display}</td>
          <td>${u.expires || '不限'}</td>
          <td>
            <button class="secondary" onclick="showLink('${u.label}')">链接/二维码</button>
            <button class="secondary" onclick="editUser('${u.label}')">编辑</button>
            <button onclick="deleteUser('${u.label}')">删除</button>
          </td>`;
        tbody.appendChild(tr);
      });
    }
    async function showLink(label) {
      const r = await api(BASE + '/api/users/' + encodeURIComponent(label) + '/link');
      const d = await r.json();
      if (!r.ok) { toast(d.detail || '获取失败'); return; }
      const linkToShow = d.https || d.tg || '';
      const imgEl = document.getElementById('linkQrImage');
      document.getElementById('linkQrInput').value = linkToShow;
      document.getElementById('linkQrModal').style.display = 'flex';
      document.getElementById('linkQrModal').classList.remove('hidden');
      if (d.qr_png_base64) {
        imgEl.innerHTML = '<img src="data:image/png;base64,' + d.qr_png_base64 + '" alt="QR" style="display:block;width:200px;height:200px;" />';
        return;
      }
      if (linkToShow) {
        if (typeof QRCode !== 'undefined') {
          try {
            var wrap = document.createElement('div');
            new QRCode(wrap, { text: linkToShow, width: 200, height: 200 });
            var canvas = wrap.querySelector('canvas');
            if (canvas) {
              imgEl.innerHTML = '<img src="' + canvas.toDataURL('image/png') + '" alt="QR" style="display:block;width:200px;height:200px;" />';
              return;
            }
          } catch (e) {}
        }
        imgEl.innerHTML = '<img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(linkToShow) + '" alt="QR" style="display:block;width:200px;height:200px;" onerror="this.parentNode.innerHTML=\'<span style=color:#888>暂无二维码</span>\'" />';
      } else {
        imgEl.innerHTML = '<span style="color:#888;">暂无二维码</span>';
      }
    }
    function closeLinkModal() {
      document.getElementById('linkQrModal').classList.add('hidden');
      document.getElementById('linkQrModal').style.display = 'none';
    }
    function copyLinkFromModal() {
      const el = document.getElementById('linkQrInput');
      const val = el.value;
      if (!val) { toast('无链接可复制'); return; }
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(val).then(function() { toast('已复制到剪贴板'); });
        } else {
          el.select();
          document.execCommand('copy');
          toast('已复制到剪贴板');
        }
      } catch (e) { toast('复制失败，请手动全选复制'); }
    }
    function editUser(label) {
      _editLabel = label;
      document.getElementById('editUserLabel').textContent = '用户：' + label;
      document.getElementById('editUserQuota').value = '';
      document.getElementById('editUserExpires').value = '';
      document.getElementById('editUserError').textContent = '';
      document.getElementById('editUserError').classList.add('hidden');
      document.getElementById('editUserModal').style.display = 'flex';
      document.getElementById('editUserModal').classList.remove('hidden');
    }
    function closeEditUserModal() {
      document.getElementById('editUserModal').classList.add('hidden');
      document.getElementById('editUserModal').style.display = 'none';
    }
    async function submitEditUser() {
      const q = document.getElementById('editUserQuota').value.trim();
      const e = document.getElementById('editUserExpires').value.trim();
      const body = {};
      if (q !== '') body.quota = q;
      if (e !== '') body.expires = e === '0' ? '0' : e;
      if (Object.keys(body).length === 0) { closeEditUserModal(); return; }
      const r = await api(BASE + '/api/users/' + encodeURIComponent(_editLabel), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const d = await r.json().catch(() => ({}));
      if (r.ok) { closeEditUserModal(); loadUsers(); toast('已更新'); }
      else { document.getElementById('editUserError').textContent = d.detail || '更新失败'; document.getElementById('editUserError').classList.remove('hidden'); }
    }
    function deleteUser(label) {
      _deleteLabel = label;
      document.getElementById('deleteConfirmMsg').textContent = '确定删除用户「' + label + '」？删除后其代理链接将失效。';
      document.getElementById('deleteConfirmModal').style.display = 'flex';
      document.getElementById('deleteConfirmModal').classList.remove('hidden');
    }
    function closeDeleteModal() {
      document.getElementById('deleteConfirmModal').classList.add('hidden');
      document.getElementById('deleteConfirmModal').style.display = 'none';
    }
    async function submitDeleteUser() {
      const label = _deleteLabel;
      closeDeleteModal();
      const r = await api(BASE + '/api/users/' + encodeURIComponent(label), { method: 'DELETE' });
      if (r.ok) { loadUsers(); toast('已删除'); }
      else { const d = await r.json().catch(() => ({})); toast(d.detail || '删除失败'); }
    }
    function showAddUser() {
      document.getElementById('addUserForm').classList.remove('hidden');
      document.getElementById('newLabel').value = '';
      document.getElementById('newQuota').value = '0';
      document.getElementById('newExpires').value = '';
      document.getElementById('newMaxIps').value = '0';
    }
    function hideAddUser() { document.getElementById('addUserForm').classList.add('hidden'); }
    async function showTraffic() {
      const r = await api(BASE + '/api/traffic');
      const d = await r.json();
      const text = d.text || '无数据';
      const w = window.open('', '_blank');
      w.document.write('<pre style="padding:16px;font-family:monospace;white-space:pre-wrap;">' + text.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre>');
    }
    async function submitAddUser() {
      const label = document.getElementById('newLabel').value.trim();
      const quota = document.getElementById('newQuota').value.trim() || '0';
      const expires = document.getElementById('newExpires').value || null;
      const maxIps = parseInt(document.getElementById('newMaxIps').value, 10) || 0;
      if (!label) { showError('apiError', '请输入用户名'); return; }
      clearError('apiError');
      const r = await api(BASE + '/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, quota, expires, max_conns: 0, max_ips: maxIps })
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) { showError('apiError', data.detail || '添加失败'); return; }
      hideAddUser();
      loadUsers();
    }
    if (token) {
      show(document.getElementById('mainCard'));
      hide(document.getElementById('loginCard'));
      document.getElementById('tokenDisplay').value = token;
      loadUsers();
      loadSettings();
      loadProxySecret();
    }
  </script>
</body>
</html>
"""


@admin_app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


# 主应用：仅提供 /admin66 路径，根路径重定向到 /admin66（便于用 nginx 等反代时无需端口）
app = FastAPI()
@app.get("/", response_class=RedirectResponse)
def root_redirect():
    return RedirectResponse(url="/admin66/", status_code=302)
app.mount("/admin66", admin_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
