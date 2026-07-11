"""
common.py
ابزارهای مشترک برای تمام اسکریپت‌های پروژه: تشخیص پروتکل، پارس کردن لینک‌ها،
تشخیص IP خصوصی/رزروشده، و ساخت شناسه یکتا برای هر کانفیگ.

هیچ اطلاعات حساسی (Token, API Key, پنل مدیریتی) در این ماژول ذخیره یا لاگ نمی‌شود.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------------
# پروتکل‌های پشتیبانی‌شده و Scheme متناظرشان
# ---------------------------------------------------------------------------
SUPPORTED_SCHEMES = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "tuic": "tuic",
    "wireguard": "wireguard",
    "socks": "socks",
    "socks5": "socks",
    "http": "http",
    "https": "http",
}

# دامنه‌ها/الگوهای مشکوک که کانفیگ‌های حاوی آن‌ها حذف می‌شوند
SUSPICIOUS_DOMAIN_PATTERNS = [
    r"\.local$",
    r"\.internal$",
    r"panel",
    r"admin",
    r"manage",
    r"dashboard",
]

# پارامترهای کوئری‌ای که نشانه توکن مدیریتی/API هستند
MANAGEMENT_TOKEN_KEYS = {"token", "apikey", "api_key", "secret", "adminpass"}

MAX_REASONABLE_PORT = 65535


@dataclass
class ParsedConfig:
    raw: str
    protocol: str
    address: str = ""
    port: int = 0
    uuid_or_password: str = ""
    transport: str = "tcp"
    security: str = "none"  # none | tls | reality
    tls: bool = False
    sni: str = ""
    host: str = ""
    name: str = ""
    insecure: bool = True
    valid: bool = False
    reject_reason: str = ""

    def unique_key(self) -> str:
        """
        شناسه یکتا فقط بر اساس اطلاعات اصلی اتصال ساخته می‌شود، نه نام کانفیگ،
        تا کانفیگ‌های تکراری با نام‌های متفاوت هم تشخیص داده شوند.
        """
        raw_key = "|".join([
            self.protocol,
            self.address.lower(),
            str(self.port),
            self.uuid_or_password,
            self.transport,
            self.host.lower(),
            self.sni.lower(),
        ])
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]


def is_probably_base64(text: str) -> bool:
    """تشخیص تقریبی این‌که آیا محتوای یک فایل به‌صورت کامل Base64 است یا خیر."""
    sample = text.strip().replace("\n", "").replace("\r", "")
    if len(sample) < 20:
        return False
    if re.search(r"://", text):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", sample))


def safe_b64decode(text: str) -> Optional[str]:
    try:
        padded = text.strip()
        padded += "=" * (-len(padded) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def is_private_or_reserved(address: str) -> bool:
    """تشخیص آدرس‌های Localhost، خصوصی و رزروشده."""
    host = address.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        # دامنه است نه IP؛ فقط localhost صریح را رد می‌کنیم
        return host.lower() in {"localhost", "0.0.0.0", "127.0.0.1"}


def has_suspicious_domain(address: str) -> bool:
    addr = address.lower()
    return any(re.search(pattern, addr) for pattern in SUSPICIOUS_DOMAIN_PATTERNS)


def has_management_token(url: str) -> bool:
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        return any(key.lower() in MANAGEMENT_TOKEN_KEYS for key in query)
    except Exception:
        return False


def detect_protocol(line: str) -> Optional[str]:
    line = line.strip()
    if not line or "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    return SUPPORTED_SCHEMES.get(scheme)


def _parse_vmess(line: str) -> ParsedConfig:
    cfg = ParsedConfig(raw=line, protocol="vmess")
    payload = line[len("vmess://"):]
    decoded = safe_b64decode(payload)
    if not decoded:
        cfg.reject_reason = "vmess base64 decode failed"
        return cfg
    try:
        data = json.loads(decoded)
    except Exception:
        cfg.reject_reason = "vmess json parse failed"
        return cfg
    cfg.address = str(data.get("add", ""))
    try:
        cfg.port = int(data.get("port", 0))
    except (TypeError, ValueError):
        cfg.port = 0
    cfg.uuid_or_password = str(data.get("id", ""))
    cfg.transport = str(data.get("net", "tcp"))
    cfg.host = str(data.get("host", ""))
    cfg.sni = str(data.get("sni", cfg.host))
    tls_val = str(data.get("tls", "")).lower()
    cfg.tls = tls_val in {"tls", "reality"}
    cfg.security = tls_val if tls_val else "none"
    cfg.name = str(data.get("ps", "")) or f"vmess-{cfg.address}"
    cfg.valid = bool(cfg.address and cfg.port and cfg.uuid_or_password)
    return cfg


def _parse_generic_uri(line: str, protocol: str) -> ParsedConfig:
    """
    پارسر عمومی برای vless / trojan / hysteria2 / tuic که ساختار مشابهی دارند:
    scheme://userinfo@host:port?query#name
    """
    cfg = ParsedConfig(raw=line, protocol=protocol)
    try:
        parsed = urlparse(line)
    except Exception:
        cfg.reject_reason = "url parse failed"
        return cfg

    cfg.address = parsed.hostname or ""
    cfg.port = parsed.port or 0
    cfg.uuid_or_password = unquote(parsed.username or "")
    cfg.name = unquote(parsed.fragment or "") or f"{protocol}-{cfg.address}"

    query = parse_qs(parsed.query)
    cfg.transport = (query.get("type") or query.get("network") or ["tcp"])[0]
    security = (query.get("security") or ["none"])[0].lower()
    cfg.security = security
    cfg.tls = security in {"tls", "reality"}
    cfg.sni = (query.get("sni") or [""])[0]
    cfg.host = (query.get("host") or [cfg.sni])[0]

    cfg.valid = bool(cfg.address and cfg.port)
    return cfg


def _parse_shadowsocks(line: str) -> ParsedConfig:
    cfg = ParsedConfig(raw=line, protocol="shadowsocks")
    body = line[len("ss://"):]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1)
        name = unquote(name)

    if "@" in body:
        userinfo, hostpart = body.rsplit("@", 1)
        decoded_userinfo = safe_b64decode(userinfo) or userinfo
    else:
        decoded_all = safe_b64decode(body)
        if not decoded_all or "@" not in decoded_all:
            cfg.reject_reason = "shadowsocks decode failed"
            return cfg
        decoded_userinfo, hostpart = decoded_all.rsplit("@", 1)

    if ":" not in decoded_userinfo:
        cfg.reject_reason = "shadowsocks missing method:password"
        return cfg
    _, password = decoded_userinfo.split(":", 1)
    cfg.uuid_or_password = password

    host, _, port_str = hostpart.partition(":")
    port_str = port_str.split("/")[0].split("?")[0]
    cfg.address = host
    try:
        cfg.port = int(port_str)
    except ValueError:
        cfg.port = 0

    cfg.name = name or f"ss-{cfg.address}"
    cfg.security = "none"
    cfg.tls = False
    cfg.valid = bool(cfg.address and cfg.port and cfg.uuid_or_password)
    return cfg


def _parse_wireguard(line: str) -> ParsedConfig:
    cfg = ParsedConfig(raw=line, protocol="wireguard")
    try:
        parsed = urlparse(line)
        cfg.address = parsed.hostname or ""
        cfg.port = parsed.port or 0
        cfg.uuid_or_password = unquote(parsed.username or "")
        cfg.name = unquote(parsed.fragment or "") or f"wg-{cfg.address}"
        cfg.security = "none"
        cfg.tls = False
        cfg.valid = bool(cfg.address and cfg.port)
    except Exception:
        cfg.reject_reason = "wireguard parse failed"
    return cfg


def _parse_proxy(line: str, protocol: str) -> ParsedConfig:
    """پارسر برای socks:// و http(s):// که رمزنگاری داخلی ندارند."""
    cfg = ParsedConfig(raw=line, protocol=protocol)
    try:
        parsed = urlparse(line)
        cfg.address = parsed.hostname or ""
        cfg.port = parsed.port or 0
        cfg.uuid_or_password = unquote(parsed.username or "")
        cfg.name = unquote(parsed.fragment or "") or f"{protocol}-{cfg.address}"
        cfg.security = "tls" if protocol == "http" and parsed.scheme == "https" else "none"
        cfg.tls = cfg.security == "tls"
        cfg.valid = bool(cfg.address and cfg.port)
    except Exception:
        cfg.reject_reason = "proxy parse failed"
    return cfg


def parse_config_line(line: str) -> Optional[ParsedConfig]:
    """نقطه ورود اصلی: یک خط کانفیگ خام می‌گیرد و ParsedConfig برمی‌گرداند."""
    line = line.strip()
    protocol = detect_protocol(line)
    if not protocol:
        return None

    if protocol == "vmess":
        cfg = _parse_vmess(line)
    elif protocol == "shadowsocks":
        cfg = _parse_shadowsocks(line)
    elif protocol == "wireguard":
        cfg = _parse_wireguard(line)
    elif protocol in {"socks", "http"}:
        cfg = _parse_proxy(line, protocol)
    else:
        cfg = _parse_generic_uri(line, protocol)

    if not cfg.valid:
        return cfg

    # اعتبارسنجی پورت
    if not (0 < cfg.port <= MAX_REASONABLE_PORT):
        cfg.valid = False
        cfg.reject_reason = "invalid port"
        return cfg

    # فیلترهای امنیتی: آدرس‌های خصوصی/رزروشده/لوکال
    if is_private_or_reserved(cfg.address):
        cfg.valid = False
        cfg.reject_reason = "private or reserved address"
        return cfg

    if has_suspicious_domain(cfg.address):
        cfg.valid = False
        cfg.reject_reason = "suspicious domain"
        return cfg

    if has_management_token(line):
        cfg.valid = False
        cfg.reject_reason = "contains management token"
        return cfg

    # کانفیگ بدون TLS/Reality حذف نمی‌شود اما insecure علامت می‌خورد
    cfg.insecure = not cfg.tls

    return cfg


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def config_to_dict(cfg: ParsedConfig) -> dict:
    d = asdict(cfg)
    d["id"] = cfg.unique_key()
    return d
