"""
collector.py
دریافت محتوای خام از منابع مشخص‌شده در data/sources.json (فقط Allowlist).
هیچ منبع ناشناسی به‌صورت خودکار اضافه یا Discover نمی‌شود.

خروجی: یک لیست از دیکشنری {"source_name", "source_url", "content"} که در
مرحله بعد توسط parser.py پردازش می‌شود.
"""
from __future__ import annotations

import sys
import time
import urllib.request
import urllib.error
from typing import List, Dict

from common import load_json

SOURCES_PATH = "data/sources.json"


def fetch_url(url: str, timeout: int, max_size: int, retries: int, user_agent: str) -> str:
    """دریافت محتوای یک URL با Timeout، Retry محدود و محدودیت حجم فایل."""
    last_error = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": user_agent})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = response.read(max_size + 1)
                if len(data) > max_size:
                    raise ValueError("file too large, skipped")
                return data.decode("utf-8", errors="ignore")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = exc
            time.sleep(1)
    print(f"[collector] failed to fetch {url}: {last_error}", file=sys.stderr)
    return ""


def collect() -> List[Dict[str, str]]:
    sources = load_json(SOURCES_PATH, {})
    settings = sources.get("settings", {})
    timeout = int(settings.get("request_timeout_seconds", 10))
    max_size = int(settings.get("max_file_size_bytes", 5_000_000))
    retries = int(settings.get("max_retries", 2))
    user_agent = settings.get("user_agent", "config-aggregator-bot/1.0")

    results: List[Dict[str, str]] = []

    for group in ("github_sources", "subscription_sources"):
        for source in sources.get(group, []):
            if not source.get("enabled"):
                continue
            url = source["url"]
            content = fetch_url(url, timeout, max_size, retries, user_agent)
            if content:
                results.append({
                    "source_name": source.get("name", url),
                    "source_url": url,
                    "content": content,
                })

    # منابع دستی (فایل‌های محلی داخل مخزن)
    for source in sources.get("manual_sources", []):
        if not source.get("enabled"):
            continue
        path = source.get("path")
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            if content.strip():
                results.append({
                    "source_name": source.get("name", path),
                    "source_url": path,
                    "content": content,
                })
        except FileNotFoundError:
            continue

    # منابع تلگرام: در نسخه اولیه فقط از طریق فایل واسط عمومی خوانده می‌شوند.
    # پشتیبانی مستقیم از Telegram Bot API (برای کانال متعلق به مدیر پروژه)
    # می‌تواند بعداً اضافه شود و توکن آن فقط از GitHub Secrets خوانده شود،
    # هرگز داخل کد یا لاگ چاپ نمی‌شود.
    for source in sources.get("telegram_sources", []):
        if not source.get("enabled"):
            continue
        print(f"[collector] telegram source '{source.get('name')}' skipped "
              f"(not implemented in base version)", file=sys.stderr)

    return results


if __name__ == "__main__":
    collected = collect()
    print(f"[collector] fetched {len(collected)} source(s)")
