#!/usr/bin/env python3
"""
响应处理工具函数
"""

import base64
import json
import os
import re
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from curl_cffi import requests as curl_requests

if TYPE_CHECKING:
    from utils.config import AccountConfig


def resolve_account_proxy(account_config: "AccountConfig") -> dict | None:
    """解析账号代理配置（默认不启用）

    规则:
    - proxy 未配置或为 false: 不启用代理（不会自动回退到全局 PROXY）
    - proxy 为 true: 使用全局 PROXY 配置（存储在 extra["global_proxy"] 中）
    - proxy 为 dict（如 {"server": "socks5://host:port"}）: 使用自定义代理

    Args:
        account_config: 账号配置

    Returns:
        代理配置字典（Camoufox/Playwright 格式），未启用时返回 None
    """
    proxy = getattr(account_config, "proxy", None)
    if proxy is True:
        return account_config.get("global_proxy")
    if isinstance(proxy, dict) and proxy:
        return proxy
    return None


def proxy_resolve(proxy_config: dict | None = None) -> str | None:
    """将 proxy_config 转换为代理 URL 字符串

    Args:
        proxy_config: 代理配置字典

    Returns:
        代理 URL 字符串，如果没有配置代理则返回 None
    """
    if not proxy_config:
        return None

    proxy_url = proxy_config.get("server")
    if not proxy_url:
        return None

    username = proxy_config.get("username")
    password = proxy_config.get("password")

    if username and password:
        # 解析 URL 并添加认证信息
        parsed = urlparse(proxy_url)
        # 构建带认证的 URL
        netloc = f"{username}:{password}@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    return proxy_url


def redact_credentials_in_text(text: str) -> str:
    """脱敏文本里可能包含账号密码的 base64 片段

    WAF 拦截页（阿里云 CF_APP_WAF 等）会把被拦下的请求体原样回显在页面里，
    而站点登录的请求体正是 {"username": ..., "password": ...} 的 base64。
    这类页面会被保存进 logs/ 并作为 Actions artifact 上传，等于把账号密码
    一起交出去，因此保存前先把这些片段替换掉。
    """
    def _looks_like_credentials(decoded: str) -> bool:
        lowered = decoded.lower()
        return ("password" in lowered or "passwd" in lowered or '"pwd"' in lowered) and (
            "username" in lowered or "user" in lowered or "email" in lowered
        )

    def _replace(match: re.Match) -> str:
        blob = match.group(0)
        try:
            padded = blob + "=" * (-len(blob) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            return blob
        if _looks_like_credentials(decoded):
            return "[REDACTED_BASE64]"
        return blob

    # base64 片段至少 24 字符，避免误伤普通文本/路径
    return re.sub(r"[A-Za-z0-9+/]{24,}={0,2}", _replace, text)


def response_resolve(
    response: curl_requests.Response,
    context: str,
    account_name: str,
) -> dict | None:
    """检查响应类型，如果是 HTML 则保存为文件，否则返回 JSON 数据

    Args:
        response: curl_cffi Response 对象
        context: 上下文描述，用于生成文件名
        account_name: 账号名称（用于日志和文件名）

    Returns:
        JSON 数据字典，如果响应是 HTML 则返回 None
    """
    safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)

    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    try:
        return response.json()
    except json.JSONDecodeError as e:
        print(f"❌ {account_name}: JSON 响应解析失败: {e}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_context = "".join(c if c.isalnum() else "_" for c in context)

        content_type = response.headers.get("content-type", "").lower()
        # 保存前脱敏：WAF 页面常回显请求体（含站点账号密码的 base64）
        body = redact_credentials_in_text(response.text)

        if "text/html" in content_type or "text/plain" in content_type:
            filename = f"{safe_account_name}_{timestamp}_{safe_context}.html"
            filepath = os.path.join(logs_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(body)

            print(f"⚠️ {account_name}: 收到 HTML 响应，已保存到: {filepath}")
        else:
            filename = f"{safe_account_name}_{timestamp}_{safe_context}_invalid.txt"
            filepath = os.path.join(logs_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(body)

            print(f"⚠️ {account_name}: 无效响应已保存到: {filepath}")
        return None
    except Exception as e:
        print(f"❌ {account_name}: 检查和处理响应时发生错误: {e}")
        return None