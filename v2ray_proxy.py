#!/usr/bin/env python3
"""
v2ray 订阅代理：解析订阅链接、挑选可用节点并启动本地 xray 代理

在 GitHub Actions 的 workflow 步骤中运行：
- Secret V2RAY_SUBSCRIPTION：v2ray 订阅地址（base64 或纯文本节点列表）
- Secret V2RAY_NODE_FILTER（可选）：按节点名称过滤（正则，如 "香港|HK|日本|JP"）
- XRAY_PATH（可选）：xray 可执行文件路径，默认为 xray.exe / xray

成功后：
- 在 127.0.0.1:10808（socks5，无认证）和 127.0.0.1:10809（http）启动本地代理
- 向 GITHUB_OUTPUT 写入 proxy=socks5://127.0.0.1:10808
- 保持 xray 进程运行（后台进程在任务内跨步骤存活）

支持节点协议：vmess / vless / trojan / shadowsocks（tcp/ws/grpc/h2、tls/reality）
"""

import base64
import json
import os
import random
import re
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlparse

SOCKS_PORT = 10808
HTTP_PORT = 10809

MAX_CANDIDATES = 5

_KEEP_PROC = []  # 防止 Popen 对象被回收；子进程在脚本退出后继续运行


# ---------- 订阅获取与解码 ----------


def _b64decode(data: str) -> str:
    padded = data.strip() + "=" * (-len(data.strip()) % 4)
    return base64.b64decode(padded).decode("utf-8", "replace")


def fetch_subscription(url: str) -> list:
    import requests

    resp = requests.get(url, timeout=30, headers={"User-Agent": "v2rayN/6.45"})
    resp.raise_for_status()
    text = resp.text.strip()

    # 订阅内容通常是整体 base64，部分服务会双重编码
    for _ in range(3):
        if "://" in text:
            break
        try:
            text = _b64decode(text).strip()
        except Exception:
            break

    links = [line.strip() for line in text.splitlines() if "://" in line.strip()]
    if not links:
        raise ValueError("订阅内容中没有解析到任何节点链接")
    return links


# ---------- 节点解析 ----------


def parse_vmess(link: str):
    raw = _b64decode(link[len("vmess://"):])
    cfg = json.loads(raw)
    add = cfg.get("add")
    port = int(cfg.get("port") or 443)
    if not add or not cfg.get("id"):
        return None

    net = cfg.get("net") or "tcp"
    stream = {"network": net}
    tls = cfg.get("tls")
    if tls == "tls":
        stream["security"] = "tls"
        tls_settings = {"serverName": cfg.get("sni") or cfg.get("host") or add}
        if cfg.get("fp"):
            tls_settings["fingerprint"] = cfg["fp"]
        if cfg.get("alpn"):
            tls_settings["alpn"] = cfg["alpn"].split(",")
        stream["tlsSettings"] = tls_settings
    elif tls == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": cfg.get("sni") or cfg.get("host") or add,
            "fingerprint": cfg.get("fp") or "chrome",
            "publicKey": cfg.get("pbk") or "",
            "shortId": cfg.get("sid") or "",
        }

    host_header = cfg.get("host") or ""
    path = cfg.get("path") or "/"
    if net == "ws":
        ws = {"path": path}
        if host_header:
            ws["headers"] = {"Host": host_header}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": path.strip("/")}
    elif net == "h2":
        stream["httpSettings"] = {"path": path, "host": [host_header or add]}
    elif net == "tcp" and cfg.get("type") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"headers": {"Host": [host_header or add]}, "path": [path]},
            }
        }

    return {
        "name": cfg.get("ps") or add,
        "outbound": {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": add,
                        "port": port,
                        "users": [
                            {
                                "id": cfg.get("id"),
                                "alterId": int(cfg.get("aid") or 0),
                                "security": cfg.get("scy") or "auto",
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream,
        },
    }


def _stream_from_query(query: dict, host: str) -> dict:
    net = query.get("type", "tcp")
    stream = {"network": net}
    security = query.get("security", "")
    if security == "tls":
        stream["security"] = "tls"
        tls_settings = {"serverName": query.get("sni") or host}
        if query.get("fp"):
            tls_settings["fingerprint"] = query["fp"]
        if query.get("alpn"):
            tls_settings["alpn"] = query["alpn"].split(",")
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": query.get("sni") or host,
            "fingerprint": query.get("fp") or "chrome",
            "publicKey": query.get("pbk", ""),
            "shortId": query.get("sid", ""),
        }

    path = unquote(query.get("path", "/"))
    host_header = query.get("host", "")
    if net == "ws":
        ws = {"path": path}
        if host_header:
            ws["headers"] = {"Host": host_header}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": query.get("serviceName", path.strip("/"))}
    elif net == "h2":
        stream["httpSettings"] = {"path": path, "host": [host_header or host]}
    elif net == "tcp" and query.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"headers": {"Host": [host_header or host]}, "path": [path]},
            }
        }
    return stream


def parse_vless(link: str):
    u = urlparse(link)
    if not u.hostname:
        return None
    query = {k: v[0] for k, v in parse_qs(u.query).items()}
    name = unquote(u.fragment) if u.fragment else u.hostname
    port = u.port or 443
    return {
        "name": name,
        "outbound": {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": u.hostname,
                        "port": port,
                        "users": [
                            {
                                "id": unquote(u.username or ""),
                                "encryption": query.get("encryption", "none"),
                                "flow": query.get("flow", ""),
                            }
                        ],
                    }
                ]
            },
            "streamSettings": _stream_from_query(query, u.hostname),
        },
    }


def parse_trojan(link: str):
    u = urlparse(link)
    if not u.hostname:
        return None
    query = {k: v[0] for k, v in parse_qs(u.query).items()}
    name = unquote(u.fragment) if u.fragment else u.hostname
    return {
        "name": name,
        "outbound": {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": u.hostname,
                        "port": u.port or 443,
                        "password": unquote(u.username or ""),
                    }
                ]
            },
            "streamSettings": _stream_from_query(query, u.hostname),
        },
    }


def parse_ss(link: str):
    body = link[len("ss://"):]
    name = "ss"
    if "#" in body:
        body, _, frag = body.partition("#")
        name = unquote(frag) or name
    body = body.split("?", 1)[0]

    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        try:
            userinfo = _b64decode(userinfo)
        except Exception:
            userinfo = unquote(userinfo)
    else:
        decoded = _b64decode(body)
        userinfo, _, hostport = decoded.rpartition("@")

    method, _, password = userinfo.partition(":")
    u = urlparse(f"//{hostport}")
    if not u.hostname or not u.port:
        return None
    if "plugin=" in link:
        return None  # 带混淆插件（obfs 等）的节点暂不支持

    return {
        "name": name,
        "outbound": {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": u.hostname,
                        "port": u.port,
                        "method": method,
                        "password": password,
                    }
                ]
            },
        },
    }


def parse_nodes(links: list) -> list:
    nodes = []
    for link in links:
        try:
            if link.startswith("vmess://"):
                node = parse_vmess(link)
            elif link.startswith("vless://"):
                node = parse_vless(link)
            elif link.startswith("trojan://"):
                node = parse_trojan(link)
            elif link.startswith("ss://"):
                node = parse_ss(link)
            else:
                continue
            if node and node["outbound"]["settings"]:
                nodes.append(node)
        except Exception as e:
            print(f"⚠️ 节点解析失败: {link[:40]}... ({e})")
    return nodes


# ---------- xray 启动与节点实测 ----------


def build_config(outbound: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks", "settings": {"udp": True}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http", "settings": {}},
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def wait_port(timeout: float = 10) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def test_node() -> tuple:
    """节点连通性测试

    对 linux.do 只要求 TLS 握手成功（任何 HTTP 状态码均可）：数据中心出口 IP 被
    Cloudflare 返回 403/质询页是正常现象，浏览器流程本身会处理质询；真正要排除的
    是 TLS 证书错误（SSL_ERROR_BAD_CERT_DOMAIN）与完全连不通的坏节点。
    出口 IP 查询必须返回 200。
    """
    from curl_cffi import requests as curl_requests

    try:
        curl_requests.get(
            "https://linux.do", proxy=f"socks5://127.0.0.1:{SOCKS_PORT}", timeout=20, impersonate="chrome136"
        )
    except Exception as e:
        return False, f"linux.do TLS 失败: {type(e).__name__}: {str(e)[:100]}"

    try:
        resp = curl_requests.get(
            "https://api.ipify.org",
            proxy=f"socks5://127.0.0.1:{SOCKS_PORT}",
            timeout=20,
            impersonate="chrome136",
        )
        if resp.status_code != 200:
            return False, f"出口 IP 查询返回 HTTP {resp.status_code}"
        return True, resp.text.strip()[:64]
    except Exception as e:
        return False, f"出口 IP 查询失败: {type(e).__name__}: {str(e)[:100]}"


def set_github_output(key: str, value: str) -> None:
    out_file = os.getenv("GITHUB_OUTPUT")
    if out_file:
        with open(out_file, "a", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")
    print(f"ℹ️ 输出 {key}={value}")


def main() -> int:
    subscription = os.getenv("V2RAY_SUBSCRIPTION", "").strip()
    node_filter = os.getenv("V2RAY_NODE_FILTER", "").strip()
    xray_path = os.getenv("XRAY_PATH", "xray.exe" if os.name == "nt" else "xray")

    if not subscription:
        print("❌ V2RAY_SUBSCRIPTION 未配置")
        return 1

    links = fetch_subscription(subscription)
    nodes = parse_nodes(links)
    print(f"ℹ️ 订阅解析到 {len(nodes)} 个节点")
    if node_filter:
        nodes = [n for n in nodes if re.search(node_filter, n["name"])]
        print(f"ℹ️ 按过滤条件 \"{node_filter}\" 匹配到 {len(nodes)} 个节点")
    if not nodes:
        print("❌ 没有可用的候选节点")
        return 1

    random.shuffle(nodes)

    for node in nodes[:MAX_CANDIDATES]:
        print(f"ℹ️ 尝试节点: {node['name']}")
        config_path = os.path.abspath("xray_config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(build_config(node["outbound"]), f, ensure_ascii=False, indent=2)

        proc = subprocess.Popen(
            [xray_path, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _KEEP_PROC.append(proc)

        if not wait_port():
            print(f"⚠️ 节点 {node['name']}: xray 启动失败")
            proc.terminate()
            continue

        try:
            ok, exit_ip = test_node()
        except Exception as e:
            print(f"⚠️ 节点 {node['name']}: 连通性测试失败 - {type(e).__name__}: {str(e)[:120]}")
            proc.terminate()
            continue

        if ok:
            print(f"✅ 已选择节点: {node['name']}（出口 IP: {exit_ip}）")
            print(f"✅ 本地代理已就绪: socks5://127.0.0.1:{SOCKS_PORT} / http://127.0.0.1:{HTTP_PORT}")
            set_github_output("proxy", f"socks5://127.0.0.1:{SOCKS_PORT}")
            return 0

        print(f"⚠️ 节点 {node['name']}: 连通性测试未通过，尝试下一个节点")
        proc.terminate()

    print(f"❌ 已尝试 {min(len(nodes), MAX_CANDIDATES)} 个节点均不可用")
    return 1


if __name__ == "__main__":
    sys.exit(main())
