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

MAX_CANDIDATES = 10  # 测速候选节点数上限

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


def fetch_subscriptions(raw: str) -> list:
    """下载一个或多个订阅并合并节点链接

    多个订阅地址之间用换行、逗号或空白分隔（Secret 中可多行填写）。
    单个订阅失败不影响其他订阅（打印警告后继续）；全部失败时报错退出。

    Returns:
        合并去重后的节点链接列表
    """
    urls = [u.strip() for u in re.split(r"[\n\r,;\s]+", raw.strip()) if u.strip()]
    if not urls:
        raise ValueError("V2RAY_SUBSCRIPTION 为空")

    all_links = []
    failed = []
    for i, url in enumerate(urls, 1):
        if len(urls) > 1:
            print(f"📥 下载订阅 {i}/{len(urls)}: {url[:60]}{'...' if len(url) > 60 else ''}")
        try:
            links = fetch_subscription(url)
            all_links.extend(links)
            print(f"   ✅ {len(links)} 个节点")
        except Exception as e:
            failed.append(url)
            print(f"   ⚠️ 订阅失败: {type(e).__name__}: {str(e)[:100]}")

    if not all_links:
        raise ValueError(f"全部 {len(urls)} 个订阅均下载失败")

    if failed:
        print(f"⚠️ {len(failed)}/{len(urls)} 个订阅失败，继续使用其余订阅的节点")

    # 去重（同一节点出现在多个订阅中时）
    seen = set()
    unique_links = []
    for link in all_links:
        if link not in seen:
            seen.add(link)
            unique_links.append(link)
    return unique_links


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


def build_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": True}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": socks_port + 1, "protocol": "http", "settings": {}},
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def start_xray(outbound: dict, socks_port: int, xray_path: str):
    """写配置并启动 xray，返回 Popen（失败返回 None）"""
    config_path = os.path.abspath("xray_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(build_config(outbound, socks_port), f, ensure_ascii=False, indent=2)
    try:
        proc = subprocess.Popen(
            [xray_path, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"⚠️ xray 启动异常: {e}")
        return None
    _KEEP_PROC.append(proc)
    return proc


def stop_xray(proc) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def wait_port(port: int, timeout: float = 10) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def probe_latency(socks_port: int, timeout: int = 10) -> float | None:
    """测速：通过节点请求 https://connect.linux.do（OAuth 网关，链路关键域名）的总耗时

    Returns:
        耗时秒数；连接失败（含 TLS 证书错误）返回 None
    """
    from curl_cffi import requests as curl_requests

    start = time.monotonic()
    try:
        curl_requests.get(
            "https://connect.linux.do",
            proxy=f"socks5://127.0.0.1:{socks_port}",
            timeout=timeout,
            impersonate="chrome136",
        )
        return time.monotonic() - start
    except Exception:
        return None


def probe_challenge_reachable(socks_port: int, timeout: int = 10) -> bool:
    """验证 Cloudflare 质询组件域名经节点可达

    Cloudflare 全屏质询页的验证组件从 challenges.cloudflare.com 加载；
    实测部分节点（尤其数据中心 IP 段）该域名加载不出，导致质询页永远
    无法通过（Cloudflare iframes not found 的根因）。延迟最低的节点
    往往正是这类节点，因此测速必须先验证质询可达性再比延迟。
    """
    from curl_cffi import requests as curl_requests

    try:
        resp = curl_requests.get(
            "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/scripts/jsd/main.js",
            proxy=f"socks5://127.0.0.1:{socks_port}",
            timeout=timeout,
            impersonate="chrome136",
        )
        return resp.status_code == 200
    except Exception:
        return False


def test_node(socks_port: int) -> tuple:
    """节点完整连通性验证（对测速胜出的节点执行）

    对 linux.do 与 connect.linux.do（OAuth 网关，独立证书）只要求 TLS 握手成功
    （任何 HTTP 状态码均可）：数据中心出口 IP 被 Cloudflare 返回 403/质询页是正常
    现象，浏览器流程本身会处理质询；真正要排除的是 TLS 证书错误
    （SSL_ERROR_BAD_CERT_DOMAIN，节点侧 DNS 污染/SNI 劫持的标志）与完全连不通的
    坏节点。实测有节点 linux.do 主域正常但 connect.linux.do 证书不匹配。
    出口 IP 查询必须返回 200。
    """
    from curl_cffi import requests as curl_requests

    for host in ("linux.do", "connect.linux.do"):
        try:
            curl_requests.get(
                f"https://{host}", proxy=f"socks5://127.0.0.1:{socks_port}", timeout=20, impersonate="chrome136"
            )
        except Exception as e:
            return False, f"{host} TLS 失败: {type(e).__name__}: {str(e)[:100]}"

    try:
        resp = curl_requests.get(
            "https://api.ipify.org",
            proxy=f"socks5://127.0.0.1:{socks_port}",
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

    links = fetch_subscriptions(subscription)
    nodes = parse_nodes(links)
    print(f"ℹ️ 共解析到 {len(nodes)} 个节点")
    if node_filter:
        nodes = [n for n in nodes if re.search(node_filter, n["name"])]
        print(f"ℹ️ 按过滤条件 \"{node_filter}\" 匹配到 {len(nodes)} 个节点")
    if not nodes:
        print("❌ 没有可用的候选节点")
        return 1

    random.shuffle(nodes)
    candidates = nodes[:MAX_CANDIDATES]

    # ---- 阶段一：逐节点测速（质询组件可达为硬性门槛，connect.linux.do 耗时为速度指标） ----
    print(f"🏃 开始节点测速（{len(candidates)} 个候选，指标：connect.linux.do 耗时 + 质询组件可达）")
    scored = []  # (延迟秒数, node)
    total = len(candidates)
    for i, node in enumerate(candidates, 1):
        # 每个候选使用独立端口，测完即停，避免端口占用冲突
        probe_port = SOCKS_PORT + 100 + i * 10
        proc = start_xray(node["outbound"], probe_port, xray_path)
        if proc is None:
            print(f"  [{i}/{total}] {node['name']}: xray 启动失败")
            continue
        if not wait_port(probe_port, timeout=8):
            print(f"  [{i}/{total}] {node['name']}: xray 启动超时")
            stop_xray(proc)
            continue
        latency = probe_latency(probe_port)
        if latency is None:
            print(f"  [{i}/{total}] {node['name']}: 连通性测试失败")
            stop_xray(proc)
            continue
        # Cloudflare 质询组件不可达的节点直接淘汰（质询永远过不了，延迟再低也没用）
        if not probe_challenge_reachable(probe_port):
            print(f"  [{i}/{total}] {node['name']}: {latency:.2f}s 但质询组件不可达，淘汰")
            stop_xray(proc)
            continue
        print(f"  [{i}/{total}] {node['name']}: {latency:.2f}s（质询组件可达）")
        stop_xray(proc)
        scored.append((latency, node))

    if not scored:
        print(f"❌ 已尝试 {total} 个节点均不可用")
        return 1

    scored.sort(key=lambda x: x[0])
    print("📊 测速排名（前 5）:")
    for rank, (latency, node) in enumerate(scored[:5], 1):
        print(f"  {rank}. {node['name']} — {latency:.2f}s")

    # ---- 阶段二：延迟最低的节点依次完整验证并启动，第一个通过的即选定 ----
    for latency, node in scored[:3]:
        proc = start_xray(node["outbound"], SOCKS_PORT, xray_path)
        if proc is None or not wait_port(SOCKS_PORT, timeout=8):
            stop_xray(proc)
            print(f"⚠️ 节点 {node['name']}: 启动失败，尝试下一个")
            continue
        try:
            ok, detail = test_node(SOCKS_PORT)
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {str(e)[:100]}"
        if ok:
            print(f"✅ 已选择最快节点: {node['name']}（延迟 {latency:.2f}s，出口 IP: {detail}）")
            print(f"✅ 本地代理已就绪: socks5://127.0.0.1:{SOCKS_PORT} / http://127.0.0.1:{SOCKS_PORT + 1}")
            set_github_output("proxy", f"socks5://127.0.0.1:{SOCKS_PORT}")
            return 0
        stop_xray(proc)
        print(f"⚠️ 节点 {node['name']}: 完整验证未通过（{detail}），尝试下一个")

    print("❌ 测速胜出的节点均未通过完整验证")
    return 1


if __name__ == "__main__":
    sys.exit(main())
