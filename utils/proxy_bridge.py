#!/usr/bin/env python3
"""
本地 HTTP → SOCKS5 桥接代理

Camoufox（Playwright/Firefox）不支持带用户名密码认证的 SOCKS5 代理（启动时直接报错，
凭据写在 server URL 里则被静默剥离）。本模块在本地起一个无认证的 HTTP 代理，
把浏览器的代理请求转发到远端带认证的 SOCKS5 代理：

    浏览器 --HTTP(无认证)--> 本地桥接 --SOCKS5(RFC 1929 认证)--> 远端代理

- CONNECT 请求（HTTPS，浏览器流量的绝大多数）：建立 SOCKS5 隧道后双向转发
- 绝对地址形式的普通 HTTP 请求：同样先建隧道再转发原始请求
- 目标地址以域名（ATYP=0x03）发给远端代理解析，等价于 socks5h 的远程 DNS 行为
- 进程内按 (host, port, username, password) 去重复用同一个桥接实例

仅使用标准库，无新增依赖。
"""

import ipaddress
import socket
import struct
import threading
from urllib.parse import unquote

# SOCKS5 握手常量
_SOCKS_VER = 0x05
_CMD_CONNECT = 0x01
_METHOD_NO_AUTH = 0x00
_METHOD_USER_PASS = 0x02
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04

# RFC 1928 reply code 说明，用于错误日志
_SOCKS_REPLY_MESSAGES = {
    0: "成功",
    1: "通用 SOCKS 服务器失败",
    2: "规则不允许此连接",
    3: "网络不可达",
    4: "主机不可达",
    5: "连接被拒绝",
    6: "TTL 过期",
    7: "命令不支持",
    8: "地址类型不支持",
}

_CONNECT_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"
_CONNECT_FAIL = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

_SOCKS_CONNECT_TIMEOUT = 15
_MAX_ERROR_LOGS = 3


class Socks5HttpBridge:
    """本地无认证 HTTP 代理，转发到远端带认证的 SOCKS5 代理"""

    def __init__(self, host: str, port: int, username: str | None, password: str | None, owner: str = ""):
        self.socks_host = host
        self.socks_port = port
        self.username = username
        self.password = password
        self.owner = owner
        self.local_port: int | None = None
        self._server_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._connections: set = set()
        self._conn_lock = threading.Lock()
        self._error_logs = 0
        self._error_lock = threading.Lock()

    # ---- 生命周期 ----

    def start(self) -> str:
        """启动本地 HTTP 代理监听，返回代理 server URL（http://127.0.0.1:端口）"""
        if self.local_port is not None:
            return f"http://127.0.0.1:{self.local_port}"

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(64)
        self.local_port = server.getsockname()[1]
        self._server_sock = server

        self._accept_thread = threading.Thread(
            target=self._accept_loop, name=f"socks-bridge-{self.local_port}", daemon=True
        )
        self._accept_thread.start()
        owner_tag = f"[{self.owner}] " if self.owner else ""
        print(
            f"ℹ️ {owner_tag}检测到带认证的 SOCKS5 代理，已启动本地桥接: "
            f"http://127.0.0.1:{self.local_port} -> socks5://{self.socks_host}:{self.socks_port}"
        )
        return f"http://127.0.0.1:{self.local_port}"

    def stop(self) -> None:
        """停止监听（已建立的隧道由浏览器断开时自然结束）"""
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None
        with self._conn_lock:
            for conn in list(self._connections):
                try:
                    conn.close()
                except Exception:
                    pass
            self._connections.clear()

    # ---- 接受连接 ----

    def _accept_loop(self) -> None:
        while True:
            try:
                client, _ = self._server_sock.accept()
            except OSError:
                break  # 监听 socket 已关闭
            with self._conn_lock:
                self._connections.add(client)
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _log_error(self, message: str) -> None:
        with self._error_lock:
            if self._error_logs < _MAX_ERROR_LOGS:
                self._error_logs += 1
                owner_tag = f"[{self.owner}] " if self.owner else ""
                print(f"⚠️ {owner_tag}本地代理桥接错误: {message}")
            elif self._error_logs == _MAX_ERROR_LOGS:
                self._error_logs += 1
                print(f"⚠️ 本地代理桥接错误较多，后续同类错误不再打印")

    # ---- 客户端处理 ----

    def _handle_client(self, client: socket.socket) -> None:
        remote = None
        try:
            client.settimeout(30)
            head = self._read_head(client)
            if not head:
                client.close()
                return

            first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first_line.split(" ")
            if len(parts) >= 2 and parts[0].upper() == "CONNECT":
                # CONNECT host:port HTTP/1.x
                target = parts[1]
                host, port = self._parse_host_port(target)
            else:
                # 绝对地址形式的普通 HTTP 请求：GET http://host/path HTTP/1.1
                host, port = self._parse_http_head_target(head)
                if host is None:
                    client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    client.close()
                    return

            remote = self._open_socks5_tunnel(host, port)
            if remote is None:
                client.sendall(_CONNECT_FAIL)
                client.close()
                return

            client.settimeout(None)
            if parts[0].upper() != "CONNECT":
                # 非 CONNECT：把已收到的原始请求头转发给目标服务器，后续双向透传
                remote.sendall(head)
            else:
                client.sendall(_CONNECT_OK)

            upstream = threading.Thread(target=self._relay, args=(client, remote), daemon=True)
            upstream.start()
            self._relay(remote, client)
            upstream.join(timeout=5)
        except Exception as e:
            self._log_error(f"{e!r}")
            try:
                client.sendall(_CONNECT_FAIL)
            except Exception:
                pass
        finally:
            try:
                client.close()
            except Exception:
                pass
            if remote:
                try:
                    remote.close()
                except Exception:
                    pass
            with self._conn_lock:
                self._connections.discard(client)

    def _read_head(self, client: socket.socket) -> bytes | None:
        """读取完整的 HTTP 请求头（到 \\r\\n\\r\\n 为止）"""
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client.recv(65536)
            if not chunk:
                return None
            head += chunk
            if len(head) > 256 * 1024:
                return None
        return head

    @staticmethod
    def _parse_host_port(target: str) -> tuple[str, int]:
        if target.startswith("["):  # IPv6 字面量 [::1]:80
            host, _, rest = target[1:].partition("]")
            port = int(rest.lstrip(":") or 0)
            return host, port
        host, _, port_str = target.rpartition(":")
        if not host:
            return target, 80
        return host, int(port_str or 0)

    def _parse_http_head_target(self, head: bytes) -> tuple[str | None, int]:
        """从绝对地址形式的请求头解析目标 host:port（优先请求行，其次 Host 头）"""
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first_line.split(" ")
        url = parts[1] if len(parts) >= 2 else ""
        if url.lower().startswith(("http://", "https://")):
            rest = url.split("://", 1)[1]
            authority = rest.split("/", 1)[0]
            host, port = self._parse_host_port(authority)
            if port == 0:
                port = 443 if url.lower().startswith("https://") else 80
            return host, port
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host, port = self._parse_host_port(line.split(b":", 1)[1].decode("latin-1").strip())
                return host, port or 80
        return None, 0

    # ---- SOCKS5 隧道 ----

    def _open_socks5_tunnel(self, host: str, port: int) -> socket.socket | None:
        """与远端 SOCKS5 代理完成认证和 CONNECT，返回隧道 socket"""
        try:
            remote = socket.create_connection((self.socks_host, self.socks_port), timeout=_SOCKS_CONNECT_TIMEOUT)
            remote.settimeout(_SOCKS_CONNECT_TIMEOUT)

            # 握手：优先提供用户名密码认证，同时允许无认证
            methods = [_METHOD_USER_PASS, _METHOD_NO_AUTH] if self.username or self.password else [_METHOD_NO_AUTH]
            remote.sendall(bytes([_SOCKS_VER, len(methods)]) + bytes(methods))
            resp = self._recv_exact(remote, 2)
            if not resp or resp[0] != _SOCKS_VER:
                self._log_error(f"SOCKS5 握手响应异常: {resp!r}")
                remote.close()
                return None
            method = resp[1]

            if method == _METHOD_USER_PASS:
                user = (self.username or "").encode("utf-8")[:255]
                password = (self.password or "").encode("utf-8")[:255]
                remote.sendall(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
                auth_resp = self._recv_exact(remote, 2)
                if not auth_resp or auth_resp[1] != 0x00:
                    self._log_error(f"SOCKS5 用户名密码认证被拒绝 (user={self.username})")
                    remote.close()
                    return None
            elif method != _METHOD_NO_AUTH:
                self._log_error(f"SOCKS5 代理选择了不支持的方法: {method:#x}")
                remote.close()
                return None

            # CONNECT 目标：IPv4/IPv6 字面量或域名（由远端解析，等价 socks5h）
            if _is_ipv4(host):
                addr = bytes([_ATYP_IPV4]) + socket.inet_aton(host)
            elif ":" in host:
                addr = bytes([_ATYP_IPV6]) + socket.inet_pton(socket.AF_INET6, host)
            else:
                encoded = _encode_host(host)
                addr = bytes([_ATYP_DOMAIN, len(encoded)]) + encoded
            # CONNECT 命令：VER=5, CMD=1(CONNECT), RSV=0
            remote.sendall(bytes([_SOCKS_VER, _CMD_CONNECT, 0x00]) + addr + struct.pack(">H", port or 80))

            reply = self._recv_exact(remote, 4)
            if not reply or reply[1] != 0x00:
                code = reply[1] if reply else -1
                reason = _SOCKS_REPLY_MESSAGES.get(code, "未知错误码")
                self._log_error(f"SOCKS5 CONNECT 失败: {host}:{port} (reply={code}, {reason})")
                remote.close()
                return None

            # 跳过绑定地址，长度取决于 ATYP
            atyp = reply[3]
            if atyp == _ATYP_IPV4:
                self._recv_exact(remote, 4 + 2)
            elif atyp == _ATYP_IPV6:
                self._recv_exact(remote, 16 + 2)
            elif atyp == _ATYP_DOMAIN:
                length = self._recv_exact(remote, 1)
                if not length:
                    remote.close()
                    return None
                self._recv_exact(remote, length[0] + 2)

            remote.settimeout(None)
            return remote
        except Exception as e:
            self._log_error(f"建立 SOCKS5 隧道失败 {self.socks_host}:{self.socks_port} -> {host}:{port}: {e!r}")
            return None

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes | None:
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _relay(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass


def _is_ipv4(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


def _encode_host(host: str) -> bytes:
    try:
        return host.encode("ascii")
    except UnicodeEncodeError:
        return host.encode("idna")


# ---- 进程级桥接注册表：相同 SOCKS5 端点复用同一个桥接实例 ----

_bridges: dict[tuple, Socks5HttpBridge] = {}
_bridges_lock = threading.Lock()

_maxminddb_patched = False


def _patch_maxminddb_windows_path() -> None:
    """修复 Windows 下项目路径包含非 ASCII 字符时 geoip 查询失败的问题

    maxminddb 会把数据库路径 os.fsencode 成 UTF-8 bytes 再交给 C 扩展打开，
    而 Windows 的文件 CRT 按 ANSI 代码页（如 GBK）解码 bytes 路径，
    导致非 ASCII 安装路径（如 "D:\\ai 项目\\newapi签到"）报 FileNotFoundError。
    这里在打开前把 bytes 以 UTF-8 解码回 str。CI（ASCII 路径）与非 Windows 平台不受影响。
    """
    global _maxminddb_patched
    if _maxminddb_patched:
        return
    _maxminddb_patched = True

    import sys

    if sys.platform != "win32":
        return
    try:
        import maxminddb

        original = maxminddb.open_database

        def open_database_unicode(source, mode=None, **kwargs):
            if isinstance(source, (bytes, bytearray)):
                source = source.decode("utf-8", "replace")
            # C 扩展在 Windows 上按 ANSI 代码页处理路径，非 ASCII 路径必失败，
            # 改用纯 Python 的内存映射实现（使用 Unicode API 打开文件）
            if mode is None or mode in (maxminddb.MODE_AUTO, maxminddb.MODE_MMAP_EXT):
                mode = maxminddb.MODE_MMAP
            return original(source, mode, **kwargs)

        maxminddb.open_database = open_database_unicode
    except Exception:
        pass


def _parse_socks5_proxy(proxy: dict) -> tuple | None:
    """从代理配置解析 SOCKS5 端点，仅当带认证时返回 (host, port, username, password)

    支持 socks5:// 和 socks5h://，凭据可以写在 server URL 里或 username/password 字段中。
    免认证的 SOCKS5 浏览器可直接使用，无需桥接，返回 None。
    """
    server = str(proxy.get("server") or "")
    if "://" not in server:
        return None
    scheme, rest = server.split("://", 1)
    scheme = scheme.lower()
    if scheme not in ("socks5", "socks5h"):
        return None

    userinfo = None
    if "@" in rest:
        userinfo, rest = rest.rsplit("@", 1)
    host, _, port_str = rest.partition(":")
    port = int(port_str) if port_str.isdigit() else 1080
    if not host:
        return None

    username = proxy.get("username")
    password = proxy.get("password")
    if not username and userinfo:
        user, _, pwd = unquote(userinfo).partition(":")
        username, password = user, pwd or None

    if not username and not password:
        return None
    return host, port, username, password


def get_browser_proxy(proxy_config: dict | None, owner: str = "") -> dict | None:
    """为浏览器（Camoufox）准备代理配置

    - None / http / https / 免认证 socks5：原样返回（浏览器可直接使用）
    - 带认证的 socks5 / socks5h：启动（或复用）本地 HTTP→SOCKS5 桥接，
      返回 {"server": "http://127.0.0.1:端口"}
    """
    if not proxy_config:
        return proxy_config

    _patch_maxminddb_windows_path()

    parsed = _parse_socks5_proxy(proxy_config)
    if not parsed:
        return proxy_config

    with _bridges_lock:
        bridge = _bridges.get(parsed)
        if bridge is None:
            host, port, username, password = parsed
            bridge = Socks5HttpBridge(host, port, username, password, owner=owner)
            _bridges[parsed] = bridge
    return {"server": bridge.start()}


def stop_all_bridges() -> None:
    """停止所有桥接实例（进程退出前可选调用）"""
    with _bridges_lock:
        for bridge in _bridges.values():
            bridge.stop()
        _bridges.clear()
