#!/usr/bin/env python3
"""
CheckIn 类
"""

import asyncio
import json
import inspect
import hashlib
import os
import tempfile
from datetime import datetime
from urllib.parse import urlparse, urlencode

from curl_cffi import requests as curl_requests
from camoufox.async_api import AsyncCamoufox
from utils.config import AccountConfig, ProviderConfig
from utils.browser_utils import parse_cookies, filter_cookies, get_random_user_agent, take_screenshot, aliyun_captcha_check
from utils.get_cf_clearance import get_cf_clearance
from utils.http_utils import proxy_resolve, response_resolve, resolve_account_proxy
from utils.topup import topup
from utils.get_headers import get_browser_headers, get_curl_cffi_impersonate, print_browser_headers
from utils.mask_utils import mask_username

class CheckIn:
    """newapi.ai 签到管理类"""

    def __init__(
        self,
        account_name: str,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
        github_accounts: list | None = None,
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
                proxy_config: 全局代理配置(可选)
                github_accounts: 全局 GitHub 账号列表（供 linux.do 的 GitHub 登录使用，可选）
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.account_config = account_config
        self.provider_config = provider_config
        # 全局 GitHub 账号（linux.do 登录页支持 GitHub OAuth，凭据从 ACCOUNTS_GITHUB 复用）
        self.github_accounts = github_accounts or []

        # 将全局代理存入 account_config.extra，供 get_cdk 和 check_in_status 等函数使用
        if global_proxy:
            self.account_config.extra["global_proxy"] = global_proxy

        self.global_proxy = global_proxy

        # 账号代理默认不启用：proxy=true 时使用全局 PROXY，dict 为自定义代理，未配置则不走代理
        resolved_proxy = resolve_account_proxy(account_config)
        if global_proxy and not resolved_proxy:
            print(
                f"ℹ️ {self.account_name}: 已配置全局 PROXY 但此账号未启用 "
                "(在 ACCOUNTS 中设置 \"proxy\": true 以启用)"
            )
        # HTTP 请求层（curl_cffi/libcurl）与浏览器层共用账号代理配置
        # （本地代理如 v2ray/xray 均为无认证 socks5/http，浏览器可直接使用）
        self.http_proxy_config = proxy_resolve(resolved_proxy)
        self.camoufox_proxy_config = resolved_proxy

        # storage-states 目录
        self.storage_state_dir = storage_state_dir

        os.makedirs(self.storage_state_dir, exist_ok=True)

    # WAF cookie 与来源 IP 绑定：签到请求与获取 bypass_cookies 走同一出口（默认直连），
    # 而 OAuth 浏览器可能经代理（出口 IP 不同）回跳站点拿到另一组 WAF cookie。
    # 合并时 WAF 类 cookie 必须保留 bypass 侧的版本，否则签到请求会被 WAF 拦截
    WAF_COOKIE_NAMES = frozenset({"acw_tc", "cdn_sec_tc", "acw_sc__v2", "cf_clearance"})

    def merge_cookies(self, bypass_cookies: dict, user_cookies: dict) -> dict:
        """合并 WAF/CF bypass cookies 与用户会话 cookies

        WAF 类 cookie 优先取 bypass_cookies（与签到请求同出口），
        其余（session 等站点会话）优先取 user_cookies
        """
        merged = dict(user_cookies)
        for name, value in bypass_cookies.items():
            if name in self.WAF_COOKIE_NAMES or name not in merged:
                merged[name] = value
        return merged

    # ---- 站点会话缓存：OAuth 成功后的站点 session（如 anyrouter.top 的 session）
    # 有效期通常远长于 linux.do/GitHub 授权流程，缓存后下次运行直接复用，
    # 避免每次运行都触发 linux.do Cloudflare 质询与 GitHub 2FA ----

    def _site_session_path(self, auth_type: str, username_hash: str) -> str:
        """站点会话缓存文件路径（存放在 storage-states 目录，随 Actions 缓存持久化）"""
        return f"{self.storage_state_dir}/site_{self.provider_config.name}_{auth_type}_{username_hash}.json"

    def _load_site_session(self, auth_type: str, username_hash: str) -> dict | None:
        """读取站点会话缓存，无缓存或格式不完整时返回 None"""
        path = self._site_session_path(auth_type, username_hash)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ {self.account_name}: 读取站点会话缓存失败: {e}")
            return None
        if not data.get("cookies") or not data.get("api_user"):
            return None
        return data

    def _save_site_session(
        self,
        auth_type: str,
        username_hash: str,
        cookies: dict,
        api_user: str | int,
        browser_headers: dict | None = None,
    ) -> None:
        """保存站点会话缓存（OAuth 成功后调用）"""
        if not cookies or not api_user:
            return
        try:
            os.makedirs(self.storage_state_dir, exist_ok=True)
            path = self._site_session_path(auth_type, username_hash)
            data = {
                "cookies": cookies,
                "api_user": api_user,
                "browser_headers": browser_headers or {},
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ {self.account_name}: 站点会话已缓存（下次运行将优先复用，无需重新登录）")
        except Exception as e:
            print(f"⚠️ {self.account_name}: 保存站点会话缓存失败: {e}")

    async def _try_cached_site_session(
        self,
        auth_type: str,
        username_hash: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict] | None:
        """尝试用缓存的站点会话直接签到

        Returns:
            (成功标志, 结果) ；无缓存时返回 None（调用方继续 OAuth 流程）
        """
        cached = self._load_site_session(auth_type, username_hash)
        if not cached:
            return None

        print(
            f"ℹ️ {self.account_name}: 发现站点会话缓存（保存于 {cached.get('saved_at', '未知')}），"
            "尝试直接签到（免登录）"
        )
        cached_headers = common_headers.copy()
        if cached.get("browser_headers"):
            cached_headers.update(cached["browser_headers"])
        cached_cookies = self.merge_cookies(bypass_cookies, cached["cookies"])
        try:
            ok, info = await self.check_in_with_cookies(cached_cookies, cached_headers, cached["api_user"])
        except Exception as e:
            ok, info = False, {"error": f"缓存会话签到异常：{e}"}

        if ok:
            print(f"✅ {self.account_name}: 站点会话有效，本次无需重新登录")
            return ok, info

        print(
            f"⚠️ {self.account_name}: 站点会话已失效"
            f"（{info.get('error', '未知原因')}），重新走 {auth_type} 登录"
        )
        return None

    async def get_waf_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取 WAF cookies（隐私模式）"""
        print(
            f"ℹ️ {self.account_name}: 启动浏览器获取 WAF Cookie (使用代理: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_waf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: 使用临时目录：{tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: 访问登录页获取初始 Cookie")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    cookies = await browser.cookies()

                    waf_cookies = {}
                    print(f"ℹ️ {self.account_name}: WAF Cookie 列表")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (值：{cookie_value})")
                        if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"] and cookie_value is not None:
                            waf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: 第 1 步后获取到 {len(waf_cookies)} 个 WAF Cookie")

                    # 检查是否至少获取到一个 WAF cookie
                    if not waf_cookies:
                        print(f"❌ {self.account_name}: 未获取到 WAF Cookie")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(waf_cookies.keys())
                    print(f"✅ {self.account_name}: 成功获取 WAF Cookie: {cookie_names}")

                    return waf_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: 获取 WAF Cookie 时发生错误：{e}")
                    return None
                finally:
                    await page.close()

    async def get_aliyun_captcha_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取阿里云验证 cookies"""
        print(
            f"ℹ️ {self.account_name}: 启动浏览器获取阿里云验证码 Cookie (使用代理: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_aliyun_captcha_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: 使用临时目录：{tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: 访问登录页获取初始 Cookie")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                        # # 提取验证码相关数据
                        # captcha_data = await page.evaluate(
                        #     """() => {
                        #     const data = {};

                        #     // 获取 traceid
                        #     const traceElement = document.getElementById('traceid');
                        #     if (traceElement) {
                        #         const text = traceElement.innerText || traceElement.textContent;
                        #         const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                        #         data.traceid = match ? match[1] : null;
                        #     }

                        #     // 获取 window.aliyun_captcha 相关字段
                        #     for (const key in window) {
                        #         if (key.startsWith('aliyun_captcha')) {
                        #             data[key] = window[key];
                        #         }
                        #     }

                        #     // 获取 requestInfo
                        #     if (window.requestInfo) {
                        #         data.requestInfo = window.requestInfo;
                        #     }

                        #     // 获取当前 URL
                        #     data.currentUrl = window.location.href;

                        #     return data;
                        # }"""
                        # )

                        # print(
                        #     f"📋 {self.account_name}: Captcha data extracted: " f"\n{json.dumps(captcha_data, indent=2)}"
                        # )

                        # # 通过 WaitForSecrets 发送验证码数据并等待用户手动验证
                        # from utils.wait_for_secrets import WaitForSecrets

                        # wait_for_secrets = WaitForSecrets()
                        # secret_obj = {
                        #     "CAPTCHA_NEXT_URL": {
                        #         "name": f"{self.account_name} - Aliyun Captcha Verification",
                        #         "description": (
                        #             f"Aliyun captcha verification required.\n"
                        #             f"TraceID: {captcha_data.get('traceid', 'N/A')}\n"
                        #             f"Current URL: {captcha_data.get('currentUrl', 'N/A')}\n"
                        #             f"Please complete the captcha manually in the browser, "
                        #             f"then provide the next URL after verification."
                        #         ),
                        #     }
                        # }

                        # secrets = wait_for_secrets.get(
                        #     secret_obj,
                        #     timeout=300,
                        #     notification={
                        #         "title": "阿里云验证",
                        #         "content": "请在浏览器中完成验证，并提供下一步的 URL。\n"
                        #         f"{json.dumps(captcha_data, indent=2)}\n"
                        #         "📋 操作说明：https://github.com/aceHubert/newapi-ai-check-in/docs/aliyun_captcha/README.md",
                        #     },
                        # )
                        # if not secrets or "CAPTCHA_NEXT_URL" not in secrets:
                        #     print(f"❌ {self.account_name}: No next URL provided " f"for captcha verification")
                        #     return None

                        # next_url = secrets["CAPTCHA_NEXT_URL"]
                        # print(f"🔄 {self.account_name}: Navigating to next URL " f"after captcha: {next_url}")

                        # # 导航到新的 URL
                        # await page.goto(next_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 再次检查是否还有 traceid
                        traceid_after = None
                        try:
                            traceid_after = await page.evaluate(
                                """() => {
                                const traceElement = document.getElementById('traceid');
                                if (traceElement) {
                                    const text = traceElement.innerText || traceElement.textContent;
                                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                                    return match ? match[1] : null;
                                }
                                return null;
                            }"""
                            )
                        except Exception:
                            traceid_after = None

                        if traceid_after:
                            print(
                                f"❌ {self.account_name}: 验证码验证失败，"
                                f"traceid 仍然存在：{traceid_after}"
                            )
                            return None

                        print(f"✅ {self.account_name}: 验证码验证成功，" f"traceid 已清除")

                    cookies = await browser.cookies()

                    aliyun_captcha_cookies = {}
                    print(f"ℹ️ {self.account_name}: 阿里云验证码 Cookie 列表")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (值：{cookie_value})")
                        # if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]
                        # and cookie_value is not None:
                        aliyun_captcha_cookies[cookie_name] = cookie_value

                    print(
                        f"ℹ️ {self.account_name}: "
                        f"第 1 步后获取到 {len(aliyun_captcha_cookies)} 个"
                        f"阿里云验证码 Cookie"
                    )

                    # 检查是否至少获取到一个 Aliyun Captcha cookie
                    if not aliyun_captcha_cookies:
                        print(f"❌ {self.account_name}: " f"未获取到阿里云验证码 Cookie")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(aliyun_captcha_cookies.keys())
                    print(f"✅ {self.account_name}: " f"成功获取阿里云验证码 Cookie: {cookie_names}")

                    return aliyun_captcha_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: " f"获取阿里云验证码 Cookie 时发生错误，{e}")
                    return None
                finally:
                    await page.close()

    async def get_status_with_browser(self) -> dict | None:
        """使用 Camoufox 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        print(
            f"ℹ️ {self.account_name}: 启动浏览器获取状态 (使用代理: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: 使用临时目录：{tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: 访问状态页从 localStorage 获取状态")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: 已从 localStorage 获取状态")
                        else:
                            print(f"⚠️ {self.account_name}: localStorage 中未找到状态")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: 从 localStorage 读取状态时发生错误：{e}")

                    return status_data

                except Exception as e:
                    print(f"❌ {self.account_name}: 获取状态时发生错误：{e}")
                    return None
                finally:
                    await page.close()

    async def get_auth_client_id(self, session: curl_requests.Session, headers: dict, provider: str) -> dict:
        """获取状态信息

        Args:
            session: curl_cffi Session 客户端
            headers: 请求头
            provider: 提供商类型 (github/linuxdo)

        Returns:
            包含 success 和 client_id 或 error 的字典
        """
        try:
            response = session.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response_resolve(response, f"get_auth_client_id_{provider}", self.account_name)
                if data is None:

                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting status from browser")
                    # try:
                    #     status_data = await self.get_status_with_browser()
                    #     if status_data:
                    #         oauth = status_data.get(f"{provider}_oauth", False)
                    #         if not oauth:
                    #             return {
                    #                 "success": False,
                    #                 "error": f"{provider} OAuth is not enabled.",
                    #             }

                    #         client_id = status_data.get(f"{provider}_client_id", "")
                    #         if client_id:
                    #             print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                    #             return {
                    #                 "success": True,
                    #                 "client_id": client_id,
                    #             }
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "获取 client id 失败：响应类型无效 (已保存到日志)",
                    }

                if data.get("success"):
                    status_data = data.get("data", {})
                    oauth = status_data.get(f"{provider}_oauth", False)
                    if not oauth:
                        return {
                            "success": False,
                            "error": f"{provider} OAuth 未启用。",
                        }

                    client_id = status_data.get(f"{provider}_client_id", "")
                    return {
                        "success": True,
                        "client_id": client_id,
                    }
                else:
                    error_msg = data.get("message", "未知错误")
                    return {
                        "success": False,
                        "error": f"获取 client id 失败：{error_msg}",
                    }
            return {
                "success": False,
                "error": f"获取 client id 失败：HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"获取 client id 失败，{e}",
            }

    async def get_auth_state_with_browser(self) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: 启动浏览器获取授权状态 (使用代理: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: 使用临时目录：{tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    # 1. Open the login page first
                    print(f"ℹ️ {self.account_name}: 打开登录页")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    # Wait for page to be fully loaded
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    response = await page.evaluate(
                        f"""async () => {{
                            try{{
                                const response = await fetch('{self.provider_config.get_auth_state_url()}');
                                const data = await response.json();
                                return data;
                            }}catch(e){{
                                return {{
                                    success: false,
                                    message: e.message
                                }};
                            }}
                        }}"""
                    )

                    if response and "data" in response:
                        cookies = await browser.cookies()
                        return {
                            "success": True,
                            "state": response.get("data"),
                            "cookies": cookies,
                        }

                    return {"success": False, "error": f"获取授权状态失败，\n{json.dumps(response, indent=2)}"}

                except Exception as e:
                    print(f"❌ {self.account_name}: 获取授权状态失败，{e}")
                    await take_screenshot(page, "auth_url_error", self.account_name)
                    return {"success": False, "error": "获取授权状态失败"}
                finally:
                    await page.close()

    async def get_auth_state(
        self,
        session: curl_requests.Session,
        headers: dict,
    ) -> dict:
        """获取认证状态
        
        使用 curl_cffi Session 发送请求。Session 可在创建时设置全局 impersonate。
        
        Args:
            session: curl_cffi Session 客户端（已包含 cookies，可能已设置 impersonate）
            headers: 请求头
        """
        try:
            response = session.get(
                self.provider_config.get_auth_state_url(),
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                json_data = response_resolve(response, "get_auth_state", self.account_name)
                if json_data is None:
                    return {
                        "success": False,
                        "error": "获取授权状态失败：响应类型无效 (已保存到日志)",
                    }

                # 检查响应是否成功
                if json_data.get("success"):
                    auth_data = json_data.get("data")

                    # 将 curl_cffi Cookies 转换为 Camoufox 格式
                    result_cookies = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc

                    print(f"ℹ️ {self.account_name}: 从授权状态请求中获取到 {len(response.cookies)} 个 Cookie")
                    for cookie in response.cookies.jar:
                        # 从 _rest 中获取 HttpOnly 和 SameSite，确保类型正确
                        http_only_raw = cookie._rest.get("HttpOnly", False)
                        http_only = bool(http_only_raw) if http_only_raw is not None else False
                        
                        same_site_raw = cookie._rest.get("SameSite", "Lax")
                        same_site = str(same_site_raw) if same_site_raw else "Lax"
                        
                        # secure 也需要确保是布尔值
                        secure = bool(cookie.secure) if cookie.secure is not None else False
                        
                        print(
                            f"  📚 Cookie: {cookie.name} (域名：{cookie.domain}，"
                            f"路径：{cookie.path}，过期时间：{cookie.expires}，"
                            f"HttpOnly: {http_only}，Secure: {secure}，"
                            f"SameSite: {same_site})"
                        )
                        # 构建 cookie 字典，Camoufox 要求字段类型严格
                        cookie_dict = {
                            "name": cookie.name,
                            "domain": cookie.domain if cookie.domain else parsed_domain,
                            "value": cookie.value,
                            "path": cookie.path if cookie.path else "/",
                            "secure": secure,
                            "httpOnly": http_only,
                            "sameSite": same_site,
                        }
                        # 只有当 expires 是有效的数值时才添加
                        if cookie.expires is not None:
                            cookie_dict["expires"] = float(cookie.expires)
                        result_cookies.append(cookie_dict)

                    return {
                        "success": True,
                        "state": auth_data,
                        "cookies": result_cookies,
                    }
                else:
                    error_msg = json_data.get("message", "未知错误")
                    return {
                        "success": False,
                        "error": f"获取授权状态失败：{error_msg}",
                    }
            return {
                "success": False,
                "error": f"获取授权状态失败：HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"获取授权状态失败，{e}",
            }

    async def get_user_info_with_browser(self, auth_cookies: list[dict]) -> dict:
        """使用 Camoufox 获取用户信息

        Returns:
            包含 success、quota、used_quota 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: 启动浏览器获取用户信息 (使用代理: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_user_info_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: 使用临时目录：{tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                browser.add_cookies(auth_cookies)

                try:
                    # 1. 打开登录页面
                    print(f"ℹ️ {self.account_name}: 打开主页")
                    await page.goto(self.provider_config.origin, wait_until="networkidle")

                    # 等待页面完全加载
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 获取用户信息
                    response = await page.evaluate(
                        f"""async () => {{
                           const response = await fetch(
                               '{self.provider_config.get_user_info_url()}'
                           );
                           const data = await response.json();
                           return data;
                        }}"""
                    )

                    if response and "data" in response:
                        user_data = response.get("data", {})
                        quota = round(user_data.get("quota", 0) / 500000, 2)
                        used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                        bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                        print(
                            f"✅ {self.account_name}: "
                            f"当前余额：${quota}，已用：${used_quota}，奖励：${bonus_quota}"
                        )
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"当前余额：${quota}，已用：${used_quota}，奖励：${bonus_quota}",
                        }

                    return {
                        "success": False,
                        "error": f"获取用户信息失败，\n{json.dumps(response, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: 获取用户信息失败，{e}")
                    await take_screenshot(page, "user_info_error", self.account_name)
                    return {"success": False, "error": "获取用户信息失败"}
                finally:
                    await page.close()

    async def get_user_info(self, session: curl_requests.Session, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = session.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_user_info", self.account_name)
                if json_data is None:
                    # 尝试从浏览器获取用户信息
                    # print(f"ℹ️ {self.account_name}: Getting user info from browser")
                    # try:
                    #     user_info_result = await self.get_user_info_with_browser()
                    #     if user_info_result.get("success"):
                    #         return user_info_result
                    #     else:
                    #         error_msg = user_info_result.get("error", "Unknown error")
                    #         print(f"⚠️ {self.account_name}: {error_msg}")
                    # except Exception as browser_err:
                    #     print(
                    #         f"⚠️ {self.account_name}: "
                    #         f"Failed to get user info from browser: {browser_err}"
                    #     )

                    return {
                        "success": False,
                        "error": "获取用户信息失败：响应类型无效 (已保存到日志)",
                    }

                if json_data.get("success"):
                    user_data = json_data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "bonus_quota": bonus_quota,
                        "display": f"当前余额：${quota}，已用：${used_quota}，奖励：${bonus_quota}",
                    }
                else:
                    error_msg = json_data.get("message", "未知错误")
                    return {
                        "success": False,
                        "error": f"获取用户信息失败：{error_msg}",
                    }
            return {
                "success": False,
                "error": f"获取用户信息失败：HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"获取用户信息失败，{e}",
            }

    def execute_check_in(
        self,
        session: curl_requests.Session,
        headers: dict,
        api_user: str | int,
    ) -> dict:
        """执行签到请求
        
        Returns:
            包含 success, message, data 等信息的字典
        """
        print(f"🌐 {self.account_name}: 正在执行签到")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        check_in_url = self.provider_config.get_check_in_url(api_user)
        if not check_in_url:
            print(f"❌ {self.account_name}: 未配置签到 URL")
            return {"success": False, "error": "未配置签到 URL"}

        response = session.post(check_in_url, headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: 响应状态码 {response.status_code}")

        # 尝试解析响应（200 或 400 都可能包含有效的 JSON）
        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_check_in", self.account_name)
            if json_data is None:
                # 如果不是 JSON 响应（可能是 HTML），检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: 签到成功！")
                    return {"success": True, "message": "签到成功"}
                else:
                    print(f"❌ {self.account_name}: 签到失败 - 响应格式无效")
                    return {"success": False, "error": "响应格式无效"}

            # 检查签到结果
            message = json_data.get("message", json_data.get("msg", ""))
            # 不同站点的"已签到"提示文案不同（已经签到 / 今日已签到 / 已簽到 / 请勿重复签到 / already 等），
            # 重复签到不算失败，一律视为成功
            already_signed_in = (
                any(keyword in message for keyword in ("已经签到", "已签到", "已簽到", "重复签到"))
                or "already" in message.lower()
            )

            if (
                json_data.get("ret") == 1
                or json_data.get("code") == 0
                or json_data.get("success")
                or "签到成功" in message
                or already_signed_in
            ):
                # 提取签到数据
                check_in_data = json_data.get("data", {})
                checkin_date = check_in_data.get("checkin_date", "")
                quota_awarded = check_in_data.get("quota_awarded", 0)

                if already_signed_in and not quota_awarded:
                    print(f"✅ {self.account_name}: {message}（无需重复签到）")
                elif quota_awarded:
                    quota_display = round(quota_awarded / 500000, 2)
                    print(f"✅ {self.account_name}: 签到成功！日期：{checkin_date}，奖励额度：${quota_display}")
                else:
                    print(f"✅ {self.account_name}: 签到成功！{message}")
                
                return {
                    "success": True,
                    "message": message or "签到成功",
                    "data": check_in_data,
                }
            else:
                error_msg = json_data.get("msg", json_data.get("message", "未知错误"))
                print(f"❌ {self.account_name}: 签到失败 - {error_msg}")
                return {"success": False, "error": error_msg}
        else:
            print(f"❌ {self.account_name}: 签到失败 - HTTP {response.status_code}")
            return {"success": False, "error": f"HTTP {response.status_code}"}

    async def execute_topup(
        self,
        headers: dict,
        cookies: dict,
        api_user: str | int,
        topup_interval: int = 60,
    ) -> dict:
        """执行完整的 CDK 获取和充值流程

        直接调用 get_cdk 生成器函数，每次 yield 一个 CDK 字符串并执行 topup
        每次 topup 之间保持间隔时间，如果 topup 失败则停止
        
        支持同步生成器和异步生成器两种类型的 get_cdk 函数

        Args:
            headers: 请求头
            cookies: cookies 字典
            api_user: API 用户 ID（通过参数传递，因为登录方式可能不同）
            topup_interval: 多次 topup 之间的间隔时间（秒），默认 60 秒

        Returns:
            包含 success, topup_count, errors 等信息的字典
        """
        # 检查是否配置了 get_cdk 函数
        if not self.provider_config.get_cdk:
            print(f"ℹ️ {self.account_name}: 提供商 {self.provider_config.name} 未配置 get_cdk 函数")
            return {
                "success": True,
                "topup_count": 0,
                "topup_success_count": 0,
                "error": "",
            }

        # 构建 topup 请求头
        topup_headers = headers.copy()
        topup_headers.update({
            "Referer": f"{self.provider_config.origin}/console/topup",
            "Origin": self.provider_config.origin,
            self.provider_config.api_user_key: f"{api_user}",
        })

        results = {
            "success": True,
            "topup_count": 0,
            "topup_success_count": 0,
            "error": "",
        }

        # 调用 get_cdk 函数，返回同步生成器或异步生成器
        cdk_generator = self.provider_config.get_cdk(self.account_config)
        
        topup_count = 0
        error_msg = ""

        # 内部函数：处理单个 CDK 结果
        async def process_cdk_result(success: bool, data: dict) -> bool:
            """处理单个 CDK 结果，返回是否应该继续
            
            Args:
                success: 是否成功获取 CDK
                data: 包含 code 或 error 的字典
                
            Returns:
                bool: True 继续处理下一个，False 停止处理
            """
            nonlocal topup_count, error_msg
            
            # 如果获取 CDK 失败，停止处理
            if not success:
                error_msg = data.get("error", "获取 CDK 失败")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: 获取 CDK 失败 - {error_msg}，停止充值流程")
                return False
            
            # 获取 code
            cdk = data.get("code", "")
            
            # 如果 code 为空，表示不需要充值，继续处理下一个
            if not cdk:
                print(f"ℹ️ {self.account_name}: 没有可充值的 CDK (code 为空)，继续...")
                return True
            
            # 如果不是第一个 CDK，等待间隔时间
            if topup_count > 0 and topup_interval > 0:
                print(f"⏳ {self.account_name}: 等待 {topup_interval} 秒后进行下一次充值...")
                await asyncio.sleep(topup_interval)

            topup_count += 1
            print(f"💰 {self.account_name}: 正在执行充值 #{topup_count}，CDK: {cdk}")

            topup_result = topup(
                provider_config=self.provider_config,
                account_config=self.account_config,
                headers=topup_headers,
                cookies=cookies,
                key=cdk,
            )

            results["topup_count"] += 1

            if topup_result.get("success"):
                results["topup_success_count"] += 1
                if not topup_result.get("already_used"):
                    print(f"✅ {self.account_name}: 充值 #{topup_count} 成功")
                return True  # 继续处理下一个
            else:
                # topup 失败，记录错误并停止
                error_msg = topup_result.get("error", "充值失败")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: 充值 #{topup_count} 失败，停止充值流程")
                return False  # 停止处理

        # 检查是否是异步生成器
        if inspect.isasyncgen(cdk_generator):
            # 异步生成器，使用 async for
            async for success, data in cdk_generator:
                should_continue = await process_cdk_result(success, data)
                if not should_continue:
                    break
        else:
            # 同步生成器，使用普通 for
            for success, data in cdk_generator:
                should_continue = await process_cdk_result(success, data)
                if not should_continue:
                    break

        if topup_count == 0:
            print(f"ℹ️ {self.account_name}: 没有可用的 CDK 进行充值")
        elif results["topup_success_count"] > 0:
            print(f"✅ {self.account_name}: 充值成功 {results['topup_success_count']}/{results['topup_count']} 次")

        return results

    async def check_in_with_cookies(
        self,
        cookies: dict,
        common_headers: dict,
        api_user: str | int,
        impersonate: str | None = None,
    ) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作
        
        Args:
            cookies: cookies 字典
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
            api_user: API 用户 ID
        """
        print(
            f"ℹ️ {self.account_name}: 使用现有 Cookie 执行签到 (使用代理: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值
        if not impersonate:
            user_agent = common_headers.get("User-Agent", "")
            impersonate = get_curl_cffi_impersonate(user_agent) if user_agent else "firefox135"
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: 使用 curl_cffi Session，impersonate={impersonate}")
        
        try:
            # 打印 cookies 的键和值
            print(f"ℹ️ {self.account_name}: 将使用以下 Cookie:")
            for key, value in cookies.items():
                print(f"  📚 {key}: {value[:50] if len(value) > 50 else value}{'...' if len(value) > 50 else ''}")
            session.cookies.update(cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = f"{api_user}"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 检查是否需要手动签到
            if self.provider_config.needs_manual_check_in():
                # 如果配置了签到状态查询，先检查是否已签到
                check_in_status_func = self.provider_config.get_check_in_status_func()
                if check_in_status_func:
                    checked_in_today = check_in_status_func(
                        provider_config=self.provider_config,
                        account_config=self.account_config,
                        cookies=cookies,
                        headers=headers,
                    )
                    if checked_in_today:
                        print(f"ℹ️ {self.account_name}: 今日已签到，跳过签到")
                    else:
                        # 未签到，执行签到
                        check_in_result = self.execute_check_in(session, headers, api_user)
                        if not check_in_result.get("success"):
                            return False, {"error": check_in_result.get("error", "签到失败")}
                        # 签到成功后再次查询状态（显示最新状态）
                        check_in_status_func(
                            provider_config=self.provider_config,
                            account_config=self.account_config,
                            cookies=cookies,
                            headers=headers,
                        )
                else:
                    # 没有配置签到状态查询函数，直接执行签到
                    check_in_result = self.execute_check_in(session, headers, api_user)
                    if not check_in_result.get("success"):
                        return False, {"error": check_in_result.get("error", "签到失败")}
            else:
                print(f"ℹ️ {self.account_name}: 签到已自动完成 (由用户信息请求触发)")

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: 提供商需要手动充值，正在执行...")
                topup_result = await self.execute_topup(headers, cookies, api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: 充值完成 - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} 次成功"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "充值失败"
                    print(f"❌ {self.account_name}: 充值失败，停止签到流程")
                    return False, {"error": error_msg}

            user_info = await self.get_user_info(session, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "已成功获取用户信息")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "未知错误")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "获取用户信息失败"}
            else:
                return False, {"error": "无用户信息"}

        except Exception as e:
            print(f"❌ {self.account_name}: 执行签到流程时发生错误 - {e}")
            return False, {"error": "执行签到流程时发生错误"}
        finally:
            session.close()

    async def check_in_with_system_access_token(
        self,
        access_token: str,
        bypass_cookies: dict,
        common_headers: dict,
        api_user: str | int,
    ) -> tuple[bool, dict]:
        """使用 system access token 执行签到操作
        
        Args:
            access_token: 系统访问令牌
            bypass_cookies: 绕过 cookies（WAF/CF）
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
            api_user: API 用户 ID
        """
        print(
            f"ℹ️ {self.account_name}: 使用系统访问令牌执行签到 (使用代理: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent) if user_agent else "firefox135"
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: 使用 curl_cffi Session，impersonate={impersonate}")
        
        try:
            # 设置 bypass cookies
            if bypass_cookies:
                session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers["Authorization"] = f"Bearer {access_token}"
            headers[self.provider_config.api_user_key] = f"{api_user}"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 检查是否需要手动签到
            if self.provider_config.needs_manual_check_in():
                # 如果配置了签到状态查询，先检查是否已签到
                check_in_status_func = self.provider_config.get_check_in_status_func()
                if check_in_status_func:
                    checked_in_today = check_in_status_func(
                        provider_config=self.provider_config,
                        account_config=self.account_config,
                        cookies=session.cookies.get_dict(),
                        headers=headers,
                    )
                    if checked_in_today:
                        print(f"ℹ️ {self.account_name}: 今日已签到，跳过签到")
                    else:
                        # 未签到，执行签到
                        check_in_result = self.execute_check_in(session, headers, api_user)
                        if not check_in_result.get("success"):
                            return False, {"error": check_in_result.get("error", "签到失败")}
                        # 签到成功后再次查询状态（显示最新状态）
                        check_in_status_func(
                            provider_config=self.provider_config,
                            account_config=self.account_config,
                            cookies=session.cookies.get_dict(),
                            headers=headers,
                        )
                else:
                    # 没有配置签到状态查询函数，直接执行签到
                    check_in_result = self.execute_check_in(session, headers, api_user)
                    if not check_in_result.get("success"):
                        return False, {"error": check_in_result.get("error", "签到失败")}
            else:
                print(f"ℹ️ {self.account_name}: 签到已自动完成 (由用户信息请求触发)")

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: 提供商需要手动充值，正在执行...")
                topup_result = await self.execute_topup(headers, session.cookies.get_dict(), api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: 充值完成 - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} 次成功"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "充值失败"
                    print(f"❌ {self.account_name}: 充值失败，停止签到流程")
                    return False, {"error": error_msg}

            user_info = await self.get_user_info(session, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "已成功获取用户信息")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "未知错误")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "获取用户信息失败"}
            else:
                return False, {"error": "无用户信息"}

        except Exception as e:
            print(f"❌ {self.account_name}: 执行签到流程时发生错误 - {e}")
            return False, {"error": f"执行签到流程时发生错误 - {e}"}
        finally:
            session.close()

    async def check_in_with_github(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作
        
        Args:
            username: GitHub 用户名
            password: GitHub 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: 使用 GitHub 账号执行签到 (使用代理: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值，在 Session 上设置全局 impersonate
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: 使用 curl_cffi Session，impersonate={impersonate}")
        
        try:
            session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: 使用配置中的 GitHub client ID")
            else:
                client_id_result = await self.get_auth_client_id(session, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: 已获取 GitHub client ID: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "未知错误")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "获取 GitHub client ID 失败"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                session=session,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: 已获取 GitHub 授权状态：{auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "未知错误")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "获取 GitHub 授权状态失败"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/github_{username_hash}_storage_state.json"

            # 优先复用站点会话缓存（避免每次运行都触发 GitHub 登录/2FA）
            cached_result = await self._try_cached_site_session(
                "github", username_hash, bypass_cookies, common_headers
            )
            if cached_result is not None:
                return cached_result

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            # 总超时兜底（同 LinuxDoSignIn，防止无超时挂起拖垮整个 run）
            try:
                success, result_data, oauth_browser_headers = await asyncio.wait_for(
                    github.signin(
                        client_id=client_id_result["client_id"],
                        auth_state=auth_state_result.get("state"),
                        auth_cookies=auth_state_result.get("cookies", []),
                        cache_file_path=cache_file_path,
                    ),
                    timeout=720,
                )
            except asyncio.TimeoutError:
                print(f"❌ {self.account_name}: GitHub 登录授权总超时（12 分钟），放弃本账号")
                return False, {"error": "GitHub 登录授权总超时"}

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 缓存站点会话，下次运行直接复用（免 GitHub 登录）
                self._save_site_session("github", username_hash, user_cookies, api_user, oauth_browser_headers)

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: 使用 OAuth 浏览器指纹更新 headers")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = self.merge_cookies(bypass_cookies, user_cookies)
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: 已收到 OAuth code，正在调用回调接口")

                # 构建带参数的回调 URL
                base_url = self.provider_config.get_github_auth_url()
                callback_url = f"{base_url}?{urlencode(result_data, doseq=True)}"
                print(f"ℹ️ {self.account_name}: 回调 URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 curl_cffi 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        session.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: 使用 OAuth 浏览器指纹更新 headers")
                        updated_headers.update(oauth_browser_headers)

                    response = session.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "github_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: 已从回调获取 api_user: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: 提取到 {len(user_cookies)} 个用户 Cookie: {list(user_cookies.keys())}"
                                )
                                # 缓存站点会话，下次运行直接复用（免 GitHub 登录）
                                self._save_site_session(
                                    "github", username_hash, user_cookies, api_user, oauth_browser_headers
                                )
                                merged_cookies = self.merge_cookies(bypass_cookies, user_cookies)
                                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
                            else:
                                print(f"❌ {self.account_name}: 回调响应中没有用户 ID")
                                return False, {"error": "OAuth 回调响应中没有用户 ID"}
                        else:
                            error_msg = json_data.get("message", "未知错误") if json_data else "响应无效"
                            print(f"❌ {self.account_name}: OAuth 回调失败：{error_msg}")
                            return False, {"error": f"OAuth 回调失败：{error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth 回调 HTTP {response.status_code}")
                        return False, {"error": f"OAuth 回调 HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: 调用 OAuth 回调时发生错误：{callback_err}")
                    return False, {"error": f"OAuth 回调错误：{callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: 执行签到流程时发生错误 - {e}")
            return False, {"error": "GitHub 签到流程错误"}
        finally:
            session.close()

    def get_linuxdo_proxy(self) -> dict | None:
        """获取访问 linux.do 专用的代理配置

        环境变量 LINUXDO_PROXY=true 时，访问 https://linux.do/ 使用全局 PROXY 配置的代理，
        用于绕过 linux.do 对 GitHub Actions 等数据中心 IP 的限流；
        未启用或未配置 PROXY 时返回 None（与站点访问代理一致）

        Returns:
            代理配置字典（Camoufox/Playwright 格式），未启用时返回 None
        """
        enabled = os.getenv("LINUXDO_PROXY", "").strip().lower() in ("true", "1", "yes")
        if not enabled:
            return None

        if self.global_proxy:
            print(f"ℹ️ {self.account_name}: 已启用 LINUXDO_PROXY，linux.do 将使用 PROXY 中的代理")
            return self.global_proxy

        print(f"⚠️ {self.account_name}: 已启用 LINUXDO_PROXY 但未配置 PROXY，已忽略")
        return None

    async def check_in_with_linuxdo(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: 使用 Linux.do 账号执行签到 (使用代理: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值，在 Session 上设置全局 impersonate
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: 使用 curl_cffi Session，impersonate={impersonate}")
        
        try:
            session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.linuxdo_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.linuxdo_client_id,
                }
                print(f"ℹ️ {self.account_name}: 使用配置中的 Linux.do client ID")
            else:
                client_id_result = await self.get_auth_client_id(session, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: 已获取 Linux.do client ID: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "未知错误")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "获取 Linux.do client ID 失败"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                session=session,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: 已获取 Linux.do 授权状态：{auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "未知错误")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "获取 Linux.do 授权状态失败"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/linuxdo_{username_hash}_storage_state.json"

            # 优先复用站点会话缓存（避免每次运行都触发 linux.do 登录）
            cached_result = await self._try_cached_site_session(
                "linuxdo", username_hash, bypass_cookies, common_headers
            )
            if cached_result is not None:
                return cached_result

            from sign_in_with_linuxdo import LinuxDoSignIn

            # linux.do 登录页支持 GitHub OAuth：复用全局 GitHub 账号
            # （linux.do 账号密码登录在数据中心/代理环境会被风控拦截，GitHub 登录稳定）
            github_account = self.github_accounts[0] if self.github_accounts else None

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
                proxy=self.get_linuxdo_proxy(),
                github_username=github_account.username if github_account else None,
                github_password=github_account.password if github_account else None,
                storage_state_dir=self.storage_state_dir,
            )

            # 总超时兜底：登录/授权流程内个别等待（质询 solver、页面操作）可能因浏览器
            # 假死无限挂起（实测有账号卡 63 分钟拖垮整个 run）。正常最长路径（含 2FA
            # wait-for-secrets 5 分钟）约 10 分钟，超时则放弃本账号继续下一个
            try:
                success, result_data, oauth_browser_headers = await asyncio.wait_for(
                    linuxdo.signin(
                        client_id=client_id_result["client_id"],
                        auth_state=auth_state_result["state"],
                        auth_cookies=auth_state_result.get("cookies", []),
                        cache_file_path=cache_file_path,
                    ),
                    timeout=720,
                )
            except asyncio.TimeoutError:
                print(f"❌ {self.account_name}: Linux.do 登录授权总超时（12 分钟），放弃本账号")
                return False, {"error": "Linux.do 登录授权总超时"}

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 缓存站点会话，下次运行直接复用（免 Linux.do 登录）
                self._save_site_session(
                    "linuxdo", username_hash, user_cookies, api_user, oauth_browser_headers
                )

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: 使用 OAuth 浏览器指纹更新 headers")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = self.merge_cookies(bypass_cookies, user_cookies)
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: 已收到 OAuth code，正在调用回调接口")

                # 构建带参数的回调 URL
                base_url = self.provider_config.get_linuxdo_auth_url()
                callback_url = f"{base_url}?{urlencode(result_data, doseq=True)}"
                print(f"ℹ️ {self.account_name}: 回调 URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 curl_cffi 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        session.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: 使用 OAuth 浏览器指纹更新 headers")
                        updated_headers.update(oauth_browser_headers)

                    # provider 服务端可能出现瞬时故障（如 failed to connect to Linux DO server，
                    # 即 newapi 服务器临时连不上 connect.linux.do），此时 OAuth code 尚未被消费，
                    # 重试同一回调有机会成功
                    json_data = None
                    for _cb_attempt in (1, 2, 3):
                        response = session.get(callback_url, headers=updated_headers, timeout=30)

                        if response.status_code != 200:
                            if 500 <= response.status_code < 600 and _cb_attempt < 3:
                                print(
                                    f"⚠️ {self.account_name}: 回调 HTTP {response.status_code}，"
                                    f"5 秒后重试（{_cb_attempt}/3）"
                                )
                                await asyncio.sleep(5)
                                continue
                            print(f"❌ {self.account_name}: OAuth 回调 HTTP {response.status_code}")
                            return False, {"error": f"OAuth 回调 HTTP {response.status_code}"}

                        json_data = response_resolve(response, "linuxdo_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            break

                        error_msg = json_data.get("message", "未知错误") if json_data else "响应无效"
                        if "failed to connect" in str(error_msg).lower() and _cb_attempt < 3:
                            print(
                                f"⚠️ {self.account_name}: 回调返回「{error_msg}」，"
                                f"5 秒后重试（{_cb_attempt}/3）"
                            )
                            await asyncio.sleep(5)
                            continue
                        print(f"❌ {self.account_name}: OAuth 回调失败：{error_msg}")
                        return False, {"error": f"OAuth 回调失败：{error_msg}"}

                    if not (json_data and json_data.get("success")):
                        print(f"❌ {self.account_name}: OAuth 回调重试均未成功")
                        return False, {"error": "OAuth 回调重试均未成功"}

                    user_data = json_data.get("data", {})
                    api_user = user_data.get("id")

                    if api_user:
                        print(f"✅ {self.account_name}: 已从回调获取 api_user: {api_user}")

                        # 提取 cookies
                        user_cookies = {}
                        for cookie in response.cookies.jar:
                            user_cookies[cookie.name] = cookie.value

                        print(
                            f"ℹ️ {self.account_name}: 提取到 {len(user_cookies)} 个用户 Cookie: {list(user_cookies.keys())}"
                        )
                        # 缓存站点会话，下次运行直接复用（免 Linux.do 登录）
                        self._save_site_session(
                            "linuxdo", username_hash, user_cookies, api_user, oauth_browser_headers
                        )
                        merged_cookies = self.merge_cookies(bypass_cookies, user_cookies)
                        return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
                    else:
                        print(f"❌ {self.account_name}: 回调响应中没有用户 ID")
                        return False, {"error": "OAuth 回调响应中没有用户 ID"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: 调用 OAuth 回调时发生错误：{callback_err}")
                    return False, {"error": f"OAuth 回调错误：{callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: 执行签到流程时发生错误 - {e}")
            return False, {"error": "Linux.do 签到流程错误"}
        finally:
            session.close()

    async def check_in_with_site(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
        mode: str = "auto",
    ) -> tuple[bool, dict]:
        """使用站点账号密码执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: 使用站点账号执行签到，mode={mode} (使用代理: {'true' if self.http_proxy_config else 'false'})"
        )

        if mode == "browser":
            return await self.check_in_with_site_browser(username, password, bypass_cookies, common_headers)

        success, result = await self.check_in_with_site_api(username, password, bypass_cookies, common_headers)
        if success or mode == "api":
            return success, result

        print(f"⚠️ {self.account_name}: 站点 API 登录失败，回退到浏览器登录")
        return await self.check_in_with_site_browser(username, password, bypass_cookies, common_headers)

    async def check_in_with_site_api(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用站点登录接口执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: 正在执行站点 API 登录 (使用代理: {'true' if self.http_proxy_config else 'false'})"
        )

        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)

        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: 使用 curl_cffi Session，impersonate={impersonate}")

        try:
            session.cookies.update(bypass_cookies)

            headers = common_headers.copy()
            headers["Content-Type"] = "application/json"
            headers["X-Requested-With"] = "XMLHttpRequest"
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            login_url = f"{self.provider_config.origin}/api/user/login?turnstile="
            payload = {"username": username, "password": password}
            response = session.post(login_url, headers=headers, json=payload, timeout=30)

            if response.status_code != 200:
                print(f"❌ {self.account_name}: 站点登录失败 - HTTP {response.status_code}")
                return False, {"error": f"站点登录 HTTP {response.status_code}"}

            json_data = response_resolve(response, "site_login", self.account_name)
            if json_data is None:
                return False, {"error": "站点登录返回无效响应"}

            if not json_data.get("success"):
                error_msg = json_data.get("message", "站点登录失败")
                print(f"❌ {self.account_name}: 站点登录失败 - {error_msg}")
                return False, {"error": error_msg}

            user_data = json_data.get("data", {})
            api_user = user_data.get("id")
            if api_user is None:
                print(f"❌ {self.account_name}: 站点登录响应中没有用户 ID")
                return False, {"error": "站点登录响应中没有用户 ID"}

            user_cookies = {}
            for cookie in session.cookies.jar:
                user_cookies[cookie.name] = cookie.value

            print(f"ℹ️ {self.account_name}: 提取到 {len(user_cookies)} 个站点登录 Cookie: {list(user_cookies.keys())}")

            merged_cookies = self.merge_cookies(bypass_cookies, user_cookies)
            return await self.check_in_with_cookies(merged_cookies, common_headers, api_user, impersonate)

        except Exception as e:
            print(f"❌ {self.account_name}: 执行站点登录流程时发生错误 - {e}")
            return False, {"error": "站点登录流程错误"}
        finally:
            session.close()

    async def _click_site_password_login_switch(self, page) -> bool:
        """切换到站点账号密码登录表单，尽量使用稳定选择器和文本匹配。"""
        selectors = [
            'button:has-text("使用 邮箱或用户名 登录")',
            'button:has-text("邮箱或用户名")',
            'button:has-text("用户名")',
            'button.semi-button:nth-child(4)',
        ]

        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element:
                    print(f"ℹ️ {self.account_name}: 通过选择器点击站点密码登录切换按钮：{selector}")
                    await element.click()
                    await page.wait_for_timeout(1000)
                    return True
            except Exception as e:
                print(f"⚠️ {self.account_name}: 密码登录切换选择器 {selector} 失败: {e}")

        try:
            clicked = await page.evaluate(
                """() => {
                    const candidates = Array.from(document.querySelectorAll('button'));
                    const button = candidates.find((item) => {
                        const text = (item.innerText || item.textContent || '').replace(/\s+/g, ' ').trim();
                        return text.includes('邮箱或用户名') || text.includes('用户名') || text.includes('密码登录');
                    });
                    if (button) {
                        button.click();
                        return true;
                    }
                    return false;
                }"""
            )
            if clicked:
                print(f"ℹ️ {self.account_name}: 通过文本扫描点击站点密码登录切换按钮")
                await page.wait_for_timeout(1000)
                return True
        except Exception as e:
            print(f"⚠️ {self.account_name}: 密码登录切换文本扫描失败: {e}")

        return False

    async def _fill_site_login_form(self, page, username: str, password: str) -> bool:
        """填写站点登录表单，使用 fill + 事件触发，兼容前端校验。"""
        username_selectors = [
            '#username',
            'input[name="username"]',
            'input[placeholder*="用户名"]',
            'input[placeholder*="邮箱"]',
            'input[type="text"]',
        ]
        password_selectors = [
            '#password',
            'input[name="password"]',
            'input[type="password"]',
        ]

        username_selector = None
        for selector in username_selectors:
            try:
                await page.wait_for_selector(selector, timeout=3000)
                username_selector = selector
                break
            except Exception:
                continue

        password_selector = None
        for selector in password_selectors:
            try:
                await page.wait_for_selector(selector, timeout=3000)
                password_selector = selector
                break
            except Exception:
                continue

        if not username_selector or not password_selector:
            print(f"❌ {self.account_name}: 未找到站点登录表单输入框")
            return False

        await page.fill(username_selector, username)
        await page.dispatch_event(username_selector, "input")
        await page.dispatch_event(username_selector, "change")
        await page.wait_for_timeout(500)

        await page.fill(password_selector, password)
        await page.dispatch_event(password_selector, "input")
        await page.dispatch_event(password_selector, "change")
        await page.wait_for_timeout(500)
        return True

    async def _submit_site_login_form(self, page) -> bool:
        """提交站点登录表单，优先使用表单内 submit 按钮。"""
        selectors = [
            'form button[type="submit"]',
            'button[type="submit"]:has-text("继续")',
            'button.semi-button-primary:has-text("继续")',
            'button.semi-button-primary',
        ]

        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element:
                    print(f"ℹ️ {self.account_name}: 通过选择器提交站点登录表单：{selector}")
                    await element.click()
                    return True
            except Exception as e:
                print(f"⚠️ {self.account_name}: 提交选择器 {selector} 失败: {e}")

        try:
            submitted = await page.evaluate(
                """() => {
                    const buttons = Array.from(document.querySelectorAll('button'));
                    const button = buttons.find((item) => {
                        const text = (item.innerText || item.textContent || '').replace(/\s+/g, ' ').trim();
                        return text.includes('继续') || text.includes('登录') || text.includes('登入');
                    });
                    if (button) {
                        button.click();
                        return true;
                    }
                    const form = document.querySelector('form');
                    if (form) {
                        form.requestSubmit ? form.requestSubmit() : form.submit();
                        return true;
                    }
                    return false;
                }"""
            )
            if submitted:
                print(f"ℹ️ {self.account_name}: 通过文本/表单扫描提交站点登录表单")
                return True
        except Exception as e:
            print(f"⚠️ {self.account_name}: 提交文本/表单扫描失败: {e}")

        return False

    async def _read_site_api_user_from_browser(self, page, cookies: dict, common_headers: dict) -> str | int | None:
        """从浏览器 localStorage 或 /api/user/self 获取用户 ID。"""
        try:
            user_data = await page.evaluate("() => localStorage.getItem('user')")
            if user_data:
                user_obj = json.loads(user_data)
                api_user = user_obj.get("id")
                if api_user is not None:
                    print(f"✅ {self.account_name}: 已从 localStorage 获取 api user: {api_user}")
                    return api_user
        except Exception as e:
            print(f"⚠️ {self.account_name}: 从 localStorage 读取用户时发生错误：{e}")

        session = None
        try:
            user_agent = common_headers.get("User-Agent", "")
            impersonate = get_curl_cffi_impersonate(user_agent)
            session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
            session.cookies.update(cookies)

            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.origin
            headers["Origin"] = self.provider_config.origin

            response = session.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)
            if response.status_code == 200:
                json_data = response_resolve(response, "site_user_self", self.account_name)
                if json_data and json_data.get("success"):
                    user_data = json_data.get("data", {})
                    api_user = user_data.get("id")
                    if api_user is not None:
                        print(f"✅ {self.account_name}: 已从用户信息 API 获取 api user: {api_user}")
                        return api_user
            print(f"⚠️ {self.account_name}: 无法从用户信息 API 获取 api user，HTTP {response.status_code}")
        except Exception as e:
            print(f"⚠️ {self.account_name}: 从用户信息 API 获取 api user 时发生错误：{e}")
        finally:
            if session:
                session.close()

        return None

    async def check_in_with_site_browser(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用浏览器打开登录页并完成站点账号密码登录。"""
        print(
            f"ℹ️ {self.account_name}: 正在执行站点浏览器登录 (使用代理: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        async with AsyncCamoufox(
            headless=False,
            humanize=True,
            locale="en-US",
            geoip=True if self.camoufox_proxy_config else False,
            proxy=self.camoufox_proxy_config,
            os="macos",
            config={
                "forceScopeAccess": True,
            },
        ) as browser:
            context = await browser.new_context()
            if bypass_cookies:
                parsed_origin = urlparse(self.provider_config.origin)
                await context.add_cookies([
                    {
                        "name": name,
                        "value": value,
                        "domain": parsed_origin.hostname,
                        "path": "/",
                        "secure": parsed_origin.scheme == "https",
                    }
                    for name, value in bypass_cookies.items()
                ])
                print(f"ℹ️ {self.account_name}: 浏览器登录前设置了 {len(bypass_cookies)} 个绕过 Cookie")

            page = await context.new_page()
            try:
                await page.goto(self.provider_config.get_login_url(), wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    await page.wait_for_timeout(3000)

                if self.provider_config.aliyun_captcha:
                    await aliyun_captcha_check(page, self.account_name)

                await self._click_site_password_login_switch(page)

                if not await self._fill_site_login_form(page, username, password):
                    await take_screenshot(page, "site_login_form_not_found", self.account_name)
                    return False, {"error": "未找到站点浏览器登录表单"}

                current_url = page.url
                if not await self._submit_site_login_form(page):
                    await take_screenshot(page, "site_login_submit_not_found", self.account_name)
                    return False, {"error": "未找到站点浏览器登录提交按钮"}

                try:
                    await page.wait_for_function('localStorage.getItem("user") !== null', timeout=15000)
                except Exception:
                    try:
                        await page.wait_for_url(lambda url: url != current_url, timeout=15000)
                    except Exception:
                        await page.wait_for_timeout(5000)

                restore_cookies = await context.cookies()
                user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)
                merged_cookies = self.merge_cookies(bypass_cookies, user_cookies)

                api_user = await self._read_site_api_user_from_browser(page, merged_cookies, common_headers)
                if api_user is None:
                    await take_screenshot(page, "site_browser_login_no_user_id", self.account_name)
                    return False, {"error": "站点浏览器登录成功但未找到用户 ID"}

                browser_headers = await get_browser_headers(page)
                updated_headers = common_headers.copy()
                if browser_headers:
                    print_browser_headers(self.account_name, browser_headers)
                    updated_headers.update(browser_headers)

                impersonate = get_curl_cffi_impersonate(updated_headers.get("User-Agent", ""))
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)

            except Exception as e:
                print(f"❌ {self.account_name}: 执行站点浏览器登录流程时发生错误 - {e}")
                await take_screenshot(page, "site_browser_login_error", self.account_name)
                return False, {"error": "站点浏览器登录流程错误"}
            finally:
                await page.close()
                await context.close()

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ 开始处理 {self.account_name}")

        bypass_cookies = {}
        browser_headers = None  # 浏览器指纹头部信息
        
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_browser()
            if waf_cookies:
                bypass_cookies = waf_cookies
                print(f"✅ {self.account_name}: 已获取 WAF Cookie")
            else:
                print(f"⚠️ {self.account_name}: 无法获取 WAF Cookie，将继续使用空 Cookie")

        elif self.provider_config.needs_cf_clearance():
            # 直接调用公共模块的 get_cf_clearance 函数
            try:
                cf_result = await get_cf_clearance(
                    url=self.provider_config.get_login_url(),
                    account_name=self.account_name,
                    proxy_config=self.camoufox_proxy_config,
                )
                
                if cf_result[0]:
                    bypass_cookies = cf_result[0]
                    print(f"✅ {self.account_name}: 已获取 Cloudflare Cookie")
                else:
                    print(f"⚠️ {self.account_name}: 无法获取 Cloudflare Cookie，将继续使用空 Cookie")

                # 因为 Cloudflare 验证需要一致的浏览器指纹
                if cf_result[1]:
                    browser_headers = cf_result[1]
                    print(f"✅ {self.account_name}: 已获取 Cloudflare 指纹 headers")
            except Exception as e:
                print(f"❌ {self.account_name}: 获取 cf_clearance Cookie 时发生错误：{e}")
                print(f"⚠️ {self.account_name}: 将继续使用空 Cookie")
        else:
            print(f"ℹ️ {self.account_name}: 无需绕过，直接使用用户 Cookie")

        # 生成公用请求头（只生成一次 User-Agent，整个签到流程保持一致）
        # 注意：Referer 和 Origin 不在这里设置，由各个签到方法根据实际请求动态设置
        if browser_headers:
            # 如果有浏览器指纹头部（来自 cf_clearance 获取），使用它
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": browser_headers.get("User-Agent", get_random_user_agent()),
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            
            # 只有当 browser_headers 中包含 sec-ch-ua 时才添加 Client Hints 头部
            # Firefox 浏览器不支持 Client Hints，所以 browser_headers 中不会有这些头部
            # 如果强行添加会导致 Cloudflare 检测到指纹不一致而返回 403
            if "sec-ch-ua" in browser_headers:
                common_headers.update({
                    "sec-ch-ua": browser_headers.get("sec-ch-ua", ""),
                    "sec-ch-ua-mobile": browser_headers.get("sec-ch-ua-mobile", "?0"),
                    "sec-ch-ua-platform": browser_headers.get("sec-ch-ua-platform", ""),
                    "sec-ch-ua-platform-version": browser_headers.get("sec-ch-ua-platform-version", ""),
                    "sec-ch-ua-arch": browser_headers.get("sec-ch-ua-arch", ""),
                    "sec-ch-ua-bitness": browser_headers.get("sec-ch-ua-bitness", ""),
                    "sec-ch-ua-full-version": browser_headers.get("sec-ch-ua-full-version", ""),
                    "sec-ch-ua-full-version-list": browser_headers.get("sec-ch-ua-full-version-list", ""),
                    "sec-ch-ua-model": browser_headers.get("sec-ch-ua-model", '""'),
                })
                print(f"ℹ️ {self.account_name}: 使用浏览器指纹 headers (包含 Client Hints)")
            else:
                print(f"ℹ️ {self.account_name}: 使用浏览器指纹 headers (Firefox，无 Client Hints)")
        else:
            # 没有浏览器指纹，生成一次随机 User-Agent 并在整个流程中使用
            random_ua = get_random_user_agent()
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": random_ua,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            print(f"ℹ️ {self.account_name}: 使用随机 User-Agent (仅生成一次)")

        # 解析账号配置
        cookies_data = self.account_config.cookies
        system_access_token_data = self.account_config.system_access_token
        github_accounts = self.account_config.github  # 现在是 List[OAuthAccountConfig] 类型
        linuxdo_accounts = self.account_config.linux_do  # 现在是 List[OAuthAccountConfig] 类型
        site_accounts = self.account_config.site
        results = []

        # 尝试 cookies 认证
        if cookies_data:
            print(f"\nℹ️ {self.account_name}: 正在尝试 Cookie 认证")
            try:
                user_cookies = parse_cookies(cookies_data)
                if not user_cookies:
                    print(f"❌ {self.account_name}: Cookie 格式无效")
                    results.append(("cookies", False, {"error": "Cookie 格式无效"}))
                else:
                    api_user = self.account_config.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: 未找到 Cookie 认证所需的 API 用户标识")
                        results.append(("cookies", False, {"error": "未找到 API 用户标识"}))
                    else:
                        # 使用已有 cookies 执行签到，传入公用请求头
                        all_cookies = {**bypass_cookies, **user_cookies}
                        success, user_info = await self.check_in_with_cookies(all_cookies, common_headers, api_user)
                        if success:
                            print(f"✅ {self.account_name}: Cookie 认证成功")
                            results.append(("cookies", True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Cookie 认证失败")
                            results.append(("cookies", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Cookie 认证发生错误：{e}")
                results.append(("cookies", False, {"error": str(e)}))

        # 尝试 system access token 认证
        if system_access_token_data:
            print(f"\nℹ️ {self.account_name}: 正在尝试系统访问令牌认证")
            try:
                api_user = self.account_config.api_user
                if not api_user:
                    print(f"❌ {self.account_name}: 未找到系统访问令牌所需的 API 用户标识")
                    results.append(("system_access_token", False, {"error": "未找到 API 用户标识"}))
                else:
                    # 使用 system access token 执行签到，传入公用请求头
                    success, user_info = await self.check_in_with_system_access_token(
                        system_access_token_data, bypass_cookies, common_headers, api_user
                    )
                    if success:
                        print(f"✅ {self.account_name}: 系统访问令牌认证成功")
                        results.append(("system_access_token", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: 系统访问令牌认证失败")
                        results.append(("system_access_token", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: 系统访问令牌认证发生错误：{e}")
                results.append(("system_access_token", False, {"error": str(e)}))

        # 尝试 GitHub 认证（支持多个账号）
        if github_accounts:
            for idx, github_account in enumerate(github_accounts):
                account_label = f"github[{idx}]" if len(github_accounts) > 1 else "github"
                print(f"\nℹ️ {self.account_name}: 正在尝试 GitHub 认证 ({mask_username(github_account.username)})")
                try:
                    username = github_account.username
                    password = github_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: GitHub 账号信息不完整")
                        results.append((account_label, False, {"error": "GitHub 账号信息不完整"}))
                    else:
                        # 使用 GitHub 账号执行签到，传入公用请求头
                        success, user_info = await self.check_in_with_github(
                            username, password, bypass_cookies, common_headers
                        )
                        if success:
                            print(f"✅ {self.account_name}: GitHub 认证成功 ({mask_username(github_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: GitHub 认证失败 ({mask_username(github_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: GitHub 认证发生错误 ({mask_username(github_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        if site_accounts:
            for idx, site_account in enumerate(site_accounts):
                account_label = f"site[{idx}]" if len(site_accounts) > 1 else "site"
                print(f"\nℹ️ {self.account_name}: 正在尝试站点认证 ({mask_username(site_account.username)})")
                try:
                    username = site_account.username
                    password = site_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: 站点账号信息不完整")
                        results.append((account_label, False, {"error": "站点账号信息不完整"}))
                    else:
                        success, user_info = await self.check_in_with_site(
                            username,
                            password,
                            bypass_cookies,
                            common_headers,
                            site_account.mode,
                        )
                        if success:
                            print(f"✅ {self.account_name}: 站点认证成功 ({mask_username(site_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: 站点认证失败 ({mask_username(site_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: 站点认证发生错误 ({mask_username(site_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        # 尝试 Linux.do 认证（支持多个账号）
        if linuxdo_accounts:
            for idx, linuxdo_account in enumerate(linuxdo_accounts):
                account_label = f"linux.do[{idx}]" if len(linuxdo_accounts) > 1 else "linux.do"
                print(f"\nℹ️ {self.account_name}: 正在尝试 Linux.do 认证 ({mask_username(linuxdo_account.username)})")
                try:
                    username = linuxdo_account.username
                    password = linuxdo_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Linux.do 账号信息不完整")
                        results.append((account_label, False, {"error": "Linux.do 账号信息不完整"}))
                    else:
                        # 使用 Linux.do 账号执行签到，传入公用请求头
                        success, user_info = await self.check_in_with_linuxdo(
                            username,
                            password,
                            bypass_cookies,
                            common_headers,
                        )
                        if success:
                            print(f"✅ {self.account_name}: Linux.do 认证成功 ({mask_username(linuxdo_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Linux.do 认证失败 ({mask_username(linuxdo_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: Linux.do 认证发生错误 ({mask_username(linuxdo_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        if not results:
            print(f"❌ {self.account_name}: 配置中未找到有效的认证方式")
            return []

        # 输出最终结果
        print(f"\n📋 {self.account_name} 认证结果：")
        successful_count = 0
        for auth_method, success, user_info in results:
            status = "✅" if success else "❌"
            print(f"  {status} {auth_method} 认证")
            if success:
                successful_count += 1

        print(f"\n🎯 {self.account_name}: {successful_count}/{len(results)} 种认证方式成功")

        return results

   
