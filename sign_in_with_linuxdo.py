#!/usr/bin/env python3
"""
使用 Camoufox 绕过 Cloudflare 验证执行 Linux.do 签到
"""

import json
import os
from urllib.parse import urlparse, parse_qs
from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType
from utils.browser_utils import filter_cookies, take_screenshot, save_page_content_to_file
from utils.config import ProviderConfig
from utils.get_headers import get_browser_headers, print_browser_headers
from utils.proxy_bridge import get_browser_proxy
from utils.storage_state import ensure_storage_state_from_env

STORAGE_STATE_ENV_NAME = "STORATE_STATES_LINUXDO"


class LinuxDoSignIn:
    """使用 Linux.do 登录授权类"""

    def __init__(
        self,
        account_name: str,
        provider_config: ProviderConfig,
        username: str,
        password: str,
        proxy: dict | None = None,
    ):
        """初始化

        Args:
            account_name: 账号名称
            provider_config: 提供商配置
            username: Linux.do 用户名
            password: Linux.do 密码
            proxy: 访问 linux.do 使用的代理配置（Camoufox/Playwright 格式），为 None 时直连
        """
        self.account_name = account_name
        self.provider_config = provider_config
        self.username = username
        self.password = password
        self.proxy = proxy

    async def signin(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
    ) -> tuple[bool, dict, dict | None]:
        """使用 Linux.do 账号执行登录授权

        Args:
            client_id: OAuth 客户端 ID
            auth_state: OAuth 认证状态
            auth_cookies: OAuth 认证 cookies
            cache_file_path: 缓存文件

        Returns:
            (成功标志, 用户信息字典, 浏览器指纹头部信息或None)
            - 浏览器指纹头部信息仅在检测到 Cloudflare 验证页面时返回
        """
        print(f"ℹ️ {self.account_name}: 开始使用 Linux.do 登录")
        print(
            f"ℹ️ {self.account_name}: 使用 client_id: {client_id}，auth_state: {auth_state}，缓存文件: {cache_file_path}"
        )

        # 使用 Camoufox 启动浏览器（LINUXDO_PROXY 启用时通过代理访问 linux.do）
        # 浏览器（Camoufox/Playwright）不支持带认证的 SOCKS5，自动经本地桥接转换为 HTTP 代理
        browser_proxy = get_browser_proxy(self.proxy, self.account_name)
        print(f"ℹ️ {self.account_name}: 正在访问 linux.do（使用代理: {'true' if browser_proxy else 'false'}）")
        async with AsyncCamoufox(
            # persistent_context=True,
            # user_data_dir=tmp_dir,
            headless=False,
            humanize=True,
            locale="en-US",
            os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            geoip=True if browser_proxy else False,
            proxy=browser_proxy,
            config={
                "forceScopeAccess": True,
            },
        ) as browser:
            ensure_storage_state_from_env(
                    cache_file_path,
                    self.account_name,
                    self.username,
                    env_name=STORAGE_STATE_ENV_NAME,
            )
            
            # 只有在缓存文件存在时才加载 storage_state
            storage_state = cache_file_path if os.path.exists(cache_file_path) else None
            if storage_state:
                print(f"ℹ️ {self.account_name}: 找到缓存文件，恢复会话缓存")
            else:
                print(f"ℹ️ {self.account_name}: 未找到缓存文件，将全新开始")

            context = await browser.new_context(storage_state=storage_state)

            # 设置从参数获取的 auth cookies 到页面上下文
            if auth_cookies:
                await context.add_cookies(auth_cookies)
                print(f"ℹ️ {self.account_name}: 已设置 {len(auth_cookies)} 个来自提供商的认证 Cookie")
            else:
                print(f"ℹ️ {self.account_name}: 无需设置的认证 Cookie")

            page = await context.new_page()

            async with ClickSolver(
                framework=FrameworkType.CAMOUFOX, page=page, max_attempts=5, attempt_delay=3
            ) as solver:

                try:
                    # 检查是否已经登录（通过缓存恢复）
                    is_logged_in = False
                    oauth_url = (
                        f"https://connect.linux.do/oauth2/authorize?"
                        f"response_type=code&client_id={client_id}&state={auth_state}"
                    )

                    if os.path.exists(cache_file_path):
                        try:
                            print(f"ℹ️ {self.account_name}: 正在检查 {oauth_url} 的登录状态")
                            # 直接访问授权页面检查是否已登录
                            response = await page.goto(oauth_url, wait_until="domcontentloaded")
                            print(
                                f"ℹ️ {self.account_name}: 已重定向到应用页面 {response.url if response else '无'}"
                            )
                            await save_page_content_to_file(page, "sign_in_check", self.account_name, prefix="linuxdo")

                            # 登录后可能直接跳转回应用页面
                            if response and response.url.startswith(self.provider_config.origin):
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: 已通过缓存登录，继续进行授权"
                                )
                            else:
                                # 检查是否出现授权按钮（表示已登录）
                                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                                if allow_btn:
                                    is_logged_in = True
                                    print(
                                        f"✅ {self.account_name}: 已通过缓存登录，继续进行授权"
                                    )
                                else:
                                    print(f"ℹ️ {self.account_name}: 缓存会话已过期，需要重新登录")
                        except Exception as e:
                            print(
                                f"⚠️ {self.account_name}: 检查登录状态失败: {e}\n"
                                f"当前页面: {page.url}"
                            )

                    # 如果未登录，则执行登录流程
                    if not is_logged_in:
                        run_login_manual = os.getenv('RUN_LINUXDO_LOGIN_MANUAL')
                        print(f"ℹ️ {self.account_name}: 手动登录环境变量为 {run_login_manual}")
                        if run_login_manual != 'true':
                            print(
                                f"❌ {self.account_name}: 登录失败\n"
                                f"当前页面: {page.url}"
                            )
                            await take_screenshot(page, "logged_in_failed", self.account_name)
                            return False, {"error": "Linux.do 登录失败"}, None
                        
                        try:
                            print(f"ℹ️ {self.account_name}: 开始登录 linux.do")

                            await page.goto("https://linux.do/login", wait_until="domcontentloaded")

                            # 检查是否在 Cloudflare 验证页面
                            page_title = await page.title()
                            page_content = await page.content()

                            if "Just a moment" in page_title or "Checking your browser" in page_content:
                                print(f"ℹ️ {self.account_name}: 检测到 Cloudflare 验证，正在自动解决...")
                                try:
                                    await solver.solve_captcha(
                                        captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL
                                    )
                                    print(f"✅ {self.account_name}: Cloudflare 验证已自动解决")
                                    await page.wait_for_timeout(10000)
                                except Exception as solve_err:
                                    print(f"⚠️ {self.account_name}: 自动解决失败: {solve_err}")

                            # 等待登录表单可见（新登录页为 Ember 异步水合，需等表单交互就绪）
                            try:
                                await page.wait_for_selector("#login-button", state="visible", timeout=15000)
                            except Exception:
                                print(f"⚠️ {self.account_name}: 等待登录按钮超时，继续尝试")

                            # 监听登录接口响应，用于诊断登录失败的具体原因
                            login_api_responses = []

                            def _capture_login_response(response):
                                try:
                                    if "/session" in response.url and response.request.method == "POST":
                                        login_api_responses.append(response)
                                except Exception:
                                    pass

                            page.on("response", _capture_login_response)

                            await page.fill("#login-account-name", self.username)
                            await page.wait_for_timeout(2000)
                            await page.fill("#login-account-password", self.password)
                            await page.wait_for_timeout(2000)

                            # 页面异步水合可能重置已填写的表单，点击前校验一次
                            for _selector, _value in (
                                ("#login-account-name", self.username),
                                ("#login-account-password", self.password),
                            ):
                                try:
                                    if (await page.input_value(_selector)) != _value:
                                        print(f"⚠️ {self.account_name}: 表单字段被页面重置，重新填写 {_selector}")
                                        await page.fill(_selector, _value)
                                except Exception:
                                    pass

                            # 新登录页提交需要 Cloudflare Turnstile 令牌，网络慢时其脚本加载较久，
                            # 必须等令牌就绪再点击登录，否则提交会被静默拦截
                            try:
                                await page.wait_for_function(
                                    """() => {
                                        const el = document.querySelector('input[name="cf-turnstile-response"]');
                                        return el && el.value && el.value.length > 10;
                                    }""",
                                    timeout=30000,
                                )
                                print(f"ℹ️ {self.account_name}: Turnstile 令牌已就绪")
                            except Exception:
                                print(f"⚠️ {self.account_name}: 等待 Turnstile 令牌超时，继续尝试提交")

                            await page.click("#login-button")

                            # 等待登录结果：跳转离开 /login，或登录接口返回响应
                            for _ in range(30):
                                if "/login" not in page.url or login_api_responses:
                                    break
                                await page.wait_for_timeout(1000)

                            for _resp in login_api_responses:
                                try:
                                    _body = await _resp.json()
                                    _msg = _body.get("message") or _body.get("error") or ""
                                    _ok = _body.get("success") or _body.get("ret") == 1
                                    if _resp.status == 200 and _ok:
                                        print(f"✅ {self.account_name}: 登录接口返回成功 ({_resp.status})")
                                    else:
                                        try:
                                            detail = _msg or (await _resp.text())[:200]
                                        except Exception:
                                            detail = _msg
                                        print(
                                            f"❌ {self.account_name}: 登录接口返回失败 "
                                            f"HTTP {_resp.status}：{detail}"
                                        )
                                except Exception:
                                    print(f"⚠️ {self.account_name}: 登录接口响应无法解析 (HTTP {_resp.status})")
                            if not login_api_responses:
                                print(f"⚠️ {self.account_name}: 未捕获到登录接口请求，页面 URL: {page.url}")
                            page.remove_listener("response", _capture_login_response)

                            await page.wait_for_timeout(10000)

                            await save_page_content_to_file(page, "sign_in_result", self.account_name, prefix="linuxdo")

                            try:
                                current_url = page.url
                                print(f"ℹ️ {self.account_name}: 当前页面 URL 为 {current_url}")
                                if "linux.do/challenge" in current_url:
                                    print(
                                        f"⚠️ {self.account_name}: 检测到 Cloudflare 验证，"
                                        "Camoufox 应会自动绕过，等待中..."
                                    )
                                    # 等待 Cloudflare 验证完成
                                    await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=60000)
                                    print(f"✅ {self.account_name}: 成功绕过 Cloudflare 验证")

                            except Exception as e:
                                print(f"⚠️ {self.account_name}: 可能存在 Cloudflare 验证: {e}")
                                # 即使超时，也尝试继续
                                pass

                            # 保存新的会话状态
                            await context.storage_state(path=cache_file_path)
                            print(f"✅ {self.account_name}: 会话缓存已保存到缓存文件")

                        except Exception as e:
                            print(f"❌ {self.account_name}: 登录 linux.do 时发生错误: {e}")
                            await take_screenshot(page, "signin_bypass_error", self.account_name)
                            return False, {"error": "Linux.do 登录出错"}, None

                        # 登录后访问授权页面
                        try:
                            print(f"ℹ️ {self.account_name}: 正在前往授权页面: {oauth_url}")
                            await page.goto(oauth_url, wait_until="domcontentloaded")
                        except Exception as e:
                            print(f"❌ {self.account_name}: 跳转到授权页面失败: {e}")
                            await take_screenshot(page, "auth_page_navigation_failed_bypass", self.account_name)
                            return False, {"error": "Linux.do 授权页面跳转失败"}, None

                    try:
                        # 等待授权按钮出现，最多等待30秒
                        print(f"ℹ️ {self.account_name}: 正在等待授权按钮...")
                        await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                        allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')

                        if allow_btn_ele:
                            print(f"✅ {self.account_name}: 已找到授权按钮，继续进行授权")
                            await allow_btn_ele.click()

                            # 在等待重定向之前，先检查是否遇到 Cloudflare 挑战
                            try:
                                print(f"ℹ️ {self.account_name}: 正在检查授权后是否出现 Cloudflare 验证...")
                                await page.wait_for_timeout(3000)  # 等待页面响应

                                page_title = await page.title()
                                page_content = await page.content()
                                current_url = page.url

                                # 检查 URL 中是否包含 Cloudflare 挑战参数或页面内容
                                if "__cf_chl_rt_tk" in current_url or "Just a moment" in page_title or "Checking your browser" in page_content:
                                    cloudflare_challenge_detected = True
                                    print(f"ℹ️ {self.account_name}: 重定向前检测到 Cloudflare 验证，正在自动解决...")
                                    try:
                                        await solver.solve_captcha(
                                            captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL
                                        )
                                        print(f"✅ {self.account_name}: Cloudflare 验证已自动解决")
                                        await page.wait_for_timeout(5000)
                                    except Exception as solve_err:
                                        print(f"⚠️ {self.account_name}: 自动解决失败: {solve_err}")
                                else:
                                    print(f"ℹ️ {self.account_name}: 未检测到 Cloudflare 验证，继续重定向")
                                    
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: 检查 Cloudflare 验证时出错: {e}")
                        else:
                            print(f"❌ {self.account_name}: 未找到授权按钮")
                            await take_screenshot(page, "approve_button_not_found_bypass", self.account_name)
                            return False, {"error": "Linux.do 未找到授权按钮"}, None
                    except Exception as e:
                        print(
                            f"❌ {self.account_name}: 授权过程中发生错误: {e}\n"
                            f"当前页面: {page.url}"
                        )
                        await take_screenshot(page, "authorization_failed_bypass", self.account_name)
                        return False, {"error": "Linux.do 授权失败"}, None

                    # 统一处理授权逻辑（无论是否通过缓存登录）
                    # 标记是否检测到 Cloudflare 验证页面
                    cloudflare_challenge_detected = False

                    try:                  
                        # 先检查是否已跳转到 /console/token（Cloudflare 挑战等待期间可能已完成跳转）
                        console_token_pattern = f"**{self.provider_config.origin}/console/token**"
                        try:
                            await page.wait_for_url(console_token_pattern, timeout=3000)
                            print(f"ℹ️ {self.account_name}: 已重定向到 /console/token，跳过 redirect_pattern 等待")
                        except Exception:
                            # 未跳转到 /console/token，使用配置的 redirect_pattern 等待
                            redirect_pattern = self.provider_config.get_linuxdo_auth_redirect_pattern()
                            print(f"ℹ️ {self.account_name}: 正在等待重定向到: {redirect_pattern}")
                            await page.wait_for_url(redirect_pattern, timeout=30000)
                            await page.wait_for_timeout(5000)

                        # 检查是否在 Cloudflare 验证页面
                        page_title = await page.title()
                        page_content = await page.content()

                        if "Just a moment" in page_title or "Checking your browser" in page_content:
                            cloudflare_challenge_detected = True
                            print(f"ℹ️ {self.account_name}: 检测到 Cloudflare 验证，正在自动解决...")
                            try:
                                await solver.solve_captcha(
                                    captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL
                                )
                                print(f"✅ {self.account_name}: Cloudflare 验证已自动解决")
                                await page.wait_for_timeout(10000)
                            except Exception as solve_err:
                                print(f"⚠️ {self.account_name}: 自动解决失败: {solve_err}")
                    except Exception as e:
                        # 检查 URL 中是否包含 code 参数，如果包含则视为正常（OAuth 回调成功）
                        if "code=" in page.url:
                            print(f"ℹ️ {self.account_name}: 重定向超时但在 URL 中找到 OAuth code，继续执行...")
                        else:
                            print(
                                f"❌ {self.account_name}: 重定向过程中发生错误: {e}\n"
                                f"当前页面: {page.url}"
                            )
                            await take_screenshot(page, "linuxdo_authorization_failed", self.account_name)

                    # 从 localStorage 获取 user 对象并提取 id
                    api_user = None
                    current_url = page.url
                    try:
                        try:
                            await page.wait_for_function('localStorage.getItem("user") !== null', timeout=10000)
                        except Exception:
                            await page.wait_for_timeout(5000)

                        user_data = await page.evaluate("() => localStorage.getItem('user')")
                        if user_data:
                            user_obj = json.loads(user_data)
                            api_user = user_obj.get("id")
                            if api_user:
                                print(f"✅ {self.account_name}: 获取到 api_user: {api_user}")
                            else:
                                print(f"⚠️ {self.account_name}: 在 localStorage 中未找到用户 ID")
                        else:
                            print(f"⚠️ {self.account_name}: 在 localStorage 中未找到用户数据")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: 从 localStorage 读取用户信息时出错: {e}")

                    if api_user:
                        print(f"✅ {self.account_name}: OAuth 授权成功")

                        # 提取 session cookie，只保留与 provider domain 匹配的
                        restore_cookies = await page.context.cookies()
                        user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)

                        result = {"cookies": user_cookies, "api_user": api_user}

                        # 只有当检测到 Cloudflare 验证页面时，才获取并返回浏览器指纹头部信息
                        browser_headers = None
                        if cloudflare_challenge_detected:
                            browser_headers = await get_browser_headers(page)
                            print_browser_headers(self.account_name, browser_headers)
                            print(
                                f"ℹ️ {self.account_name}: 已返回浏览器指纹头部（检测到 Cloudflare 验证）"
                            )
                        else:
                            print(
                                f"ℹ️ {self.account_name}: 未返回浏览器指纹头部（未检测到 Cloudflare 验证）"
                            )

                        return True, result, browser_headers
                    else:
                        print(f"⚠️ {self.account_name}: 已收到 OAuth 回调但未找到用户 ID")
                        await take_screenshot(page, "oauth_failed_no_user_id_bypass", self.account_name)
                        parsed_url = urlparse(current_url)
                        query_params = parse_qs(parsed_url.query)

                        # 如果 query 中包含 code，说明 OAuth 回调成功
                        if "code" in query_params:
                            print(f"✅ {self.account_name}: 已收到 OAuth code: {query_params.get('code')}")
                            # 只有当检测到 Cloudflare 验证页面时，才获取并返回浏览器指纹头部信息
                            browser_headers = None
                            if cloudflare_challenge_detected:
                                browser_headers = await get_browser_headers(page)
                                print_browser_headers(self.account_name, browser_headers)
                                print(
                                    f"ℹ️ {self.account_name}: 已返回浏览器指纹头部（检测到 Cloudflare 验证）"
                                )
                            else:
                                print(
                                    f"ℹ️ {self.account_name}: 未返回浏览器指纹头部（未检测到 Cloudflare 验证）"
                                )
                            return True, query_params, browser_headers
                        else:
                            print(
                                f"❌ {self.account_name}: OAuth 失败，回调中无 code\n"
                                f"解析的 URL 为: {current_url}"
                            )
                            return (
                                False,
                                {
                                    "error": "Linux.do OAuth 失败 - 回调中无 code",
                                },
                                None,
                            )

                except Exception as e:
                    print(f"❌ {self.account_name}: 处理 linux.do 页面时发生错误: {e}")
                    await take_screenshot(page, "page_navigation_error_bypass", self.account_name)
                    return False, {"error": "Linux.do 页面跳转出错"}, None
                finally:
                    await page.close()
                    await context.close()
