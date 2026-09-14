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
        print(f"ℹ️ {self.account_name}: 正在访问 linux.do（使用代理: {'true' if self.proxy else 'false'}）")
        async with AsyncCamoufox(
            # persistent_context=True,
            # user_data_dir=tmp_dir,
            headless=False,
            humanize=True,
            locale="en-US",
            os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            geoip=False,  # geoip 查询经代理易超时且慢代理下指纹生成不稳定，固定指纹更可靠
            proxy=self.proxy,
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

                            # 授权流程是多级重定向链（authorize -> sso_provider -> sso_callback -> 应用页），
                            # domcontentloaded 可能停在中间页。等待跳转链完成（URL 稳定 2 秒）
                            async def _wait_redirect_settle(max_wait_s: int = 20) -> None:
                                last_url, stable = page.url, 0
                                for _ in range(max_wait_s * 2):
                                    await page.wait_for_timeout(500)
                                    if page.url == last_url:
                                        stable += 1
                                        if stable >= 4:  # 2 秒无变化视为稳定
                                            return
                                    else:
                                        last_url, stable = page.url, 0

                            await _wait_redirect_settle(20)
                            final_url = page.url
                            if final_url != (response.url if response else ""):
                                print(f"ℹ️ {self.account_name}: 重定向链完成后页面为 {final_url}")
                            await save_page_content_to_file(page, "sign_in_check", self.account_name, prefix="linuxdo")

                            # 登录后可能直接跳转回应用页面
                            if final_url.startswith(self.provider_config.origin):
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: 已通过缓存登录，继续进行授权"
                                )
                            elif "sso_provider" in final_url or "sso_callback" in final_url:
                                # SSO 中间跳转说明 linux.do 会话有效（过期会回到登录页）
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: 会话有效（SSO 跳转中），继续等待授权页面"
                                )
                                # SSO 链路（connect.linux.do）可能再次弹出 Cloudflare 质询
                                # （预置会话的 cf_clearance 与当前代理出口 IP 不匹配），
                                # 先自动解决质询再等授权按钮
                                for _sso_wait_round in range(3):
                                    try:
                                        _title = await page.title()
                                        if "Just a moment" in _title or "Checking your browser" in (await page.content()):
                                            print(
                                                f"ℹ️ {self.account_name}: SSO 跳转遇到 Cloudflare 质询，"
                                                f"正在自动解决（第 {_sso_wait_round + 1}/3 轮）..."
                                            )
                                            try:
                                                await solver.solve_captcha(
                                                    captcha_container=page,
                                                    captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL,
                                                )
                                                print(f"✅ {self.account_name}: Cloudflare 质询已自动解决")
                                            except Exception as solve_err:
                                                print(f"⚠️ {self.account_name}: 自动解决失败: {solve_err}")
                                        await page.wait_for_selector(
                                            'a[href^="/oauth2/approve"], input[type="submit"]',
                                            timeout=20000,
                                        )
                                        break
                                    except Exception:
                                        if _sso_wait_round == 2:
                                            print(
                                                f"⚠️ {self.account_name}: 等待授权页面超时，"
                                                f"当前页面: {page.url}"
                                            )
                                        else:
                                            await page.wait_for_timeout(3000)
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

                            try:
                                await page.goto(
                                    "https://linux.do/login",
                                    wait_until="domcontentloaded",
                                    timeout=90000,
                                )
                            except Exception as goto_err:
                                print(
                                    f"⚠️ {self.account_name}: 登录页加载缓慢或失败（{type(goto_err).__name__}），"
                                    "代理出口可能不稳定"
                                )

                            # Cloudflare 质询页处理：质询脚本经代理可能加载缓慢或失败，
                            # 自动解决 + 等待 + 刷新最多重试 2 轮
                            for _cf_attempt in (1, 2):
                                page_title = await page.title()
                                page_content = await page.content()

                                if "Just a moment" not in page_title and "Checking your browser" not in page_content:
                                    break

                                print(
                                    f"ℹ️ {self.account_name}: 检测到 Cloudflare 验证，"
                                    f"正在自动解决（第 {_cf_attempt}/2 轮）..."
                                )
                                try:
                                    await solver.solve_captcha(
                                        captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL
                                    )
                                    print(f"✅ {self.account_name}: Cloudflare 验证已自动解决")
                                except Exception as solve_err:
                                    print(f"⚠️ {self.account_name}: 自动解决失败: {solve_err}")

                                # 等待质询页消失（登录表单出现），最多 45 秒
                                try:
                                    await page.wait_for_selector("#login-button", state="visible", timeout=45000)
                                    break
                                except Exception:
                                    if _cf_attempt == 1:
                                        print(f"ℹ️ {self.account_name}: 质询未通过，刷新页面重试")
                                        try:
                                            await page.reload(wait_until="domcontentloaded")
                                        except Exception:
                                            pass

                            # 等待登录表单可见（新登录页为 Ember 异步水合，需等表单交互就绪）
                            try:
                                await page.wait_for_selector("#login-button", state="visible", timeout=15000)
                            except Exception:
                                print(f"⚠️ {self.account_name}: 等待登录按钮超时，继续尝试")

                            # 监听登录相关响应（/session 为 Ember XHR，POST /login 为免 JS 原生表单提交）
                            login_api_responses = []

                            def _capture_login_response(response):
                                try:
                                    if response.request.method == "POST" and (
                                        "/session" in response.url or response.url.rstrip("/").endswith("/login")
                                    ):
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

                            # 等待登录结果：跳转离开 /login，或登录接口返回响应
                            async def _wait_login_result(seconds: int) -> bool:
                                for _ in range(seconds):
                                    if "/login" not in page.url or login_api_responses:
                                        return True
                                    await page.wait_for_timeout(1000)
                                return bool(login_api_responses) or "/login" not in page.url

                            async def _wait_turnstile_token(timeout_ms: int) -> bool:
                                """等待 Cloudflare Turnstile 令牌存在（新登录页提交必需）"""
                                try:
                                    await page.wait_for_function(
                                        """() => {
                                            const el = document.querySelector('input[name="cf-turnstile-response"]');
                                            return el && el.value && el.value.length > 10;
                                        }""",
                                        timeout=timeout_ms,
                                    )
                                    return True
                                except Exception:
                                    return False

                            if await _wait_turnstile_token(30000):
                                print(f"ℹ️ {self.account_name}: Turnstile 令牌已就绪")
                            else:
                                print(f"⚠️ {self.account_name}: 等待 Turnstile 令牌超时，继续尝试提交")

                            # 提交方式 1：点击页面 CTA 登录按钮，最多 3 轮。
                            # 令牌经代理刷新失败时（challenges.cloudflare.com 不可达），客户端会
                            # 静默拦截提交且无任何报错；令牌组件恢复后会重新生成令牌，重试即可
                            for _click_round in (1, 2, 3):
                                # 等待令牌；页面重渲染可能移除按钮元素，点击前重新等待其出现
                                await _wait_turnstile_token(20000)
                                for _btn_wait in range(3):
                                    try:
                                        await page.click("#login-button", timeout=10000)
                                        break
                                    except Exception as click_err:
                                        print(
                                            f"⚠️ {self.account_name}: 点击登录按钮失败"
                                            f"（{type(click_err).__name__}），等待按钮重新出现"
                                        )
                                        try:
                                            await page.wait_for_selector(
                                                "#login-button", state="visible", timeout=10000
                                            )
                                        except Exception:
                                            pass
                                print(f"ℹ️ {self.account_name}: 已点击登录按钮（第 {_click_round}/3 轮）")
                                if await _wait_login_result(12):
                                    break
                                if _click_round < 3:
                                    print(f"⚠️ {self.account_name}: 点击后无登录请求，等待令牌恢复后重试")

                            if not await _wait_login_result(15):
                                # 提交方式 2：密码框内回车提交
                                print(f"⚠️ {self.account_name}: 点击登录按钮无响应，尝试回车提交")
                                try:
                                    await page.press("#login-account-password", "Enter")
                                except Exception:
                                    pass
                                await _wait_login_result(10)

                            if not login_api_responses and "/login" in page.url:
                                # 提交方式 3：使用页面自带的免 JS 原生表单（hidden-login-form）直接提交
                                print(f"⚠️ {self.account_name}: 回车提交也无响应，尝试原生表单提交")
                                try:
                                    await page.evaluate(
                                        """(creds) => {
                                            const f = document.querySelector('#hidden-login-form');
                                            if (!f) return false;
                                            const u = f.querySelector('#signin_username');
                                            const p = f.querySelector('#signin_password');
                                            if (!u || !p) return false;
                                            u.value = creds.u;
                                            p.value = creds.p;
                                            const btn = f.querySelector('#signin-button');
                                            if (btn) btn.click();
                                            return true;
                                        }""",
                                        {"u": self.username, "p": self.password},
                                    )
                                except Exception as eval_err:
                                    print(f"⚠️ {self.account_name}: 原生表单提交失败: {eval_err}")
                                await _wait_login_result(15)

                            for _resp in login_api_responses:
                                try:
                                    _status = _resp.status
                                    _detail = ""
                                    try:
                                        _body = await _resp.json()
                                        _detail = _body.get("message") or _body.get("error") or ""
                                    except Exception:
                                        try:
                                            _detail = (await _resp.text())[:120]
                                        except Exception:
                                            _detail = ""
                                    if _status == 200 and "/session" in _resp.url:
                                        print(f"ℹ️ {self.account_name}: 登录接口响应 HTTP 200：{_detail or '(无消息体)'}")
                                    else:
                                        print(
                                            f"⚠️ {self.account_name}: 登录请求响应 HTTP {_status}：{_detail}"
                                        )
                                except Exception:
                                    print(f"⚠️ {self.account_name}: 登录请求响应无法解析")
                            if not login_api_responses:
                                print(
                                    f"⚠️ {self.account_name}: 未捕获到任何登录请求，页面 URL: {page.url}，"
                                    "页面脚本可能未完全加载"
                                )
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
