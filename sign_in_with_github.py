#!/usr/bin/env python3
"""
使用 GitHub 账号执行登录授权
"""

import json
import os
from urllib.parse import urlparse, parse_qs
from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType
from utils.browser_utils import filter_cookies, take_screenshot, save_page_content_to_file
from utils.config import ProviderConfig
from utils.wait_for_secrets import WaitForSecrets
from utils.get_headers import get_browser_headers, print_browser_headers
from utils.storage_state import ensure_storage_state_from_env

STORAGE_STATE_ENV_NAME = "STORATE_STATES_GITHUB"

# GitHub 授权页（/login/oauth/authorize）的「Authorize」按钮。
# 该页表单里的第一个 submit 按钮是「Cancel」（name="authorize" value="0"），
# 用通用的 button[type="submit"] 会点到「Cancel」= 拒绝授权，GitHub 随即回调
# error=access_denied（应用被 GitHub 停用才会返回 application_suspended，
# 所以出现 access_denied 就说明是授权页上真的被拒了）。
GITHUB_AUTHORIZE_BUTTON = 'button[name="authorize"][value="1"], button.js-oauth-authorize-btn'


async def find_authorize_button(page):
    """查找 GitHub 授权页的「Authorize」按钮，找不到或不可见时返回 None

    已授权过的应用会跳过授权页直接跳回，因此找不到按钮未必是异常。
    """
    try:
        btn = await page.query_selector(GITHUB_AUTHORIZE_BUTTON)
        if btn and await btn.is_visible():
            return btn
    except Exception:
        pass  # 跳转进行中查询会抛 Execution context destroyed，忽略
    return None


class GitHubSignIn:
    """使用 GitHub 登录授权类"""

    def __init__(
        self,
        account_name: str,
        provider_config: ProviderConfig,
        username: str,
        password: str,
    ):
        """初始化

        Args:
            account_name: 账号名称
            provider_config: 提供商配置
            proxy_conf
            username: GitHub 用户名
            password: GitHub 密码
        """
        self.account_name = account_name
        self.provider_config = provider_config
        self.username = username
        self.password = password

    async def signin(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
    ) -> tuple[bool, dict, dict | None]:
        """使用 GitHub 账号执行登录授权

        Args:
            client_id: OAuth 客户端 ID
            auth_state: OAuth 认证状态
            auth_cookies: OAuth 认证 cookies
            cache_file_path: 缓存文件路径

        Returns:
            (成功标志, 结果字典, 浏览器指纹头部信息或None)
            - 浏览器指纹头部信息仅在检测到 Cloudflare 验证页面时返回
        """
        print(f"ℹ️ {self.account_name}: 开始使用 GitHub 账号登录")
        print(
            f"ℹ️ {self.account_name}: 使用 client_id: {client_id}，auth_state: {auth_state}，缓存文件: {cache_file_path}"
        )

        async with AsyncCamoufox(
            # persistent_context=True,
            # user_data_dir=tmp_dir,
            headless=False,
            humanize=True,
            locale="en-US",
            os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
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

            # 设置从 auth_state 获取的 session cookies 到页面上下文
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
                    oauth_url = f"https://github.com/login/oauth/authorize?response_type=code&client_id={client_id}&state={auth_state}&scope=user:email"

                    if os.path.exists(cache_file_path):
                        try:
                            print(f"ℹ️ {self.account_name}: 正在检查 {oauth_url} 的登录状态")
                            # 直接访问授权页面检查是否已登录
                            response = await page.goto(oauth_url, wait_until="domcontentloaded")
                            print(
                                f"ℹ️ {self.account_name}: 已重定向到应用页面 {response.url if response else '无'}"
                            )
                            await save_page_content_to_file(page, "sign_in_check", self.account_name, prefix="github")

                            # 登录后可能直接跳转回应用页面
                            if response and response.url.startswith(self.provider_config.origin):
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: 已通过缓存登录，继续进行授权"
                                )
                            else:
                                # 检查是否出现授权按钮（表示已登录）
                                authorize_btn = await find_authorize_button(page)
                                if authorize_btn:
                                    is_logged_in = True
                                    print(
                                        f"✅ {self.account_name}: 已通过缓存登录，继续进行授权"
                                    )
                                    try:
                                        await authorize_btn.click()
                                    except Exception as click_err:
                                        print(f"⚠️ {self.account_name}: 点击授权按钮失败: {click_err}")
                                else:
                                    print(f"ℹ️ {self.account_name}: 未找到授权按钮，需要重新登录")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: 检查登录状态失败: {e}")

                    # 如果未登录，则执行登录流程
                    if not is_logged_in:
                        try:
                            print(f"ℹ️ {self.account_name}: 开始登录 GitHub")

                            await page.goto("https://github.com/login", wait_until="domcontentloaded")
                            await page.fill("#login_field", self.username)
                            await page.fill("#password", self.password)
                            await page.click('input[type="submit"][value="Sign in"]')
                            await page.wait_for_timeout(10000)

                            await save_page_content_to_file(page, "sign_in_result", self.account_name, prefix="github")

                            # 处理账号选择（如果需要）
                            try:
                                switch_account_form = await page.query_selector('form[action="/switch_account"]')
                                if switch_account_form:
                                    print(f"ℹ️ {self.account_name}: 需要选择账号")
                                    submit_btn = await switch_account_form.query_selector('input[type="submit"]')
                                    if submit_btn:
                                        print(f"ℹ️ {self.account_name}: 正在点击账号选择提交按钮")
                                        await submit_btn.click()
                                        await page.wait_for_timeout(5000)
                                        await save_page_content_to_file(
                                            page, "account_selected", self.account_name, prefix="github"
                                        )
                                    else:
                                        print(f"⚠️ {self.account_name}: 未找到账号选择提交按钮")
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: 处理账号选择时出错: {e}")

                            # 处理两步验证（如果需要）
                            try:
                                # 检查是否需要两步验证
                                otp_input = await page.query_selector('#app_totp, input[name="app_otp"], input[name="otp"]')
                                if otp_input:
                                    print(f"ℹ️ {self.account_name}: 需要两步验证")

                                    # 记录当前URL用于检测跳转
                                    current_url = page.url
                                    print(f"ℹ️ {self.account_name}: 当前页面 URL 为 {current_url}")

                                    # 尝试通过 wait-for-secrets 自动获取 OTP
                                    otp_code = None
                                    try:
                                        print(
                                            f"🔐 {self.account_name}: 正在尝试通过 wait-for-secrets 获取 OTP..."
                                        )
                                        # Define secret object
                                        wait_for_secrets = WaitForSecrets()
                                        secret_obj = {
                                            "OTP": {
                                                "name": "GitHub 两步验证 OTP",
                                                "description": "来自身份验证器应用的 OTP",
                                            }
                                        }
                                        secrets = wait_for_secrets.get(
                                            secret_obj,
                                            timeout=5,
                                            notification={
                                                "title": "GitHub 两步验证 OTP",
                                                "message": "请在您的账号关联的邮箱查看验证码，并通过以下链接输入",
                                            },
                                        )
                                        if secrets and "OTP" in secrets:
                                            otp_code = secrets["OTP"]
                                            print(f"✅ {self.account_name}: 已通过 wait-for-secrets 获取 OTP")
                                    except Exception as e:
                                        print(f"⚠️ {self.account_name}: wait-for-secrets 失败: {e}")

                                    if otp_code:
                                        # 自动填充 OTP
                                        print(f"✅ {self.account_name}: 正在自动填充 OTP 验证码")
                                        await otp_input.fill(otp_code)
                                        await save_page_content_to_file(
                                            page, "otp_filled", self.account_name, prefix="github"
                                        )

                                        # OTP 输入会自动提交
                                        # 先尝试查询非 disabled 的按钮
                                        # submit_btn = await page.query_selector('button[type="submit"]:not(:disabled)')
                                        # if submit_btn:
                                        #     try:
                                        #         # 等待点击后的导航完成
                                        #         await submit_btn.click()
                                        #         print(f"✅ {self.account_name}: OTP submitted successfully")
                                        #     except Exception as nav_err:
                                        #         print(f"⚠️ {self.account_name}: " f"Navigation after OTP: {nav_err}")
                                        #         await self._save_page_content_to_file(page, "opt_nav_error")
                                        #         # 即使导航出错也继续，因为可能已经成功
                                        #         await page.wait_for_timeout(3000)
                                        # else:
                                        #     print(f"❌ {self.account_name}: Submit button not found")
                                        #     await self._save_page_content_to_file(page, "opt_submit_button_not_found")

                                        # 等待页面跳转完成（URL改变）
                                        try:
                                            await page.wait_for_url(lambda url: url != current_url, timeout=10000)
                                        except Exception:
                                            # URL未改变也继续，可能已经在正确页面
                                            pass
                                    else:
                                        # 回退到手动输入
                                        print(f"ℹ️ {self.account_name}: 请在浏览器中手动输入 OTP 验证码")
                                        await page.wait_for_timeout(30000)  # 等待30秒让用户手动输入
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: 处理两步验证时出错: {e}")

                            # 仅在确认登录成功（存在 user_session cookie）时保存会话，
                            # 2FA 未通过时保存的"半登录"状态会污染缓存，导致后续每次都要重新登录
                            try:
                                _cookies = await context.cookies()
                                _has_session = any(c["name"] == "user_session" for c in _cookies)
                            except Exception:
                                _has_session = False
                            if _has_session:
                                await context.storage_state(path=cache_file_path)
                                print(f"✅ {self.account_name}: 会话缓存已保存到缓存文件")
                            else:
                                print(
                                    f"⚠️ {self.account_name}: 未检测到 GitHub 登录态（user_session 缺失，"
                                    "2FA 可能未通过），跳过保存以避免污染缓存"
                                )

                        except Exception as e:
                            print(f"❌ {self.account_name}: 登录 GitHub 时发生错误: {e}")
                            await take_screenshot(page, "github_signin_error", self.account_name)
                            return False, {"error": "GitHub 登录出错"}, None

                        # 登录后访问授权页面
                        try:
                            print(f"ℹ️ {self.account_name}: 正在前往授权页面: {oauth_url}")
                            response = await page.goto(oauth_url, wait_until="domcontentloaded")
                            print(
                                f"ℹ️ {self.account_name}: 已重定向到应用页面 {response.url if response else '无'}"
                            )

                            # GitHub 登录后可能直接跳转回应用页面
                            if response and response.url.startswith(self.provider_config.origin):
                                print(f"✅ {self.account_name}: 已登录，继续进行授权")
                            else:
                                # 检查是否出现授权按钮（表示已登录）
                                authorize_btn = await find_authorize_button(page)
                                if authorize_btn:
                                    print(
                                        f"✅ {self.account_name}: 已通过缓存登录，继续进行授权"
                                    )
                                    try:
                                        await authorize_btn.click()
                                    except Exception as click_err:
                                        print(f"⚠️ {self.account_name}: 点击授权按钮失败: {click_err}")
                                else:
                                    print(f"ℹ️ {self.account_name}: 未找到授权按钮")
                        except Exception as e:
                            print(f"❌ {self.account_name}: 授权批准时发生错误: {e}")
                            await take_screenshot(page, "github_auth_approval_failed", self.account_name)
                            return False, {"error": "GitHub 授权批准失败"}, None

                    # 统一处理授权逻辑（无论是否通过缓存登录）
                    # 标记是否检测到 Cloudflare 验证页面
                    cloudflare_challenge_detected = False

                    try:
                        # 使用配置的 OAuth 回调路径匹配模式
                        redirect_pattern = self.provider_config.get_github_auth_redirect_pattern()
                        print(f"ℹ️ {self.account_name}: 正在等待 OAuth 回调: {redirect_pattern}")
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
                            await take_screenshot(page, "github_authorization_failed", self.account_name)

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
                        cookies = await context.cookies()
                        user_cookies = filter_cookies(cookies, self.provider_config.origin)

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
                        await take_screenshot(page, "github_oauth_failed_no_user_id", self.account_name)
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
                        elif "error" in query_params:
                            # 回调带 error 说明授权被 GitHub 侧拒绝，最常见的是 access_denied
                            # （授权页上点了 Cancel，或该账号始终未批准此应用）
                            error_code = (query_params.get("error") or [""])[0]
                            error_desc = (query_params.get("error_description") or [""])[0]
                            print(
                                f"❌ {self.account_name}: GitHub 拒绝授权: {error_code} - {error_desc}\n"
                                f"解析的 URL 为: {current_url}"
                            )
                            return (
                                False,
                                {
                                    "error": f"GitHub 拒绝授权（{error_code}）",
                                },
                                None,
                            )
                        else:
                            print(
                                f"❌ {self.account_name}: OAuth 失败，回调中无 code\n"
                                f"解析的 URL 为: {current_url}"
                            )
                            return (
                                False,
                                {
                                    "error": "GitHub OAuth 失败 - 回调中无 code",
                                },
                                None,
                            )

                except Exception as e:
                    print(f"❌ {self.account_name}: 处理 GitHub 页面时发生错误: {e}")
                    await take_screenshot(page, "github_page_navigation_error", self.account_name)
                    return False, {"error": "GitHub 页面跳转出错"}, None
                finally:
                    await page.close()
                    await context.close()
