#!/usr/bin/env python3
"""
浏览器自动化相关的公共工具函数
"""

import math
import os
import random
from datetime import datetime
from urllib.parse import urlparse


def parse_cookies(cookies_data) -> dict:
    """解析 cookies 数据

    支持字典格式和字符串格式的 cookies

    Args:
        cookies_data: cookies 数据，可以是字典或分号分隔的字符串

    Returns:
        解析后的 cookies 字典
    """
    if isinstance(cookies_data, dict):
        return cookies_data

    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


def filter_cookies(cookies: list[dict], origin: str) -> dict:
    """根据 origin 过滤 cookies，只保留匹配域名的 cookies

    Args:
        cookies: Camoufox cookies 列表，每个元素是包含 name, value, domain 等的字典
        origin: Provider 的 origin URL (例如: https://api.example.com)

    Returns:
        过滤后的 cookies 字典 {name: value}
    """
    # 提取 provider origin 的域名
    provider_domain = urlparse(origin).netloc

    # 过滤 cookies，只保留与 provider domain 匹配的
    user_cookies = {}
    matched_items = []  # 存储 "name(domain)" 格式
    filtered_items = []  # 存储 "name(domain)" 格式

    for cookie in cookies:
        cookie_name = cookie.get("name")
        cookie_value = cookie.get("value")
        cookie_domain = cookie.get("domain", "")

        if cookie_name and cookie_value:
            # 检查 cookie domain 是否匹配 provider domain
            # cookie domain 可能以 . 开头 (如 .example.com)，需要处理
            normalized_cookie_domain = cookie_domain.lstrip(".")
            normalized_provider_domain = provider_domain.lstrip(".")

            # 匹配逻辑：cookie domain 应该是 provider domain 的后缀
            if (
                normalized_provider_domain == normalized_cookie_domain
                or normalized_provider_domain.endswith("." + normalized_cookie_domain)
                or normalized_cookie_domain.endswith("." + normalized_provider_domain)
            ):
                user_cookies[cookie_name] = cookie_value
                matched_items.append(f"{cookie_name}({cookie_domain})")
            else:
                filtered_items.append(f"{cookie_name}({cookie_domain})")

    if matched_items:
        print(f"  🔵 匹配: {', '.join(matched_items)}")
    if filtered_items:
        print(f"  🔴 过滤: {', '.join(filtered_items)}")

    print(
        f"🔍 Cookie 过滤结果（{provider_domain}）: "
        f"{len(matched_items)} 个匹配，{len(filtered_items)} 个被过滤"
    )

    return user_cookies


def get_random_user_agent() -> str:
    """获取随机的现代浏览器 User Agent 字符串

    Returns:
        随机选择的 User Agent 字符串
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) " "Gecko/20100101 Firefox/134.0",
    ]
    return random.choice(user_agents)


async def take_screenshot(
    page,
    reason: str,
    account_name: str,
    screenshots_dir: str = "screenshots",
) -> None:
    """截取当前页面的屏幕截图

    Args:
        page: Camoufox/Playwright 页面对象
        reason: 截图原因描述
        account_name: 账号名称（用于日志输出和文件名）
        screenshots_dir: 截图保存目录，默认为 "screenshots"

    Note:
        通过环境变量 DEBUG=true 启用截图功能，默认为 false
    """
    # 检查 DEBUG 环境变量
    debug_enabled = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    if not debug_enabled:
        print(f"🔍 {account_name}: 已跳过截图（DEBUG=false），原因: {reason}")
        return

    try:
        os.makedirs(screenshots_dir, exist_ok=True)

        # 自动生成安全的账号名称
        safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)

        # 生成文件名: 账号名_时间戳_原因.png
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
        filename = f"{safe_account_name}_{timestamp}_{safe_reason}.png"
        filepath = os.path.join(screenshots_dir, filename)

        await page.screenshot(path=filepath, full_page=True)
        print(f"📸 {account_name}: 截图已保存到 {filepath}")
    except Exception as e:
        print(f"⚠️ {account_name}: 截图失败: {e}")


async def save_page_content_to_file(
    page,
    reason: str,
    account_name: str,
    prefix: str = "",
    logs_dir: str = "logs",
) -> None:
    """保存页面 HTML 到日志文件

    Args:
        page: Camoufox/Playwright 页面对象
        reason: 日志原因描述
        account_name: 账号名称（用于日志输出和文件名）
        prefix: 文件名前缀（如 "github_", "linuxdo_" 等）
        logs_dir: 日志保存目录，默认为 "logs"

    Note:
        通过环境变量 DEBUG=true 启用保存 HTML 功能，默认为 false
    """
    # 检查 DEBUG 环境变量
    debug_enabled = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    if not debug_enabled:
        print(f"🔍 {account_name}: 已跳过保存 HTML（DEBUG=false），原因: {reason}")
        return

    try:
        os.makedirs(logs_dir, exist_ok=True)

        # 自动生成安全的账号名称
        safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_reason = "".join(c if c.isalnum() else "_" for c in reason)

        # 构建文件名
        if prefix:
            filename = f"{safe_account_name}_{timestamp}_{prefix}_{safe_reason}.html"
        else:
            filename = f"{safe_account_name}_{timestamp}_{safe_reason}.html"
        filepath = os.path.join(logs_dir, filename)

        html_content = await page.content()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"📄 {account_name}: 页面 HTML 已保存到 {filepath}")
    except Exception as e:
        print(f"⚠️ {account_name}: 保存 HTML 失败: {e}")


async def aliyun_captcha_check(page, account_name: str) -> bool:
    """阿里云验证码检查和处理

    检查页面是否有阿里云验证码（通过 traceid 检测），如果有则尝试自动滑动验证

    Args:
        page: Camoufox/Playwright 页面对象
        account_name: 账号名称（用于日志输出）

    Returns:
        bool: 验证码处理是否成功（无验证码或验证通过返回 True，验证失败返回 False）
    """
    # 检查是否有 traceid (阿里云验证码页面)
    try:
        traceid = await page.evaluate(
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

        if traceid:
            print(f"⚠️ {account_name}: 检测到阿里云验证码，traceid: {traceid}")
            try:
                # 兼容两代阿里云验证码：
                # 1.0 旧版：#nocaptcha 内 .nc_scale 轨道 + .btn_slide 手柄
                # 2.0 新版（AliyunCaptcha.js）：#captcha-element 容器内
                #     #aliyunCaptcha-sliding-slider 手柄（embed 模式直接渲染滑块）
                slider_element = await page.query_selector("#nocaptcha .nc_scale")
                slider_handle = await page.query_selector("#nocaptcha .btn_slide")
                if slider_handle is None:
                    # 新版：等待滑块手柄出现。实测 AliyunCaptcha.js 渲染很慢且元素
                    # 可能长时间处于零尺寸布局（visible 判定不通过但 DOM 已挂载），
                    # 因此用 state="attached" + 轮询 bounding_box
                    print(f"ℹ️ {account_name}: 等待阿里云滑块组件渲染（最长 150s）...")
                    try:
                        await page.wait_for_selector(
                            "#aliyunCaptcha-sliding-slider, "
                            "#captcha-element .aliyun_captcha_slide_button, "
                            "#captcha-element [class*='slide'], "
                            "#nocaptcha .btn_slide",
                            timeout=150000,
                            state="attached",
                        )
                    except Exception:
                        await save_page_content_to_file(
                            page, "aliyun_captcha_no_slider", account_name
                        )
                        raise
                    for _ in range(30):
                        slider_handle = (
                            await page.query_selector("#aliyunCaptcha-sliding-slider")
                            or await page.query_selector("#captcha-element .aliyun_captcha_slide_button")
                            or await page.query_selector("#captcha-element [class*='slide']")
                            or await page.query_selector("#nocaptcha .btn_slide")
                        )
                        if slider_handle:
                            handle_box = await slider_handle.bounding_box()
                            if handle_box and handle_box.get("width", 0) > 5 and handle_box.get("height", 0) > 5:
                                break
                        await page.wait_for_timeout(1000)

                if slider_element is None and slider_handle is not None:
                    # 新版没有 .nc_scale 轨道：用滑块手柄的父元素作为轨道
                    try:
                        parent_el = await slider_handle.evaluate_handle("el => el.parentElement")
                        parent_elem = parent_el.as_element() if parent_el else None
                        if parent_elem:
                            slider_element = parent_elem
                    except Exception:
                        pass

                slider = await slider_element.bounding_box() if slider_element else None
                if slider:
                    print(f"ℹ️ {account_name}: 滑块边界框: {slider}")

                handle = await slider_handle.bounding_box() if slider_handle else None
                if handle:
                    print(f"ℹ️ {account_name}: 滑块手柄边界框: {handle}")

                if slider and handle:
                    await take_screenshot(page, "aliyun_captcha_slider_start", account_name)

                    await page.mouse.move(
                        handle.get("x") + handle.get("width") / 2,
                        handle.get("y") + handle.get("height") / 2,
                    )
                    # 人手到位后会有短暂停顿再按下
                    await page.wait_for_timeout(random.randint(120, 400))
                    await page.mouse.down()
                    # 拟人轨迹：先快后慢、带纵向抖动、末端过冲后回拉，
                    # 松手前停顿——规避风控对匀速直线的判定
                    start_x = handle.get("x") + handle.get("width") / 2
                    # 拖到轨道右端（减去手柄半宽，确保手柄完全滑到底）
                    end_x = slider.get("x") + slider.get("width") - handle.get("width") / 2
                    y = handle.get("y") + handle.get("height") / 2
                    distance = end_x - start_x
                    steps = random.randint(30, 50)
                    overshoot = random.uniform(8, 20)

                    for i in range(1, steps + 1):
                        progress = i / steps
                        # ease-in-out：起步慢、中段快、收尾慢
                        eased = (
                            2 * progress**2
                            if progress < 0.5
                            else 1 - (-2 * progress + 2) ** 2 / 2
                        )
                        jitter_y = random.uniform(-3, 3) * math.sin(progress * math.pi)
                        await page.mouse.move(
                            start_x + (distance + overshoot) * eased, y + jitter_y
                        )
                        await page.wait_for_timeout(random.randint(5, 20))
                    # 过冲后回拉到终点
                    pullback_steps = random.randint(3, 6)
                    for i in range(1, pullback_steps + 1):
                        progress = i / pullback_steps
                        await page.mouse.move(
                            start_x + distance + overshoot * (1 - progress),
                            y + random.uniform(-1, 1),
                        )
                        await page.wait_for_timeout(random.randint(10, 30))
                    # 松手前停顿（人手松开前的犹豫）
                    await page.wait_for_timeout(random.randint(80, 300))
                    await page.mouse.up()
                    await take_screenshot(page, "aliyun_captcha_slider_completed", account_name)

                    # Wait for page to be fully loaded
                    await page.wait_for_timeout(20000)

                    await take_screenshot(page, "aliyun_captcha_slider_result", account_name)
                    return True
                else:
                    print(f"❌ {account_name}: 未找到滑块或滑块手柄")
                    await take_screenshot(page, "aliyun_captcha_error", account_name)
                    return False
            except Exception as e:
                print(f"❌ {account_name}: 移动滑块时发生错误: {e}")
                await take_screenshot(page, "aliyun_captcha_error", account_name)
                return False
        else:
            print(f"ℹ️ {account_name}: 未找到 traceid")
            await take_screenshot(page, "aliyun_captcha_traceid_found", account_name)
            return True
    except Exception as e:
        print(f"❌ {account_name}: 获取 traceid 时发生错误: {e}")
        await take_screenshot(page, "aliyun_captcha_error", account_name)
        return False
