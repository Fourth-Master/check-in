#!/usr/bin/env python3
"""
storage state 相关工具
"""

import json
import os


def ensure_storage_state_from_env(
    cache_file_path: str,
    account_name: str,
    username: str,
    env_name: str = "STORATE_STATES",
) -> bool:
    """当本地缓存不存在时，从环境变量恢复 storage state 文件。"""
    if not cache_file_path:
        print(f"⚠️ {account_name}: 跳过恢复会话缓存：cache_file_path 为空")
        return False

    if os.path.exists(cache_file_path):
        print(f"⚠️ {account_name}: 跳过恢复会话缓存：缓存文件已存在: {cache_file_path}")
        return False

    storage_states_str = os.getenv(env_name, "")
    if not storage_states_str:
        print(f"⚠️ {account_name}: 跳过恢复会话缓存：{env_name} 为空或未设置")
        return False

    try:
        storage_states = json.loads(storage_states_str)
    except json.JSONDecodeError as exc:
        print(f"⚠️ {account_name}: 解析 {env_name} 失败: {exc}")
        return False

    if not isinstance(storage_states, dict):
        print(f"⚠️ {account_name}: {env_name} 必须为 JSON 对象")
        return False

    # 精确匹配用户名；未命中时尝试大小写不敏感匹配（同一账号可能用邮箱、用户名等不同键配置）
    storage_state_data = storage_states.get(username)
    if storage_state_data is None:
        lowered = str(username).lower()
        for key, value in storage_states.items():
            if str(key).lower() == lowered and value:
                storage_state_data = value
                print(f"ℹ️ {account_name}: 会话缓存按大小写不敏感方式匹配到键 '{key}'")
                break
    if storage_state_data is None:
        print(f"⚠️ {account_name}: 跳过恢复会话缓存：在 {env_name} 中未找到 '{username}'（可尝试同时以 用户名/邮箱 作为键配置）")
        return False

    if isinstance(storage_state_data, str):
        try:
            storage_state_data = json.loads(storage_state_data)
        except json.JSONDecodeError as exc:
            print(f"⚠️ {account_name}: 会话缓存 '{username}' 不是有效的 JSON: {exc}")
            return False

    if not isinstance(storage_state_data, dict):
        print(f"⚠️ {account_name}: 会话缓存 '{username}' 必须为 JSON 对象")
        return False

    cache_dir = os.path.dirname(cache_file_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)

    with open(cache_file_path, "w", encoding="utf-8") as file:
        json.dump(storage_state_data, file, ensure_ascii=False, indent=2)

    print(f"ℹ️ {account_name}: 已从 {env_name} 恢复会话缓存 -> {username}")
    return True
