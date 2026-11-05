"""Dashboard session token 自动续期（适配新版 new-api 的 Authorization 鉴权）。

新版 new-api 的 /api/user/* 只认 Authorization: Bearer <dashboard session token>，
该 token 短期有效、只存在浏览器内存里；但浏览器持有可轮换的 new_api_refresh
cookie，POST /api/user/auth/refresh 即可换取新 token。

refresh cookie 为一次性轮换：必须先从 Chrome Cookies DB 读取当前有效值，
换到新 token 后立即把轮换后的新 cookie 写回 Chrome，否则浏览器登录态会被踢掉。
"""
import os
import re
import requests

REFRESH_PATH = '/api/user/auth/refresh'


def read_refresh_from_env(env_path):
    if not os.path.isfile(env_path):
        return ''
    for line in open(env_path, encoding='utf-8'):
        line = line.strip()
        if line.startswith('NEWAPI_REFRESH=') and not line.startswith('#'):
            return line[len('NEWAPI_REFRESH='):].strip()
    return ''


def write_refresh_to_env(env_path, value):
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding='utf-8') as f:
        content = f.read()
    if re.search(r'^NEWAPI_REFRESH=.*$', content, re.M):
        content = re.sub(r'^NEWAPI_REFRESH=.*$', 'NEWAPI_REFRESH=' + value, content, flags=re.M)
    else:
        content += '\nNEWAPI_REFRESH=' + value + '\n'
    with open(env_path, 'w', encoding='utf-8') as f:
        f.write(content)


def get_refresh(accounts, env_path):
    """优先从本机 Chrome 读取 refresh cookie；读不到再退回 .env。

    返回 (refresh_cookie, source, creation_utc)
    """
    try:
        from chrome_cookie_store import read_refresh
        value, creation_utc = read_refresh()
        if value:
            return value, 'chrome', creation_utc
    except Exception as e:
        print('[Refresh] 读取 Chrome cookie 失败: %s' % e)
    env_value = read_refresh_from_env(env_path)
    return env_value, 'env', None


def refresh(base_url, refresh_cookie, timeout=25):
    """返回 (access_token, new_refresh_cookie, error)"""
    url = base_url.rstrip('/') + REFRESH_PATH
    session = requests.Session()
    session.headers.update({
        'Accept': 'application/json',
        'Origin': base_url.rstrip('/'),
        'Referer': base_url.rstrip('/') + '/profile',
        'Cookie': 'new_api_refresh=' + refresh_cookie,
        'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/120.0.0.0 Safari/537.36'),
    })
    try:
        resp = session.post(url, timeout=timeout)
        data = resp.json()
    except Exception as e:
        return None, None, 'refresh 请求失败: %s' % e
    if not data.get('success'):
        return None, None, 'refresh 失败: %s' % (data.get('message') or data.get('code') or resp.status_code)
    token = (data.get('data') or {}).get('access_token')
    if not token:
        return None, None, 'refresh 响应缺少 access_token'
    match = re.search(r'new_api_refresh=([^;]+)', resp.headers.get('Set-Cookie', ''))
    new_refresh = match.group(1) if match else refresh_cookie
    return 'Bearer ' + token, new_refresh, None
