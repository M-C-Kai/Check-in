"""从本机 Chrome Cookies 数据库读取/回写 new_api_refresh cookie。

新版 new-api 的 dashboard session token 只存在浏览器内存，但浏览器持有
可轮换的 new_api_refresh cookie。每次运行脚本时从这里读取当前有效值，
换取新 token 后必须把轮换后的新值写回，否则 Chrome 手里那份会被作废。

macOS: Chrome 用 Keychain 里的 "Chrome Safe Storage" 派生 AES 密钥加密 cookie。
"""
import os
import sqlite3
import hashlib
import shutil
import subprocess
import tempfile

from Crypto.Cipher import AES

COOKIE_NAME = 'new_api_refresh'
HOST = 'www.superqiyu.org'


def _chrome_key():
    pw = subprocess.check_output(
        ['security', 'find-generic-password', '-s', 'Chrome Safe Storage', '-w']
    ).strip()
    return hashlib.pbkdf2_hmac('sha1', pw, b'saltysalt', 1003, dklen=16)


def _decrypt(enc, key):
    if not enc:
        return ''
    data = enc[3:] if enc[:3] == b'v10' else enc
    dec = AES.new(key, AES.MODE_CBC, IV=b' ' * 16).decrypt(data)
    # Chrome 在明文前加了 32 字节随机前缀，之后是 PKCS7 填充的明文
    if len(dec) > 32:
        dec = dec[32:]
    if dec:
        pad = dec[-1]
        if 1 <= pad <= 16:
            dec = dec[:-pad]
    return dec.decode('utf-8', 'replace')


def _encrypt(plain, key):
    prefix = os.urandom(32)
    data = prefix + plain.encode('utf-8')
    pad = 16 - (len(data) % 16)
    data += bytes([pad]) * pad
    return b'v10' + AES.new(key, AES.MODE_CBC, IV=b' ' * 16).encrypt(data)


def _db_path():
    return os.path.expanduser(
        '~/Library/Application Support/Google/Chrome/Default/Cookies'
    )


def read_refresh():
    """返回 (refresh_cookie, creation_utc) 或 ('', None)"""
    path = _db_path()
    if not os.path.isfile(path):
        return '', None
    tmp = tempfile.mktemp(suffix='.db')
    try:
        shutil.copy2(path, tmp)
        con = sqlite3.connect(tmp)
        row = con.execute(
            "SELECT encrypted_value, creation_utc FROM cookies "
            "WHERE host_key LIKE ? AND name = ? ORDER BY creation_utc DESC LIMIT 1",
            ('%' + HOST, COOKIE_NAME),
        ).fetchone()
        con.close()
        if not row:
            return '', None
        return _decrypt(row[0], _chrome_key()), row[1]
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def write_refresh(value, creation_utc):
    """把轮换后的 refresh cookie 写回 Chrome Cookies DB（原地更新那一行）"""
    path = _db_path()
    if not os.path.isfile(path) or not creation_utc:
        return False
    enc = _encrypt(value, _chrome_key())
    try:
        con = sqlite3.connect(path, timeout=5)
        con.execute('PRAGMA journal_mode=WAL')
        cur = con.execute(
            "UPDATE cookies SET encrypted_value = ?, last_update_utc = ? "
            "WHERE host_key LIKE ? AND name = ? AND creation_utc = ?",
            (enc, int(__import__('time').time() * 1e6) + 11644473600000000,
             '%' + HOST, COOKIE_NAME, creation_utc),
        )
        con.commit()
        con.close()
        return cur.rowcount > 0
    except Exception:
        return False
