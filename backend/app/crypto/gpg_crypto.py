"""GPG / OpenPGP 加密封装（基于纯 Python 的 pgpy）。

注意：pgpy 依赖标准库 imghdr，而该模块在 Python 3.13 中被移除，
因此在导入 pgpy 之前需要打一个最小化的 imghdr 兼容垫片。

受口令保护的 GPG 私钥
=====================
真实 GPG 密钥可以在「导出私钥」时通过 GnuPG 设置 passphrase；
pgpy 0.6.0 提供 ``key.unlock(passphrase)`` 上下文管理器作为解锁入口。
为兼容两种私钥（带口令 / 不带口令），本模块统一通过 ``decrypt(..., passphrase=None)``
参数处理：

* 不带口令的私钥        → ``passphrase`` 传不传都能成功；
* 带口令的私钥 + 错误口令 → ``pgpy.errors.PGPDecryptionError``；
* 带口令的私钥 + 不传口令 → ``ValueError``（提示「需要 GPG 密钥口令」）。

导入受口令保护的私钥时，业务层需要同时把口令保存下来（OrgKey.private_passphrase），
后续所有解密 / 签名都使用该口令。
"""
import sys
import types

if "imghdr" not in sys.modules:
    _imghdr = types.ModuleType("imghdr")
    _imghdr.what = lambda file, h=None: None  # noqa: E731
    sys.modules["imghdr"] = _imghdr

import pgpy


def generate_keypair():
    """生成 RSA-2048 的 GPG 密钥对，返回 (公钥 armored, 私钥 armored)。"""
    from pgpy.constants import HashAlgorithm, KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("密码管理", email="pm@localhost")
    key.add_uid(
        uid,
        usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
    )
    return str(key.pubkey), str(key)


def encrypt(plaintext: str, public_key_armored: str) -> str:
    pub = pgpy.PGPKey.from_blob(public_key_armored)[0]
    message = pub.encrypt(pgpy.PGPMessage.new(plaintext))
    return str(message)


def encrypt_bytes(data: bytes, public_key_armored: str) -> bytes:
    """加密任意二进制数据，返回 armored 文本的字节形式。"""
    pub = pgpy.PGPKey.from_blob(public_key_armored)[0]
    message = pub.encrypt(pgpy.PGPMessage.new(data))
    return str(message).encode("utf-8")


def _is_protected(key) -> bool:
    return bool(getattr(key, "is_protected", False))


def _collect_keys(private_key_armored: str):
    """加载私钥，返回 (主密钥, [主密钥, *子密钥], any_protected)。

    真实 GPG 导出的私钥通常包含独立的「加密子密钥」，解密时必须遍历子密钥。
    """
    keys = pgpy.PGPKey.from_blob(private_key_armored)
    primary = keys[0]
    all_keys = [primary]
    for sk in primary.subkeys.values():
        all_keys.append(sk)
    any_protected = any(_is_protected(k) for k in all_keys)
    return primary, all_keys, any_protected


def _try_decrypt_with_keys(message, all_keys, passphrase):
    """遍历主密钥 + 子密钥尝试解密；任一成功即返回明文。

    对于 ``is_protected=True`` 的密钥，使用 ``with key.unlock(passphrase):`` 上下文解锁；
    错误口令由 pgpy 抛 ``PGPDecryptionError``，本函数捕获并继续尝试下一个 key。
    """
    last_err = None
    for k in all_keys:
        protected = _is_protected(k)
        try:
            if protected:
                if not passphrase:
                    last_err = ValueError(f"该子密钥 (fingerprint={k.fingerprint}) 受口令保护，需提供口令")
                    continue
                with k.unlock(passphrase):
                    return k.decrypt(message).message
            else:
                # 不带口令的密钥尝试直接解密
                return k.decrypt(message).message
        except Exception as e:  # 含 PGPDecryptionError
            last_err = e
            continue
    raise RuntimeError(f"无法用该私钥解密：{last_err}")


def decrypt(ciphertext_armored: str, private_key_armored: str, passphrase: str = None) -> str:
    """用 GPG 私钥解密密文。

    - ``passphrase`` 为 None 时，若私钥受保护会直接抛出 ``ValueError``。
    - 错误口令会抛 ``RuntimeError``，原文可在 except 里读取。
    """
    primary, all_keys, any_protected = _collect_keys(private_key_armored)
    if any_protected and not passphrase:
        raise ValueError("该 GPG 私钥受口令保护，请提供该密钥的 passphrase")
    message = pgpy.PGPMessage.from_blob(ciphertext_armored)
    return _try_decrypt_with_keys(message, all_keys, passphrase)


def decrypt_bytes(ciphertext: bytes, private_key_armored: str, passphrase: str = None) -> bytes:
    """解密二进制密文（文件场景，但接口已统一不再有文件场景，此处保留用于 debug 测试）。"""
    primary, all_keys, any_protected = _collect_keys(private_key_armored)
    if any_protected and not passphrase:
        raise ValueError("该 GPG 私钥受口令保护，请提供该密钥的 passphrase")
    message = pgpy.PGPMessage.from_blob(ciphertext.decode("utf-8"))
    plain = _try_decrypt_with_keys(message, all_keys, passphrase)
    if isinstance(plain, str):
        return plain.encode("utf-8")
    return bytes(plain)
