"""GPG / OpenPGP 加密封装（基于纯 Python 的 pgpy）。

注意：pgpy 依赖标准库 imghdr，而该模块在 Python 3.13 中被移除，
因此在导入 pgpy 之前需要打一个最小化的 imghdr 兼容垫片。
"""
import sys
import types

if "imghdr" not in sys.modules:
    _imghdr = types.ModuleType("imghdr")
    _imghdr.what = lambda file, h=None: None  # noqa: E731
    sys.modules["imghdr"] = _imghdr

import pgpy
from pgpy.constants import (
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)


def generate_keypair():
    """生成 RSA-2048 的 GPG 密钥对，返回 (公钥 armored, 私钥 armored)。"""
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


def _collect_keys(private_key_armored: str):
    """加载私钥，返回 (主密钥, [主密钥, *子密钥])。

    真实 GPG 导出的私钥通常包含独立的「加密子密钥」，解密密文时需要遍历
    子密钥才能成功（主密钥仅用于签名/认证）。受口令保护的私钥在本环境下
    无法解锁，直接抛出清晰、可操作的错误。
    """
    keys = pgpy.PGPKey.from_blob(private_key_armored)
    primary = keys[0]
    all_keys = [primary]
    for sk in primary.subkeys.values():
        all_keys.append(sk)
    for k in all_keys:
        if getattr(k, "is_protected", False):
            raise ValueError(
                "私钥受口令保护，本系统暂不支持导入受口令保护的私钥。"
                "请先在 GnuPG 中去除口令后重新导出："
                "gpg --pinentry-mode loopback --passwd <KEYID> 将口令设为空，"
                "再执行 gpg --export-secret-keys <KEYID> 导出"
            )
    return primary, all_keys


def decrypt(ciphertext_armored: str, private_key_armored: str) -> str:
    primary, all_keys = _collect_keys(private_key_armored)
    message = pgpy.PGPMessage.from_blob(ciphertext_armored)
    last_err = None
    for k in all_keys:
        try:
            return k.decrypt(message).message
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"无法用该私钥解密：{last_err}")


def encrypt_bytes(data: bytes, public_key_armored: str) -> bytes:
    """加密任意二进制数据（文件），返回 armored 文本的字节形式。

    pgpy 的 PGPMessage 原生支持二进制，内部已采用混合加密（会话密钥 + 公钥封装），
    与参考项目 PassPy 的文件加密过程一致，密文长度与文件大小基本无关。
    """
    pub = pgpy.PGPKey.from_blob(public_key_armored)[0]
    message = pub.encrypt(pgpy.PGPMessage.new(data))
    return str(message).encode("utf-8")


def decrypt_bytes(ciphertext: bytes, private_key_armored: str) -> bytes:
    """解密文件密文，返回原始字节。"""
    primary, all_keys = _collect_keys(private_key_armored)
    message = pgpy.PGPMessage.from_blob(ciphertext.decode("utf-8"))
    last_err = None
    for k in all_keys:
        try:
            return bytes(k.decrypt(message).message)
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"无法用该私钥解密文件：{last_err}")
