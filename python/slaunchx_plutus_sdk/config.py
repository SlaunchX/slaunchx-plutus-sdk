"""密钥加载、指纹计算与客户端配置。"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import ConfigurationError

__all__ = [
    "PrivateKeySource",
    "PublicKeySource",
    "load_private_key",
    "load_public_key",
    "spki_fingerprint",
    "PlutusConfig",
    "DEFAULT_API_VERSION",
    "MAX_PLAINTEXT_BYTES",
]

#: 当前唯一受支持的契约主版本
DEFAULT_API_VERSION = "1"

#: 信封明文上限,超出即拒绝(SPEC 8.2)
MAX_PLAINTEXT_BYTES = 1024 * 1024

PrivateKeySource = Union[str, bytes, "os.PathLike[str]", rsa.RSAPrivateKey]
PublicKeySource = Union[str, bytes, "os.PathLike[str]", rsa.RSAPublicKey]

_PRIVATE_MARKER = "-----BEGIN"


def _read_pem(source: Any, kind: str) -> bytes:
    if isinstance(source, bytes):
        data = source
    elif isinstance(source, (str, os.PathLike)):
        text = os.fspath(source) if isinstance(source, os.PathLike) else source
        if _PRIVATE_MARKER in text:
            data = text.encode("utf-8")
        else:
            path = Path(text)
            if not path.is_file():
                raise ConfigurationError("%s PEM 既不是 PEM 文本也不是可读文件: %s" % (kind, text))
            data = path.read_bytes()
    else:
        raise ConfigurationError("无法识别的 %s 密钥来源类型: %r" % (kind, type(source)))
    if _PRIVATE_MARKER.encode("ascii") not in data:
        raise ConfigurationError("%s 内容不是 PEM 编码" % kind)
    return data


def load_private_key(source: PrivateKeySource) -> rsa.RSAPrivateKey:
    """加载 PKCS#8 PEM 私钥。

    :param source: PEM 文本、PEM 字节、PEM 文件路径,或已加载的 ``RSAPrivateKey``。
    :raises ConfigurationError: 内容非法或不是 RSA 私钥。
    """
    if isinstance(source, rsa.RSAPrivateKey):
        return source
    data = _read_pem(source, "私钥")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except Exception as exc:  # pragma: no cover - 由 cryptography 决定具体异常
        raise ConfigurationError("私钥解析失败: %s" % exc) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ConfigurationError("私钥不是 RSA 私钥")
    return key


def load_public_key(source: PublicKeySource) -> rsa.RSAPublicKey:
    """加载 SPKI (``BEGIN PUBLIC KEY``) PEM 公钥。

    :param source: PEM 文本、PEM 字节、PEM 文件路径,或已加载的 ``RSAPublicKey``。
    :raises ConfigurationError: 内容非法、不是 RSA 公钥、模数位长不在 2048–4096 或公开指数不等于 65537。
    """
    if isinstance(source, rsa.RSAPublicKey):
        key: rsa.RSAPublicKey = source
    else:
        data = _read_pem(source, "公钥")
        try:
            loaded = serialization.load_pem_public_key(data)
        except Exception as exc:  # pragma: no cover
            raise ConfigurationError("公钥解析失败: %s" % exc) from exc
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise ConfigurationError("公钥不是 RSA 公钥")
        key = loaded
    if not 2048 <= key.key_size <= 4096:
        raise ConfigurationError("RSA 模数位长必须在 2048–4096 之间,当前 %d" % key.key_size)
    if key.public_numbers().e != 65537:
        raise ConfigurationError("RSA 公开指数必须恰好等于 65537")
    return key


def spki_fingerprint(key: Union[rsa.RSAPublicKey, rsa.RSAPrivateKey]) -> str:
    """计算公钥指纹 ``SHA256:<SPKI DER 的小写 hex>``。

    传入私钥时自动取其公钥。
    """
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "SHA256:" + hashlib.sha256(der).hexdigest()


@dataclass
class PlutusConfig:
    """商户 SDK 配置。

    四把密钥职责严格分离,按需提供:签名调用只需 ``merchant_auth_private_key``;
    响应验签需要 ``platform_auth_public_key``;加密请求需要 ``platform_enc_public_key``;
    敏感响应与 Webhook 解密需要 ``merchant_enc_private_key``。
    """

    #: CONSUMER API 基址,如 ``https://consumer-api.example.com``。
    #: **必须是对外 CONSUMER API 域名**(边缘/网关地址),不能是源站地址,
    #: 也不能自行拼接 ``/prometheus``、``/api/v1/consumer`` 等内部前缀 ——
    #: 这些前缀由边缘负责改写,商户侧配错会导致签名 PATH 与平台实际路由不一致,
    #: 请求必然被判定为验签失败。外部路径(如 ``/card-products/10010106/shared/cards/create``)
    #: 由各请求方法的 ``path`` 参数单独给出。
    base_url: str
    #: API Key 业务 ID,填入 ``X-Api-Key``
    api_key: str
    #: 商户认证私钥,对请求规范串签名
    merchant_auth_private_key: Optional[PrivateKeySource] = None
    #: 平台认证公钥,验证响应签名与 Webhook 签名
    platform_auth_public_key: Optional[PublicKeySource] = None
    #: 平台加密公钥,加密请求体
    platform_enc_public_key: Optional[PublicKeySource] = None
    #: 商户加密私钥,解密敏感响应与 Webhook
    merchant_enc_private_key: Optional[PrivateKeySource] = None
    #: 契约主版本,填入 ``X-API-VERSION``,当前恒为 ``"1"``
    api_version: str = DEFAULT_API_VERSION
    #: requests 超时,秒;可为 ``(connect, read)`` 二元组
    timeout: Union[float, tuple] = 30.0
    #: 是否验证响应签名。默认强制,仅在联调阶段可临时关闭
    verify_response_signature: bool = True
    #: 非 2xx 响应缺少 ``X-Response-Signature`` 时是否也报错。
    #: 缺签名头的统一策略:HTTP 2xx 缺签名头**始终**抛 ``ResponseSignatureError``;
    #: 非 2xx 缺签名头默认放行(``ApiResponse.signature_verified`` 为 ``False``),
    #: 本开关置 ``True`` 后非 2xx 缺签名头同样抛错。
    require_signature_on_error_responses: bool = False
    #: HTTP 状态 >= 400 时抛出类型化 :class:`~slaunchx_plutus_sdk.errors.ApiError`
    raise_on_http_error: bool = True
    #: 响应包络的 ``success`` 明确为 ``False`` 时抛出类型化
    #: :class:`~slaunchx_plutus_sdk.errors.ApiError`。
    #: 与 ``raise_on_http_error`` 合起来覆盖 HTTP 200 + ``success:false`` 的业务失败
    raise_on_business_error: bool = True
    #: 信封解密后的明文上限
    max_plaintext_bytes: int = MAX_PLAINTEXT_BYTES
    #: 加密请求的 ``route_template`` 不在 :data:`~slaunchx_plutus_sdk.routes.ENCRYPTED_ROUTE_TEMPLATES`
    #: 已知端点表中时的处理方式。默认 ``False``:仅发出
    #: :class:`~slaunchx_plutus_sdk.client.UnknownEncryptedRouteWarning`,不阻断请求,
    #: 避免平台新增加密端点后 SDK 常量表滞后导致商户请求被卡死。置为 ``True`` 后未知路由
    #: 改为抛出 :class:`~slaunchx_plutus_sdk.errors.ConfigurationError`。
    strict_encrypted_route_validation: bool = False
    #: 附加到每个请求的固定头
    default_headers: dict = field(default_factory=dict)
    #: ``User-Agent`` 前缀
    user_agent: str = "slaunchx-plutus-sdk-python"

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ConfigurationError("base_url 不能为空")
        self.base_url = self.base_url.rstrip("/")
        if not self.api_key:
            raise ConfigurationError("api_key 不能为空")
        if not self.api_version or not self.api_version.strip():
            raise ConfigurationError("api_version 不能为空")
        self._merchant_auth_private: Optional[rsa.RSAPrivateKey] = (
            load_private_key(self.merchant_auth_private_key)
            if self.merchant_auth_private_key is not None
            else None
        )
        self._platform_auth_public: Optional[rsa.RSAPublicKey] = (
            load_public_key(self.platform_auth_public_key)
            if self.platform_auth_public_key is not None
            else None
        )
        self._platform_enc_public: Optional[rsa.RSAPublicKey] = (
            load_public_key(self.platform_enc_public_key)
            if self.platform_enc_public_key is not None
            else None
        )
        self._merchant_enc_private: Optional[rsa.RSAPrivateKey] = (
            load_private_key(self.merchant_enc_private_key)
            if self.merchant_enc_private_key is not None
            else None
        )

    # -- 已加载的密钥对象 ---------------------------------------------------

    def require_merchant_auth_private(self) -> rsa.RSAPrivateKey:
        """返回商户认证私钥;未配置时抛出 :class:`ConfigurationError`。"""
        if self._merchant_auth_private is None:
            raise ConfigurationError("未配置 merchant_auth_private_key,无法对请求签名")
        return self._merchant_auth_private

    def require_platform_auth_public(self) -> rsa.RSAPublicKey:
        """返回平台认证公钥;未配置时抛出 :class:`ConfigurationError`。"""
        if self._platform_auth_public is None:
            raise ConfigurationError("未配置 platform_auth_public_key,无法验签")
        return self._platform_auth_public

    def require_platform_enc_public(self) -> rsa.RSAPublicKey:
        """返回平台加密公钥;未配置时抛出 :class:`ConfigurationError`。"""
        if self._platform_enc_public is None:
            raise ConfigurationError("未配置 platform_enc_public_key,无法加密请求体")
        return self._platform_enc_public

    def require_merchant_enc_private(self) -> rsa.RSAPrivateKey:
        """返回商户加密私钥;未配置时抛出 :class:`ConfigurationError`。"""
        if self._merchant_enc_private is None:
            raise ConfigurationError("未配置 merchant_enc_private_key,无法解密")
        return self._merchant_enc_private

    # -- 指纹 ---------------------------------------------------------------

    @property
    def platform_encryption_key_id(self) -> str:
        """平台加密公钥指纹,用于 ``X-Platform-Encryption-Key-Id`` 与请求信封 AAD。"""
        return spki_fingerprint(self.require_platform_enc_public())

    @property
    def merchant_encryption_key_id(self) -> str:
        """商户加密公钥指纹,用于校验敏感响应/Webhook 信封的 ``keyFingerprint``。"""
        return spki_fingerprint(self.require_merchant_enc_private())
