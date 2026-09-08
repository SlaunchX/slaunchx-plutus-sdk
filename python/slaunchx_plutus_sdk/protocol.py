"""Explicit protocol selection; never fall back after signature failure."""
from enum import Enum
import re
from urllib.parse import unquote_plus, quote_plus
from .errors import CanonicalQueryError, ConfigurationError

class ProtocolProfile(str, Enum):
    REQUEST_BOUND_V1 = "request-bound-v1"
    PRODUCT_V1 = "product-v1"


def resolve_profile(value):
    try:
        return ProtocolProfile(value)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("unknown protocol_profile") from exc


def product_canonical_query(query):
    if query is None or re.fullmatch(r"[\u0009-\u000d\u001c-\u0020\u1680\u2000-\u2006\u2008-\u200a\u2028\u2029\u205f\u3000]*", query):
        return ""
    def decode(value):
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise CanonicalQueryError("invalid percent encoding")
        try:
            return unquote_plus(value, encoding="utf-8", errors="strict")
        except UnicodeError as exc:
            raise CanonicalQueryError("invalid UTF-8") from exc
    def encode(value):
        return quote_plus(value, safe="*", encoding="utf-8", errors="strict").replace("+", "%20").replace("~", "%7E")
    pairs = []
    try:
        for part in query.split("&"):
            key, sep, value = part.partition("=")
            pairs.append((decode(key), decode(value)))
        pairs.sort(key=lambda pair: (pair[0].encode("utf-16-be"), pair[1].encode("utf-16-be")))
        return "&".join(encode(k) + "=" + encode(v) for k, v in pairs)
    except UnicodeError as exc:
        raise CanonicalQueryError("invalid UTF-8") from exc


def product_request_id(value):
    import secrets
    if value is not None and ("\r" in value or "\n" in value):
        raise ConfigurationError("X-Request-Id must not contain newlines")
    return (value or "").strip() or "req_" + secrets.token_hex(16)
