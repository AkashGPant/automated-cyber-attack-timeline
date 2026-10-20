from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

import pandas as pd

_NULL_STRINGS = {"", "nan", "none", "null", "nat", "-", "n/a"}
_EPOCH_MIN = 946684800          # 2000-01-01
_EPOCH_MAX = 4102444800         # 2100-01-01
_ENC_RE = re.compile(r"-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
                     re.IGNORECASE)


class NormalizationEngine:
    @staticmethod
    def parse_timestamp(ts: Any) -> datetime:
        """Parse many timestamp shapes into a naive UTC datetime.

        Supports ISO-8601 (with/without offset or 'Z'), common log formats,
        Unix epoch in s/ms/us/ns (numeric or numeric string). Returns
        ``datetime.min`` when the value is missing or unparseable so callers can
        flag the row instead of crashing.
        """
        if ts is None:
            return datetime.min
        if isinstance(ts, datetime):
            return NormalizationEngine._to_naive_utc(pd.Timestamp(ts))
        try:
            if pd.isna(ts):
                return datetime.min
        except (TypeError, ValueError):
            pass
        text = str(ts).strip()
        if text.lower() in _NULL_STRINGS:
            return datetime.min

        # Numeric epoch
        try:
            num = float(text)
        except ValueError:
            num = None
        if num is not None:
            for divisor in (1, 1e3, 1e6, 1e9):
                seconds = num / divisor
                if _EPOCH_MIN <= seconds <= _EPOCH_MAX:
                    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
            return datetime.min

        try:
            parsed = pd.to_datetime(text, utc=True)
        except (ValueError, TypeError, OverflowError):
            try:
                parsed = pd.to_datetime(text, utc=True, dayfirst=True, format="mixed")
            except (ValueError, TypeError, OverflowError):
                return datetime.min
        if pd.isna(parsed):
            return datetime.min
        return NormalizationEngine._to_naive_utc(parsed)

    @staticmethod
    def _to_naive_utc(ts: pd.Timestamp) -> datetime:
        if ts.tzinfo is not None:
            ts = ts.tz_convert("UTC").tz_localize(None)
        return ts.to_pydatetime()

    @staticmethod
    def clean_str(value: Any) -> Optional[str]:
        """Return a stripped string or None for empty/NaN-like values."""
        if value is None:
            return None
        try:
            if pd.isna(value):
                return None
        except (TypeError, ValueError):
            pass
        text = str(value).strip()
        if text.lower() in _NULL_STRINGS:
            return None
        # pandas turns integer columns with blanks into floats ("4624.0")
        if re.fullmatch(r"-?\d+\.0", text):
            text = text[:-2]
        return text

    @staticmethod
    def to_int(value: Any) -> Optional[int]:
        text = NormalizationEngine.clean_str(value)
        if text is None:
            return None
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(float(text))
        except ValueError:
            return None

    @staticmethod
    def normalize_ip(value: Any) -> Optional[str]:
        text = NormalizationEngine.clean_str(value)
        if not text:
            return None
        text = text.strip("[]")
        if text.startswith("::ffff:") and "." in text:
            text = text[7:]
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None

    @staticmethod
    def parse_hashes(value: Any) -> Dict[str, str]:
        """Parse Sysmon 'Hashes' field: 'MD5=..,SHA256=..,IMPHASH=..'."""
        text = NormalizationEngine.clean_str(value)
        result: Dict[str, str] = {}
        if not text:
            return result
        for part in re.split(r"[,;\s]+", text):
            if "=" in part:
                algo, _, digest = part.partition("=")
                digest = digest.strip().lower()
                if re.fullmatch(r"[0-9a-f]{32,64}", digest):
                    result[algo.strip().upper()] = digest
        return result

    @staticmethod
    def decode_powershell(command_line: Optional[str]) -> Optional[str]:
        """Decode a PowerShell -EncodedCommand payload (UTF-16LE base64) if present."""
        if not command_line:
            return None
        match = _ENC_RE.search(command_line)
        if not match:
            return None
        blob = match.group(1)
        blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=False)
            decoded = raw.decode("utf-16-le", errors="ignore")
        except (binascii.Error, ValueError):
            return None
        decoded = "".join(ch for ch in decoded if ch.isprintable() or ch in "\r\n\t")
        return decoded if len(decoded.strip()) >= 4 else None


def ip_in_networks(ip: Optional[str], cidrs: Iterable[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def is_internal_ip(ip: Optional[str], internal_cidrs: Iterable[str]) -> bool:
    return ip_in_networks(ip, internal_cidrs)


def is_external_ip(ip: Optional[str], internal_cidrs: Iterable[str]) -> bool:
    """True for a routable-looking address outside the configured internal space."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved or addr.is_loopback:
        return False
    if addr.version == 4 and str(addr).endswith(".255"):
        return False
    return not ip_in_networks(ip, internal_cidrs)
