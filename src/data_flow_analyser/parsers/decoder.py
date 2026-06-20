import base64
import json
import logging
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)


def recursive_decode(payload: Any, max_depth: int = 6, current_depth: int = 0) -> Any:
    """
    Recursively decodes payloads containing nested dictionaries/lists,
    URL-encoded strings, Base64-encoded strings, or JSON payloads.
    Non-string values and empty strings are passed through unchanged.

    Args:
        payload: The raw string, dict, list, primitive, or None to decode.
        max_depth: Maximum recursion depth to prevent infinite loops (default: 6).
        current_depth: Internal recursion counter.

    Returns:
        The decoded structure or the original value when no decoding applies.
    """
    if current_depth >= max_depth:
        logger.debug("Decode max depth reached: depth=%d", current_depth)
        return payload

    if isinstance(payload, dict):
        return {
            k: recursive_decode(v, max_depth, current_depth + 1)
            for k, v in payload.items()
        }
    
    if isinstance(payload, list):
        return [
            recursive_decode(item, max_depth, current_depth + 1)
            for item in payload
        ]

    # Pass non-strings and empty strings through safely
    if not isinstance(payload, str) or not payload.strip():
        return payload

    current_val = payload.strip()

    # JSON parsing attempt
    if (current_val.startswith("{") and current_val.endswith("}")) or \
       (current_val.startswith("[") and current_val.endswith("]")):
        try:
            parsed_json = json.loads(current_val)
            logger.debug("Decoded JSON payload: depth=%d chars=%d", current_depth, len(current_val))
            return recursive_decode(parsed_json, max_depth, current_depth + 1)
        except Exception:
            pass

    # Base64 decoding attempt
    if len(current_val) >= 8 and len(current_val) % 4 == 0:
        try:
            decoded_bytes = base64.b64decode(current_val, validate=True)
            decoded_str = decoded_bytes.decode("utf-8")
            if decoded_str.isprintable() and len(decoded_str) > 0 and decoded_str != current_val:
                return recursive_decode(decoded_str, max_depth, current_depth + 1)
        except Exception:
            pass

    # URL decoding attempt
    try:
        unquoted = urllib.parse.unquote(current_val)
        if unquoted != current_val:
            logger.debug("Decoded URL-encoded payload: depth=%d chars=%d", current_depth, len(current_val))
            return recursive_decode(unquoted, max_depth, current_depth + 1)
    except Exception:
        pass

    return current_val
