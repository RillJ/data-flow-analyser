# Copyright 2026 Julian Calvin Rill
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import hashlib
import logging
from typing import Any, Dict, List, Tuple

from data_flow_analyser.models.schemas import SeedData

logger = logging.getLogger(__name__)


def generate_seed_hash_map(raw_seeds: Dict[str, str]) -> SeedData:
    """
    Pre-computes MD5, SHA-1, SHA-256, and Base64 variants for raw seed values.

    Args:
        raw_seeds: Dictionary mapping labels to raw seed strings (example: {"email": "test@surf.nl"})

    Returns:
        SeedData model containing raw values and the generated lookup map.
    """
    hash_map: Dict[str, str] = {}
    logger.debug("Generating seed lookup map: labels=%d", len(raw_seeds))

    for label, raw_val in raw_seeds.items():
        if not raw_val or not isinstance(raw_val, str):
            logger.debug("Skipping invalid seed: label=%s", label)
            continue

        trimmed = raw_val.strip()
        variations = {
            trimmed,
            trimmed.lower(),
            trimmed.upper(),
        }

        for val in variations:
            val_bytes = val.encode("utf-8")

            # Direct plaintext match
            hash_map[val] = label

            # MD5
            md5_hex = hashlib.md5(val_bytes).hexdigest()
            hash_map[md5_hex] = f"{label} (MD5)"
            hash_map[md5_hex.upper()] = f"{label} (MD5 Upper)"

            # SHA-1
            sha1_hex = hashlib.sha1(val_bytes).hexdigest()
            hash_map[sha1_hex] = f"{label} (SHA-1)"
            hash_map[sha1_hex.upper()] = f"{label} (SHA-1 Upper)"

            # SHA-256
            sha256_hex = hashlib.sha256(val_bytes).hexdigest()
            hash_map[sha256_hex] = f"{label} (SHA-256)"
            hash_map[sha256_hex.upper()] = f"{label} (SHA-256 Upper)"

            # Base64
            b64_str = base64.b64encode(val_bytes).decode("utf-8")
            hash_map[b64_str] = f"{label} (Base64)"

    result = SeedData(raw_values=raw_seeds, hash_map=hash_map)
    logger.debug("Seed lookup map generated: valid_seeds=%d lookup_entries=%d", len(result.raw_values), len(hash_map))
    return result


def scan_for_seed_matches(payload: Any, seed_data: SeedData) -> List[Tuple[str, str]]:
    """
    Recursively scans a string, dictionary, or list payload for occurrences of
    pre-computed seed hashes or plaintexts.

    Args:
        payload: Decoded payload (dict, list, str, etc.)
        seed_data: Pre-computed SeedData object containing hash_map.

    Returns:
        List of tuples: (matched_token_or_hash, seed_label)
    """
    matches: List[Tuple[str, str]] = []

    if isinstance(payload, dict):
        for k, v in payload.items():
            matches.extend(scan_for_seed_matches(k, seed_data))
            matches.extend(scan_for_seed_matches(v, seed_data))
    elif isinstance(payload, list):
        for item in payload:
            matches.extend(scan_for_seed_matches(item, seed_data))
    elif isinstance(payload, str) and payload.strip():
        # Check against hash_map
        for token, label in seed_data.hash_map.items():
            if len(token) >= 4 and token in payload:
                matches.append((token, label))

    if matches:
        logger.debug("Seed scan found matches: payload_type=%s matches=%d", type(payload).__name__, len(matches))
    return matches
