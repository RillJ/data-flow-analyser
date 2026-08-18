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

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import logging
from typing import List, Optional

from data_flow_analyser.models.schemas import (
    CookieLongevityResult,
)

logger = logging.getLogger(__name__)

def parse_set_cookie_longevity(
    set_cookie_header: str,
    flow_timestamp: Optional[datetime] = None,
    reference_time: Optional[datetime] = None,
) -> List[CookieLongevityResult]:
    """
    Parses Set-Cookie directives to report observed cookie lifespan.
    """
    results: List[CookieLongevityResult] = []
    if not set_cookie_header:
        return results

    # Prefer the capture timestamp.  If it is unavailable, use the explicit analysis reference time.  
    effective_reference_time = flow_timestamp or reference_time
    if effective_reference_time and effective_reference_time.tzinfo is None:
        effective_reference_time = effective_reference_time.replace(tzinfo=timezone.utc)

    directives = [d.strip() for d in set_cookie_header.split(";") if d.strip()]
    if not directives:
        return results

    # First directive is name=value
    name_val_part = directives[0]
    if "=" not in name_val_part:
        return results

    cookie_name, cookie_val = name_val_part.split("=", 1)
    cookie_name = cookie_name.strip()
    cookie_val = cookie_val.strip()

    max_age_seconds: Optional[int] = None
    expires_dt: Optional[datetime] = None
    lifespan_days: Optional[float] = None

    for directive in directives[1:]:
        if "=" in directive:
            d_key, d_val = directive.split("=", 1)
            d_key = d_key.strip().lower()
            d_val = d_val.strip()

            if d_key == "max-age":
                try:
                    max_age_seconds = int(d_val)
                    lifespan_days = round(max_age_seconds / (24 * 3600), 2)
                except ValueError:
                    pass
            elif d_key == "expires" and max_age_seconds is None:
                try:
                    expires_dt = parsedate_to_datetime(d_val)
                    if expires_dt.tzinfo is None:
                        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                    if effective_reference_time:
                        delta = expires_dt - effective_reference_time
                        max_age_seconds = int(delta.total_seconds())
                        lifespan_days = round(max_age_seconds / (24 * 3600), 2)
                except Exception:
                    pass

    logger.debug("Cookie lifespan: name=%s lifespan_days=%s", cookie_name, lifespan_days)

    results.append(
        CookieLongevityResult(
            cookie_name=cookie_name,
            cookie_value=cookie_val,
            max_age_seconds=max_age_seconds,
            expires_at=expires_dt,
            lifespan_days=lifespan_days,
        )
    )

    return results


def analyse_cookie_longevity(
    response_headers: dict[str, str],
    flow_timestamp: Optional[datetime] = None,
    reference_time: Optional[datetime] = None,
) -> List[CookieLongevityResult]:
    """Evaluate the lifespan of cookies declared in response headers."""
    cookie_longevity_results: List[CookieLongevityResult] = []
    set_cookie_val = response_headers.get("Set-Cookie") or response_headers.get("set-cookie")
    if set_cookie_val:
        cookie_longevity_results.extend(
            parse_set_cookie_longevity(
                set_cookie_val,
                flow_timestamp,
                reference_time=reference_time,
            )
        )
    return cookie_longevity_results
