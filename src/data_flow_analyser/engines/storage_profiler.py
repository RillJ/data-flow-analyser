"""Engine for profiling and cross-referencing observed cookies and client storage against policy declarations."""

import logging
from typing import List, Optional, Set

from data_flow_analyser.models.schemas import (
    CookieLongevityResult,
    DeclaredStorageItem,
    NetworkFlow,
    StorageClassificationResult,
    StorageClassificationType,
    StorageTechnologyType,
)

logger = logging.getLogger("data_flow_analyser.storage_profiler")


class StorageProfiler:
    """Profiles observed client-side storage mechanisms and cookies against policy disclosures."""

    def reconcile_storage(
        self,
        flows: List[NetworkFlow],
        cookie_results: List[CookieLongevityResult],
        declared_storage: List[DeclaredStorageItem],
    ) -> List[StorageClassificationResult]:
        """
        Cross-references cookies and storage mechanisms gathered from network traffic against declared storage items.
        """
        results: List[StorageClassificationResult] = []

        # Collect unique set of observed cookie names across sent/set cookies & longevity analyses
        observed_cookie_names: Set[str] = set()
        for flow in flows:
            observed_cookie_names.update(flow.cookies_sent.keys())
            observed_cookie_names.update(flow.cookies_set.keys())

        # Map longevity details by cookie name
        longevity_map = {c.cookie_name: c for c in cookie_results}

        # Index declared items by exact name and lower-case key for soft matching
        declared_map = {item.name: item for item in declared_storage}
        declared_lower_map = {item.name.lower(): item for item in declared_storage}

        for cookie_name in sorted(observed_cookie_names):
            long_info = longevity_map.get(cookie_name)
            observed_days = long_info.lifespan_days if long_info else None

            # Attempt match
            matched_declared = declared_map.get(cookie_name) or declared_lower_map.get(
                cookie_name.lower()
            )

            # Check wildcard prefix matches (e.g. _ga_XXXX matching _ga)
            if not matched_declared:
                for d_item in declared_storage:
                    if cookie_name.startswith(d_item.name):
                        matched_declared = d_item
                        break

            if matched_declared:
                # Check for excessive lifespan relative to heuristic threshold or policy
                if long_info and long_info.is_excessive_longevity:
                    results.append(
                        StorageClassificationResult(
                            name=cookie_name,
                            storage_type=StorageTechnologyType.COOKIE,
                            observed_lifespan_days=observed_days,
                            classification=StorageClassificationType.EXCESSIVE_LIFESPAN,
                            reasoning=(
                                f"Cookie '{cookie_name}' is declared in documentation but has an excessive "
                                f"observed lifespan of {observed_days:.1f} days (exceeds 90-day threshold)."
                            ),
                            declared_match=matched_declared,
                        )
                    )
                else:
                    results.append(
                        StorageClassificationResult(
                            name=cookie_name,
                            storage_type=StorageTechnologyType.COOKIE,
                            observed_lifespan_days=observed_days,
                            classification=StorageClassificationType.DOCUMENTED,
                            reasoning=f"Cookie '{cookie_name}' matches declared storage item '{matched_declared.name}'.",
                            declared_match=matched_declared,
                        )
                    )
            else:
                results.append(
                    StorageClassificationResult(
                        name=cookie_name,
                        storage_type=StorageTechnologyType.COOKIE,
                        observed_lifespan_days=observed_days,
                        classification=StorageClassificationType.UNDOCUMENTED,
                        reasoning=(
                            f"Cookie '{cookie_name}' was observed in network traffic but is not disclosed in the "
                            "privacy/cookie policy documentation."
                        ),
                        declared_match=None,
                    )
                )

        return results