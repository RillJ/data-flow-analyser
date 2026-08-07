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

import logging
from typing import List, Set

from data_flow_analyser.models.schemas import (
    CookieLongevityResult,
    ConsentOutcome,
    ConsentPhase,
    DeclaredStorageItem,
    NetworkFlow,
    StorageClassificationResult,
    StorageClassificationType,
    StorageTechnologyType,
)
from data_flow_analyser.engines.consent import classify_consent_phase

logger = logging.getLogger("data_flow_analyser.storage_profiler")


class StorageProfiler:
    """Profiles observed client-side storage mechanisms and cookies against policy disclosures."""

    def reconcile_storage(
        self,
        flows: List[NetworkFlow],
        cookie_results: List[CookieLongevityResult],
        declared_storage: List[DeclaredStorageItem],
        consent_decided_at=None,
        consent_withdrawn_at=None,
        consent_outcome: ConsentOutcome = ConsentOutcome.NECESSARY_ONLY,
    ) -> List[StorageClassificationResult]:
        """
        Cross-references cookies and storage mechanisms gathered from network traffic against declared storage items.
        """
        results: List[StorageClassificationResult] = []
        logger.debug("Storage profiling started: flows=%d cookie_records=%d declared_items=%d", len(flows), len(cookie_results), len(declared_storage))

        # Collect unique set of observed cookie names across sent/set cookies & longevity analyses
        observed_cookie_names: Set[str] = set()
        cookie_domains: dict[str, Set[str]] = {}
        cookie_domain_attributes: dict[str, Set[str]] = {}
        flow_phases = {
            flow.flow_id: classify_consent_phase(
                flow.timestamp,
                consent_decided_at,
                consent_withdrawn_at,
                consent_outcome,
            )
            for flow in flows
        }
        first_observations: dict[str, tuple] = {}
        for flow in flows:
            observed_cookie_names.update(flow.cookies_sent.keys())
            observed_cookie_names.update(flow.cookies_set.keys())
            for cookie_name in set(flow.cookies_sent) | set(flow.cookies_set):
                cookie_domains.setdefault(cookie_name, set()).add(flow.host)
            for cookie_name, domain in flow.cookies_set_domain_attributes.items():
                cookie_domain_attributes.setdefault(cookie_name, set()).add(domain)
            phase = flow_phases[flow.flow_id]
            for cookie_name in set(flow.cookies_set) | set(flow.cookies_sent):
                previous = first_observations.get(cookie_name)
                if previous is None or flow.timestamp < previous[0]:
                    first_observations[cookie_name] = (flow.timestamp, flow.flow_id, phase)

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

            first_observation = first_observations.get(cookie_name)
            first_phase = first_observation[2] if first_observation else ConsentPhase.UNKNOWN
            consent_context = {
                "first_observed_phase": first_phase,
                "first_observed_flow_id": first_observation[1] if first_observation else None,
                "first_observed_at": first_observation[0] if first_observation else None,
            }

            if matched_declared and long_info and long_info.is_excessive_longevity:
                classification = StorageClassificationType.EXCESSIVE_LIFESPAN
                reasoning = (
                    f"Cookie '{cookie_name}' is declared in documentation but has an excessive "
                    f"observed lifespan of {observed_days:.1f} days (exceeds 90-day threshold)."
                )
            elif matched_declared:
                classification = StorageClassificationType.DOCUMENTED
                reasoning = f"Cookie '{cookie_name}' matches declared storage item '{matched_declared.name}'."
            else:
                classification = StorageClassificationType.UNDOCUMENTED
                reasoning = (
                    f"Cookie '{cookie_name}' was observed in network traffic but is not disclosed in the "
                    "privacy/cookie policy documentation."
                )

            result_fields = {
                "name": cookie_name,
                "domains": sorted(cookie_domains.get(cookie_name, set())),
                "cookie_domain_attributes": sorted(cookie_domain_attributes.get(cookie_name, set())),
                "storage_type": StorageTechnologyType.COOKIE,
                "observed_lifespan_days": observed_days,
                "classification": classification,
                "reasoning": reasoning,
                "declared_match": matched_declared,
                **consent_context,
            }
            if matched_declared:
                result_fields.update(
                    declared_provider=matched_declared.provider,
                    declared_purpose=matched_declared.purpose,
                    declared_lifespan=matched_declared.stated_lifespan,
                    policy_quote=matched_declared.citation_excerpt,
                )
            results.append(StorageClassificationResult(**result_fields))
            logger.debug(
                "Storage decision: name=%s classification=%s observed_days=%s declared=%s",
                cookie_name,
                classification.value,
                observed_days,
                matched_declared.name if matched_declared else None,
            )

        logger.debug("Storage profiling complete: results=%d", len(results))
        return results
