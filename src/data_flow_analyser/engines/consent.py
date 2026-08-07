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

"""Shared consent-phase classification for flow-based analysers."""

from datetime import datetime
from typing import Optional

from data_flow_analyser.models.schemas import ConsentOutcome, ConsentPhase


def classify_consent_phase(
    timestamp: datetime,
    consent_decided_at: Optional[datetime] = None,
    consent_withdrawn_at: Optional[datetime] = None,
    consent_outcome: ConsentOutcome = ConsentOutcome.NECESSARY_ONLY,
) -> ConsentPhase:
    """Assign a flow to a phase using optional consent-banner metadata."""
    if consent_withdrawn_at and timestamp >= consent_withdrawn_at:
        return ConsentPhase.WITHDRAWN
    if consent_decided_at:
        if timestamp < consent_decided_at:
            return ConsentPhase.PRE_CONSENT
        if consent_outcome == ConsentOutcome.NON_ESSENTIAL_GRANTED:
            return ConsentPhase.FULL_CONSENT
        return ConsentPhase.POST_DECISION_NECESSARY_ONLY
    return ConsentPhase.UNKNOWN
