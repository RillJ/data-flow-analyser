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

from data_flow_analyser.models.schemas import (
    HarmLikelihood,
    ImpactSeverity,
    IndicativeRiskLevel,
    RiskAssessment,
)


def indicative_level(likelihood: HarmLikelihood, severity: ImpactSeverity) -> IndicativeRiskLevel:
    # ICO-style matrix: only 2x2 is medium; 2x3 and 3x2/3x3 are high.
    if likelihood.score >= 2 and severity.score >= 2:
        return IndicativeRiskLevel.MEDIUM if (likelihood.score, severity.score) == (2, 2) else IndicativeRiskLevel.HIGH
    return IndicativeRiskLevel.LOW


def assess_risk(
    likelihood: HarmLikelihood,
    severity: ImpactSeverity,
    potential_harms: list[str] | None = None,
    assessment_basis: str = "",
) -> RiskAssessment:
    return RiskAssessment(
        likelihood=likelihood,
        severity_impact=severity,
        risk_score=likelihood.score * severity.score,
        indicative_level=indicative_level(likelihood, severity),
        potential_harms=potential_harms or [],
        assessment_basis=assessment_basis,
        human_verification_required=True,
    )
