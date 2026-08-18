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

from data_flow_analyser.engines.risk_evaluator import assess_risk, indicative_level
from data_flow_analyser.models.schemas import (
    HarmLikelihood,
    ImpactSeverity,
    IndicativeRiskLevel,
)


def test_ico_matrix_levels_for_all_combinations():
    expected = (
        (IndicativeRiskLevel.LOW, IndicativeRiskLevel.LOW, IndicativeRiskLevel.LOW),
        (IndicativeRiskLevel.LOW, IndicativeRiskLevel.MEDIUM, IndicativeRiskLevel.HIGH),
        (IndicativeRiskLevel.LOW, IndicativeRiskLevel.HIGH, IndicativeRiskLevel.HIGH),
    )

    for likelihood in HarmLikelihood:
        for severity in ImpactSeverity:
            assert indicative_level(likelihood, severity) == expected[
                likelihood.score - 1
            ][severity.score - 1]


def test_assessment_calculates_score_and_preserves_evidence():
    assessment = assess_risk(
        HarmLikelihood.REASONABLE_POSSIBILITY,
        ImpactSeverity.SERIOUS_HARM,
        potential_harms=["loss_of_control", "loss_of_confidentiality"],
        assessment_basis="An undocumented endpoint receives an account identifier.",
    )

    assert assessment.risk_score == 6
    assert assessment.indicative_level == IndicativeRiskLevel.HIGH
    assert assessment.potential_harms == ["loss_of_control", "loss_of_confidentiality"]
    assert assessment.assessment_basis.startswith("An undocumented endpoint")
    assert assessment.human_verification_required is True


def test_remote_minimal_impact_is_low():
    assessment = assess_risk(
        HarmLikelihood.REMOTE,
        ImpactSeverity.MINIMAL_IMPACT,
    )

    assert assessment.risk_score == 1
    assert assessment.indicative_level == IndicativeRiskLevel.LOW
