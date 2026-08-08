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

from datetime import datetime
from enum import Enum
from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Core captured traffic and test-data models
# ---------------------------------------------------------------------------

class NetworkFlow(BaseModel):
    """A parsed HTTP(S) transaction evaluated during the assessment."""

    flow_id: str = Field(description="UUID identifying this network flow.")
    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    cookies_sent: Dict[str, str] = Field(default_factory=dict)
    cookies_set: Dict[str, str] = Field(default_factory=dict)
    cookies_set_domain_attributes: Dict[str, str] = Field(default_factory=dict)


class SeedData(BaseModel):
    """Injected test data and lookup hashes used to identify exposed personal data values."""

    raw_values: Dict[str, str] = Field(default_factory=dict)
    hash_map: Dict[str, str] = Field(default_factory=dict)


class ObservedEndpoint(BaseModel):
    """A network destination with entity profiling and geolocation."""

    domain: str
    ip_address: Optional[str] = None
    reverse_dns: Optional[str] = None
    parent_entity: Optional[str] = None  # like: "Google LLC"
    category: str = "unknown"  # like: "internal", "subprocessor", "third_party_tracker", "unknown"
    country_code: Optional[str] = None  # like: "US", "NL", "DE"
    asn_org: Optional[str] = None  # like: "Amazon.com, Inc.", "Cloudflare, Inc."
    is_third_country_transfer: bool = False  # Flagged if traffic leaves origin country
    is_undocumented: bool = False


class ConsentPhase(str, Enum):
    """Consent state inferred from user-supplied capture metadata."""

    UNKNOWN = "unknown"
    PRE_CONSENT = "pre_consent"
    POST_DECISION_NECESSARY_ONLY = "post_decision_necessary_only"
    FULL_CONSENT = "full_consent"
    WITHDRAWN = "withdrawn"


class ConsentOutcome(str, Enum):
    """Outcome of the consent-banner decision for non-essential processing."""

    NECESSARY_ONLY = "necessary_only"
    NON_ESSENTIAL_GRANTED = "non_essential_granted"


class PersonalDataFlowEvidence(BaseModel):
    """Grouped personal-data evidence with flow IDs retained for reproduction."""

    endpoint: str
    direction: Literal["request", "response"]
    location: str
    data_label: str
    sample_value: str
    matched_values: List[str] = Field(default_factory=list)
    detection_method: Literal["seed_match", "presidio"] = "seed_match"
    count: int = Field(ge=1)
    flow_ids: List[str] = Field(default_factory=list)
    cookies_sent: Dict[str, str] = Field(default_factory=dict)
    cookies_by_flow: Dict[str, Dict[str, str]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Browser and device fingerprinting models
# ---------------------------------------------------------------------------

class FingerprintAttribute(BaseModel):
    """One request value mapped to a browser/device fingerprinting category."""

    category: str
    key: str
    value: str
    location: str


class FingerprintVector(BaseModel):
    """Candidate browser/device fingerprint vector observed in one network flow."""

    flow_id: str
    endpoint: str
    consent_phase: ConsentPhase = ConsentPhase.UNKNOWN
    matched_categories: List[str] = Field(default_factory=list)
    attributes: List[FingerprintAttribute] = Field(default_factory=list)
    payload_locations: List[str] = Field(default_factory=list)
    attribute_count: int = 0
    heuristic_score: float = 0.0
    is_candidate: bool = False
    signature: str
    scoring_method: str = "attribute co-occurrence heuristic; no population-frequency baseline configured"


class FingerprintPersistenceFinding(BaseModel):
    """Cross-flow observation of an identical candidate vector across consent phases."""

    endpoint: str
    signature: str
    observed_phases: List[ConsentPhase] = Field(default_factory=list)
    flow_ids: List[str] = Field(default_factory=list)
    observed_before_consent: bool = False
    observed_after_full_consent: bool = False
    persists_after_full_consent: bool = False
    observed_after_necessary_only: bool = False
    persists_after_necessary_only: bool = False
    observed_after_withdrawal: bool = False
    persists_after_withdrawal: bool = False
    reasoning: str


class FingerprintAnalysisSummary(BaseModel):
    """Aggregate statistics for the fingerprint profiler."""

    total_vectors: int = 0
    candidate_vectors: int = 0
    categories_observed: Dict[str, int] = Field(default_factory=dict)
    consent_phases: Dict[str, int] = Field(default_factory=dict)
    persistence_findings: int = 0
    maximum_heuristic_score: float = 0.0
    candidate_rule: str = "4+ categories, or a canvas/audio/WebGL category plus another category"
    scoring_method: str = "attribute co-occurrence heuristic; no population-frequency baseline configured"


# ---------------------------------------------------------------------------
# Cookie and storage profiling models
# ---------------------------------------------------------------------------

class CookieLongevityResult(BaseModel):
    """Represents cookie lifespan analysis from Set-Cookie headers."""

    cookie_name: str
    cookie_value: str
    max_age_seconds: Optional[int] = None
    expires_at: Optional[datetime] = None
    lifespan_days: Optional[float] = None


# ---------------------------------------------------------------------------
# Policy-document extraction models
# ---------------------------------------------------------------------------

class DataCategoryType(str, Enum):
    CONTENT_DATA = "content_data"
    DIAGNOSTIC_DATA = "diagnostic_data"
    ACCOUNT_DATA = "account_data"
    SUPPORT_DATA = "support_data"
    WEBSITE_DATA = "website_data"
    FEEDBACK_DATA = "feedback_data"
    OTHER = "other"


class DeclaredDataCategory(BaseModel):
    """Represents a specific category of personal data declared in vendor documents."""

    category: DataCategoryType
    description: str
    examples_given: List[str] = Field(default_factory=list)
    citation_excerpt: str  # Verbatim quote from policy for human-in-the-loop verification


class DeclaredSubprocessor(BaseModel):
    """Represents a third party or subprocessor disclosed in the policy or DPA."""

    name: str
    domain_or_host: Optional[str] = None
    purpose: Optional[str] = None
    country_or_location: Optional[str] = None
    citation_excerpt: Optional[str] = None


# ---------------------------------------------------------------------------
# Storage declarations and rule-based classifications
# ---------------------------------------------------------------------------

class StorageTechnologyType(str, Enum):
    COOKIE = "cookie"
    LOCAL_STORAGE = "local_storage"
    SESSION_STORAGE = "session_storage"
    PIXEL_BEACON = "pixel_beacon"
    INDEXED_DB = "indexed_db"
    OTHER = "other"


class DeclaredStorageItem(BaseModel):
    """
    Represents a cookie, local storage key, pixel, or other client-side storage technology
    disclosed in Cookie Policies or Privacy Policies.
    """

    name: str  # example: "_ga", "session_token", "user_preferences"
    storage_type: StorageTechnologyType = StorageTechnologyType.COOKIE
    provider: Optional[str] = None  # example: "Google Analytics", "First-Party"
    purpose: Optional[str] = None  # example: "Analytics", "Strictly Necessary", "Advertising"
    stated_lifespan: Optional[str] = None  # example: "2 years", "Session", "90 days"
    citation_excerpt: Optional[str] = None  # Verbatim quote from policy for audit verification


class StorageClassificationType(str, Enum):
    UNKNOWN = "unknown"
    DOCUMENTED = "documented"
    UNDOCUMENTED = "undocumented"
    EXCESSIVE_LIFESPAN = "excessive_lifespan"
    PURPOSE_MISMATCH = "purpose_mismatch"


class StorageClassificationResult(BaseModel):
    """Reconciled evaluation of an observed client-side storage mechanism or cookie against declared policies."""

    name: str
    domains: List[str] = Field(default_factory=list)
    cookie_domain_attributes: List[str] = Field(default_factory=list)
    storage_type: StorageTechnologyType = StorageTechnologyType.COOKIE
    observed_lifespan_days: Optional[float] = None
    classification: StorageClassificationType
    reasoning: str
    declared_match: Optional[DeclaredStorageItem] = None
    declared_provider: Optional[str] = None
    declared_purpose: Optional[str] = None
    declared_lifespan: Optional[str] = None
    policy_quote: Optional[str] = None
    first_observed_phase: ConsentPhase = ConsentPhase.UNKNOWN
    first_observed_flow_id: Optional[str] = None
    first_observed_at: Optional[datetime] = None


class DocumentAnalysisResult(BaseModel):
    """Structured legal audit extractions from Privacy Policies, DPAs, or Cookie Policies."""

    document_title: str
    declared_categories: List[DeclaredDataCategory] = Field(default_factory=list)
    declared_subprocessors: List[DeclaredSubprocessor] = Field(default_factory=list)
    declared_storage_items: List[DeclaredStorageItem] = Field(default_factory=list)
    international_transfer_mechanisms: List[str] = Field(default_factory=list)
    stated_retention_summary: Optional[str] = None
    raw_document_length: int = 0
    analysis_status: Literal["complete", "partial", "failed"] = "complete"
    warnings: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoint and policy classification models
# ---------------------------------------------------------------------------

class EndpointClassificationType(str, Enum):
    UNKNOWN = "unknown"
    INTERNAL = "internal"
    DOCUMENTED_SUBPROCESSOR = "documented_subprocessor"
    UNDOCUMENTED_THIRD_PARTY = "undocumented_third_party"
    TRACKER_UNCONSENTED = "tracker_unconsented"


class EndpointClassificationResult(BaseModel):
    """Classification of an observed network host relative to vendor documentation."""

    domain: str
    classification: EndpointClassificationType
    reasoning: str
    citation_excerpt: Optional[str] = None  # quote from DPA/Policy if documented


# ---------------------------------------------------------------------------
# Deterministic ICO-style risk assessment and final report models
# ---------------------------------------------------------------------------

class DiscrepancyCategory(str, Enum):
    UNDOCUMENTED_ENDPOINT = "undocumented_endpoint"
    UNANNOUNCED_DATA_COLLECTION = "unannounced_data_collection"
    PURPOSE_MISMATCH = "purpose_mismatch"
    STORAGE_LIFESPAN_EXCESSIVE = "storage_lifespan_excessive"
    UNANNOUNCED_STORAGE = "unannounced_storage"
    STORAGE_BEFORE_CONSENT = "storage_before_consent"
    STORAGE_AFTER_NECESSARY_ONLY = "storage_after_necessary_only"
    STORAGE_AFTER_WITHDRAWAL = "storage_after_withdrawal"
    UNSAFE_THIRD_COUNTRY_TRANSFER = "unsafe_third_country_transfer"
    PLAINTEXT_PERSONAL_DATA_LEAK = "plaintext_personal_data_leak"
    FINGERPRINTING_CANDIDATE = "fingerprinting_candidate"
    FINGERPRINTING_BEFORE_CONSENT = "fingerprinting_before_consent"
    FINGERPRINTING_AFTER_NECESSARY_ONLY = "fingerprinting_after_necessary_only"
    FINGERPRINTING_AFTER_FULL_CONSENT = "fingerprinting_after_full_consent"
    FINGERPRINTING_AFTER_WITHDRAWAL = "fingerprinting_after_withdrawal"


class HarmLikelihood(str, Enum):
    REMOTE = "remote"
    REASONABLE_POSSIBILITY = "reasonable_possibility"
    MORE_LIKELY_THAN_NOT = "more_likely_than_not"

    @property
    def score(self) -> int:
        return list(type(self)).index(self) + 1


class ImpactSeverity(str, Enum):
    MINIMAL_IMPACT = "minimal_impact"
    SOME_IMPACT = "some_impact"
    SERIOUS_HARM = "serious_harm"

    @property
    def score(self) -> int:
        return list(type(self)).index(self) + 1


class IndicativeRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskAssessment(BaseModel):
    likelihood: HarmLikelihood
    severity_impact: ImpactSeverity
    risk_score: int = Field(ge=1, le=9)
    indicative_level: IndicativeRiskLevel
    potential_harms: List[str] = Field(default_factory=list)
    assessment_basis: str = ""
    human_verification_required: bool = True


class ComplianceDiscrepancy(BaseModel):
    """Represents a specific compliance discrepancy card for human audit review."""

    discrepancy_id: str
    title: str
    category: DiscrepancyCategory
    risk_assessment: RiskAssessment
    observed_evidence: str  # example: "Plaintext email sent to api.mixpanel.com (US, IP 142.250.179.196)"
    declared_claim_quote: Optional[str] = None  # exact verbatim quote from policy or "Not declared"
    evidence_references: List[str] = Field(default_factory=list)


class AnalysisProvenance(BaseModel):
    """Reproducibility metadata for one analysis execution."""

    tool_version: str = "unknown"
    model: Optional[str] = None
    api_base: Optional[str] = None
    temperature: Optional[float] = None
    analysis_started_at: Optional[datetime] = None
    analysis_finished_at: Optional[datetime] = None
    reference_time: Optional[datetime] = None
    input_hashes: Dict[str, str] = Field(default_factory=dict)
    excluded_domains: List[str] = Field(default_factory=list)
    external_metadata_mode: str = "live_network_lookups"


class FullAuditReport(BaseModel):
    """Complete AI-assisted technical privacy audit report."""

    audit_title: str
    summary: str
    endpoint_classifications: List[EndpointClassificationResult] = Field(default_factory=list)
    storage_classifications: List[StorageClassificationResult] = Field(default_factory=list)
    fingerprint_vectors: List[FingerprintVector] = Field(default_factory=list)
    fingerprint_persistence_findings: List[FingerprintPersistenceFinding] = Field(default_factory=list)
    fingerprint_summary: FingerprintAnalysisSummary = Field(default_factory=FingerprintAnalysisSummary)
    observed_endpoints: List[ObservedEndpoint] = Field(default_factory=list)
    cookie_longevity_results: List[CookieLongevityResult] = Field(default_factory=list)
    personal_data_flows: List[PersonalDataFlowEvidence] = Field(default_factory=list)
    discrepancies: List[ComplianceDiscrepancy] = Field(default_factory=list)
    total_flows_analysed: int = 0
    total_discrepancies_found: int = 0
    analysis_status: Literal["complete", "partial", "failed"] = "complete"
    warnings: List[str] = Field(default_factory=list)
    provenance: AnalysisProvenance = Field(default_factory=AnalysisProvenance)
