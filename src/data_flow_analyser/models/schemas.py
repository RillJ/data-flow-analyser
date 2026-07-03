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


class PolicyStatement(BaseModel):
    """Structured extraction of claims from vendor DPAs / Cookie Policies."""

    vendor_name: str
    declared_domains: List[str] = Field(default_factory=list)
    declared_subprocessors: List[str] = Field(default_factory=list)
    declared_cookie_names: List[str] = Field(default_factory=list)
    stated_purposes: List[str] = Field(default_factory=list)


class RiskComponents(BaseModel):
    """Individual normalized factors contributing to a network flow risk score."""

    data_sensitivity_score: float = Field(ge=0.0, le=10.0, description="S(D_personal_data)")
    subprocessor_status_score: float = Field(ge=0.0, le=10.0, description="P(E_sub)")
    tracker_category_score: float = Field(ge=0.0, le=10.0, description="T(C_track)")


class PrivacyDiscrepancy(BaseModel):
    """A documented mismatch between observed behavior and privacy expectations."""

    flow_id: str
    discrepancy_type: str
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    evidence: str
    risk_score: float = Field(
        ge=0.0,
        le=10.0,
        description="Calculated R_flow score.",
    )
    components: RiskComponents


class TrackingToken(BaseModel):
    """Represents a high-entropy string candidate flagged as a dynamic identifier."""

    token: str
    location: str  # example: "cookies_sent.session_id", "request_body.meta.visitor_id"
    entropy: float
    is_high_entropy: bool = True
    occurrences: int = 1


class SeedMatchEvidence(BaseModel):
    """A controlled-value match found in captured traffic."""

    matched_value: str
    field_type: str
    location: str
    host: Optional[str] = None


class ConsentPhase(str, Enum):
    """Consent state inferred from user-supplied capture timestamps."""

    UNKNOWN = "unknown"
    PRE_CONSENT = "pre_consent"
    CONSENTED = "consented"
    WITHDRAWN = "withdrawn"


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


class CookieLongevityResult(BaseModel):
    """Represents cookie lifespan analysis from Set-Cookie headers."""

    cookie_name: str
    cookie_value: str
    max_age_seconds: Optional[int] = None
    expires_at: Optional[datetime] = None
    lifespan_days: Optional[float] = None
    is_excessive_longevity: bool = False  # True if > 90 days.


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
    examples_given: List[str] = []
    citation_excerpt: str  # Verbatim quote from policy for human-in-the-loop verification


class DeclaredSubprocessor(BaseModel):
    """Represents a third party or subprocessor disclosed in the policy or DPA."""

    name: str
    domain_or_host: Optional[str] = None
    purpose: Optional[str] = None
    country_or_location: Optional[str] = None
    citation_excerpt: Optional[str] = None


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
    DOCUMENTED = "documented"
    UNDOCUMENTED = "undocumented"
    EXCESSIVE_LIFESPAN = "excessive_lifespan"
    PURPOSE_MISMATCH = "purpose_mismatch"


class StorageClassificationResult(BaseModel):
    """Reconciled evaluation of an observed client-side storage mechanism or cookie against declared policies."""

    name: str
    storage_type: StorageTechnologyType = StorageTechnologyType.COOKIE
    observed_lifespan_days: Optional[float] = None
    classification: StorageClassificationType
    reasoning: str
    declared_match: Optional[DeclaredStorageItem] = None


class DocumentAnalysisResult(BaseModel):
    """Structured legal audit extractions from Privacy Policies, DPAs, or Cookie Policies."""

    document_title: str
    declared_categories: List[DeclaredDataCategory] = []
    declared_subprocessors: List[DeclaredSubprocessor] = []
    declared_storage_items: List[DeclaredStorageItem] = []
    international_transfer_mechanisms: List[str] = []
    stated_retention_summary: Optional[str] = None
    raw_document_length: int = 0


class EndpointClassificationType(str, Enum):
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


class DiscrepancyCategory(str, Enum):
    UNDOCUMENTED_ENDPOINT = "undocumented_endpoint"
    UNANNOUNCED_DATA_COLLECTION = "unannounced_data_collection"
    PURPOSE_MISMATCH = "purpose_mismatch"
    STORAGE_LIFESPAN_EXCESSIVE = "storage_lifespan_excessive"
    UNANNOUNCED_STORAGE = "unannounced_storage"
    UNSAFE_THIRD_COUNTRY_TRANSFER = "unsafe_third_country_transfer"
    PLAINTEXT_PERSONAL_DATA_LEAK = "plaintext_personal_data_leak"
    FINGERPRINTING_CANDIDATE = "fingerprinting_candidate"
    FINGERPRINTING_AFTER_WITHDRAWAL = "fingerprinting_after_withdrawal"


class DiscrepancySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ComplianceDiscrepancy(BaseModel):
    """Represents a specific compliance discrepancy card for human audit review."""

    discrepancy_id: str
    title: str
    category: DiscrepancyCategory
    severity: DiscrepancySeverity
    observed_evidence: str  # example: "Plaintext email sent to api.mixpanel.com (US, IP 142.250.179.196)"
    declared_claim_quote: Optional[str] = None  # exact verbatim quote from policy or "Not declared"


class FullAuditReport(BaseModel):
    """Complete AI-assisted technical privacy audit report."""

    audit_title: str
    summary: str
    endpoint_classifications: List[EndpointClassificationResult] = []
    storage_classifications: List[StorageClassificationResult] = []
    fingerprint_vectors: List[FingerprintVector] = []
    fingerprint_persistence_findings: List[FingerprintPersistenceFinding] = []
    fingerprint_summary: FingerprintAnalysisSummary = Field(default_factory=FingerprintAnalysisSummary)
    observed_endpoints: List[ObservedEndpoint] = []
    tracking_tokens: List[TrackingToken] = []
    cookie_longevity_results: List[CookieLongevityResult] = []
    seed_matches: List[SeedMatchEvidence] = []
    discrepancies: List[ComplianceDiscrepancy] = []
    total_flows_analyzed: int = 0
    total_discrepancies_found: int = 0
    requires_human_verification: bool = True
