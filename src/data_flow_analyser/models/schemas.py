"""Pydantic schemas shared by Data Flow Analyser engine components."""

from datetime import datetime
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
    """Injected test data and lookup hashes used to identify exposed values."""

    raw_values: Dict[str, str] = Field(default_factory=dict)
    hash_map: Dict[str, str] = Field(default_factory=dict)


class ObservedEndpoint(BaseModel):
    """A network destination with entity profiling and geolocation."""
    domain: str
    ip_address: Optional[str] = None
    reverse_dns: Optional[str] = None
    parent_entity: Optional[str] = None   # like: "Google LLC"
    category: str = "unknown"             # like: "internal", "subprocessor", "third_party_tracker", "unknown"
    country_code: Optional[str] = None    # like: "US", "NL", "DE"
    asn_org: Optional[str] = None         # like: "Amazon.com, Inc.", "Cloudflare, Inc."
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
    """Individual normalied factors contributing to a network flow risk score."""

    data_sensitivity_score: float = Field(ge=0.0, le=10.0, description="S(D_pii)")
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


class CookieLongevityResult(BaseModel):
    """Represents cookie lifespan analysis from Set-Cookie headers."""
    cookie_name: str
    cookie_value: str
    max_age_seconds: Optional[int] = None
    expires_at: Optional[datetime] = None
    lifespan_days: Optional[float] = None
    is_excessive_longevity: bool = False  # True if > 90 days.
    # While EU regulations do not prescribe a universal numeric cap on cookie lifespans,
    # GDPR Art. 5(1)(e) mandates storage limitation proportional to purpose.
    # National DPAs (like from CNIL, Irish DPC) recommend maximum cookie retention windows
    # ranging from 6 to 13 months. My scanner applies a conservative heuristic threshold
    # of 90 days (7,776,000 seconds) to flag non-essential tracking cookies
    # with excessive persistence relative to temporary session/campaign tracking.