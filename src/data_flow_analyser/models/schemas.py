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
    """A network destination observed during the assessment."""

    domain: str
    ip_address: Optional[str] = None
    parent_entity: Optional[str] = None
    category: Literal["internal", "subprocessor", "third_party", "unknown"]
    is_undocumented: bool = False


class PolicyStatement(BaseModel):
    """Structured extraction of claims from vendor DPAs / Cookie Policies."""

    vendor_name: str
    declared_domains: List[str] = Field(default_factory=list)
    declared_subprocessors: List[str] = Field(default_factory=list)
    declared_cookie_names: List[str] = Field(default_factory=list)
    stated_purposes: List[str] = Field(default_factory=list)


class RiskComponents(BaseModel):
    """Individual normalised factors contributing to a network flow risk score."""

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
