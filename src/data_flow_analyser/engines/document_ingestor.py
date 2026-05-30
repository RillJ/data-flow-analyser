import json
from typing import Optional, cast
from litellm import ModelResponse, completion

from data_flow_analyser.models.schemas import (
    DataCategoryType,
    DeclaredDataCategory,
    DeclaredStorageItem,
    DeclaredSubprocessor,
    DocumentAnalysisResult,
    StorageTechnologyType,
)

SYSTEM_PROMPT = """
You are an expert Privacy Legal Auditor conducting a Data Protection Impact Assessment (DPIA).
Your task is to analyse the provided Privacy Policy, Cookie Policy, or Data Processing Agreement (DPA) and extract structured compliance claims.

1. DATA CATEGORIES: Map all declared personal data collection into these EXACT 6 categories:
   - content_data: Primary data users enter or generate in the system.
   - diagnostic_data: Data collected for troubleshooting, telemetry, and system optimisation.
   - account_data: Information related to user accounts, credentials, and authentication.
   - support_data: Data collected during customer support or helpdesk tickets.
   - website_data: Information collected via cookies, scripts, or analytics on the vendor's site.
   - feedback_data: Data obtained from user surveys and direct feedback.

2. SUBPROCESSORS: Extract all listed third-party vendors, subprocessors, or analytics providers.

3. COOKIES & STORAGE MECHANISMS: Extract all disclosed cookies, HTML5 local_storage keys, session_storage, tracking pixels/beacons, or IndexedDB storage mechanisms mentioned. Capture their name, storage type, provider, purpose, and declared lifespan.

For EVERY claim, subprocessor, and storage item, include a concise `citation_excerpt` containing the exact verbatim quote from the text.

Respond ONLY with a single valid JSON object matching this schema:
{
  "document_title": "Title or main header of document",
  "declared_categories": [
    {
      "category": "content_data|diagnostic_data|account_data|support_data|website_data|feedback_data|other",
      "description": "Explanation of what is collected and why",
      "examples_given": ["email", "file uploads"],
      "citation_excerpt": "Exact text quote from policy"
    }
  ],
  "declared_subprocessors": [
    {
      "name": "Subprocessor or vendor name",
      "domain_or_host": "domain or URL if mentioned, else null",
      "purpose": "Declared processing purpose",
      "country_or_location": "Country or EU/US transfer location if stated",
      "citation_excerpt": "Exact text quote"
    }
  ],
  "declared_storage_items": [
    {
      "name": "Cookie name or storage key (like: _ga, auth_token, _fbp)",
      "storage_type": "cookie|local_storage|session_storage|pixel_beacon|indexed_db|other",
      "provider": "First-party or vendor name (like: Google Analytics)",
      "purpose": "Essential|Analytics|Advertising|Functional",
      "stated_lifespan": "Declared lifespan (like: 2 years, Session, 90 days)",
      "citation_excerpt": "Exact text quote from policy"
    }
  ],
  "international_transfer_mechanisms": ["Standard Contractual Clauses (SCCs)", "EU-US Data Privacy Framework"],
  "stated_retention_summary": "Summary of declared storage limitation or cookie expiration terms"
}
"""


class PolicyDocumentIngestor:
    """
    Ingests vendor legal documents (Privacy Policies, Cookie Policies, DPAs) using LiteLLM
    to extract structured compliance claims, subprocessors, and declared storage mechanisms.
    """

    def __init__(
        self,
        model: str = "gpt-5.4-mini",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
    ):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base

    def analyze_document_text(
        self,
        text_content: str,
        document_title: str = "Vendor Legal Document"
    ) -> DocumentAnalysisResult:
        if not text_content.strip():
            return DocumentAnalysisResult(document_title=document_title)

        try:
            # Cast completion output to ModelResponse so Pyright knows choices exists
            response = cast(
                ModelResponse,
                completion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": f"Document Title: {document_title}\n\nDocument Text:\n{text_content[:25000]}"
                        }
                    ],
                    response_format={"type": "json_object"},
                    api_key=self.api_key,
                    api_base=self.api_base,
                )
            )

            # Defensive validation check
            if not response.choices or not response.choices[0].message:
                return DocumentAnalysisResult(
                    document_title=document_title,
                    raw_document_length=len(text_content)
                )

            raw_json_str: Optional[str] = response.choices[0].message.content

            # Type guard: make sure raw_json_str is a valid str before calling _parse_llm_json
            if not raw_json_str:
                return DocumentAnalysisResult(
                    document_title=document_title,
                    raw_document_length=len(text_content)
                )

            return self._parse_llm_json(raw_json_str, document_title, len(text_content))

        except Exception as e:
            print(f"[Warning] LiteLLM document extraction failed ({self.model}): {e}")
            return DocumentAnalysisResult(
                document_title=document_title,
                raw_document_length=len(text_content)
            )

    def _parse_llm_json(
        self,
        raw_json_str: str,
        document_title: str,
        raw_length: int
    ) -> DocumentAnalysisResult:
        """Parses and validates LLM JSON response into Pydantic models."""
        try:
            data = json.loads(raw_json_str)

            # Parse data categories
            categories = []
            for item in data.get("declared_categories", []):
                cat_type_str = item.get("category", "other").lower()
                try:
                    cat_type = DataCategoryType(cat_type_str)
                except ValueError:
                    cat_type = DataCategoryType.OTHER

                categories.append(
                    DeclaredDataCategory(
                        category=cat_type,
                        description=item.get("description", ""),
                        examples_given=item.get("examples_given", []),
                        citation_excerpt=item.get("citation_excerpt", "")
                    )
                )

            # Parse declared subprocessors
            subprocessors = []
            for sub in data.get("declared_subprocessors", []):
                subprocessors.append(
                    DeclaredSubprocessor(
                        name=sub.get("name", "Unknown"),
                        domain_or_host=sub.get("domain_or_host"),
                        purpose=sub.get("purpose"),
                        country_or_location=sub.get("country_or_location"),
                        citation_excerpt=sub.get("citation_excerpt")
                    )
                )

            # Parse declared storage items
            storage_items = []
            for item in data.get("declared_storage_items", []):
                st_type_str = item.get("storage_type", "cookie").lower()
                try:
                    st_type = StorageTechnologyType(st_type_str)
                except ValueError:
                    st_type = StorageTechnologyType.COOKIE

                storage_items.append(
                    DeclaredStorageItem(
                        name=item.get("name", "Unknown"),
                        storage_type=st_type,
                        provider=item.get("provider"),
                        purpose=item.get("purpose"),
                        stated_lifespan=item.get("stated_lifespan"),
                        citation_excerpt=item.get("citation_excerpt")
                    )
                )

            return DocumentAnalysisResult(
                document_title=data.get("document_title", document_title),
                declared_categories=categories,
                declared_subprocessors=subprocessors,
                declared_storage_items=storage_items,
                international_transfer_mechanisms=data.get("international_transfer_mechanisms", []),
                stated_retention_summary=data.get("stated_retention_summary"),
                raw_document_length=raw_length,
            )

        except (json.JSONDecodeError, KeyError, TypeError):
            return DocumentAnalysisResult(document_title=document_title, raw_document_length=raw_length)