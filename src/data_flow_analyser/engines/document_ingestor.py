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

import json
import logging
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

logger = logging.getLogger(__name__)


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
        model: str = "gpt-5.6-luna",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        temperature: float = 1.0,
    ):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.temperature = temperature

    def analyse_document_text(
        self,
        text_content: str,
        document_title: str = "Vendor Legal Document"
    ) -> DocumentAnalysisResult:
        logger.debug("Document ingestion started: title=%s chars=%d model=%s", document_title, len(text_content), self.model)
        if not text_content.strip():
            logger.debug("Document ingestion skipped: empty document")
            return DocumentAnalysisResult(
                document_title=document_title,
                analysis_status="partial",
                warnings=["The supplied document text was empty."],
            )

        try:
            user_prompt = (
                f"Document Title: {document_title}\n\n"
                f"Document Text:\n{text_content}"
            )
            logger.debug(
                "LLM request (document_ingestor) BEGIN: model=%s messages=2 response_format=json_object",
                self.model,
            )
            logger.debug("LLM request (document_ingestor) system prompt:\n%s", SYSTEM_PROMPT)
            logger.debug("LLM request (document_ingestor) user prompt:\n%s", user_prompt)
            logger.debug("LLM request (document_ingestor) END")
            # Cast completion output to ModelResponse so Pyright knows choices exists
            response = cast(
                ModelResponse,
                completion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=self.temperature,
                    api_key=self.api_key,
                    api_base=self.api_base,
                )
            )
            logger.debug("Document LLM response received: choices=%d", len(response.choices or []))

            # Defensive validation check
            if not response.choices or not response.choices[0].message:
                return DocumentAnalysisResult(
                    document_title=document_title,
                    raw_document_length=len(text_content),
                    analysis_status="failed",
                    warnings=["The document LLM returned no response choices."],
                )

            raw_json_str: Optional[str] = response.choices[0].message.content

            # Type guard: make sure raw_json_str is a valid str before calling _parse_llm_json
            if not raw_json_str:
                return DocumentAnalysisResult(
                    document_title=document_title,
                    raw_document_length=len(text_content),
                    analysis_status="failed",
                    warnings=["The document LLM returned an empty response."],
                )

            result = self._parse_llm_json(raw_json_str, document_title, len(text_content))
            logger.debug("Document analysis parsed: categories=%d subprocessors=%d storage_items=%d", len(result.declared_categories), len(result.declared_subprocessors), len(result.declared_storage_items))
            return result

        except Exception as e:
            logger.exception("Document extraction failed: model=%s error=%s", self.model, e)
            result = DocumentAnalysisResult(
                document_title=document_title,
                raw_document_length=len(text_content),
                analysis_status="failed",
                warnings=[f"Document LLM execution failed: {type(e).__name__}"],
            )
            logger.debug(
                "Document analysis failed: status=%s warnings=%s",
                result.analysis_status,
                result.warnings,
            )
            return result

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

        except (json.JSONDecodeError, KeyError, TypeError) as error:
            logger.warning("Document JSON parsing fallback: title=%s error=%s", document_title, error)
            return DocumentAnalysisResult(document_title=document_title, raw_document_length=raw_length)
