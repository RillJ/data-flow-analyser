from data_flow_analyser.engines.document_ingestor import PolicyDocumentIngestor
from data_flow_analyser.models.schemas import DataCategoryType, StorageTechnologyType


def test_parse_llm_json_response_with_storage_items():
    ingestor = PolicyDocumentIngestor()

    sample_llm_output = """
    {
      "document_title": "ACME Cookie Policy",
      "declared_categories": [
        {
          "category": "website_data",
          "description": "Cookies used for site analytics",
          "examples_given": ["_ga", "_gid"],
          "citation_excerpt": "We use analytics cookies to understand visitor interactions."
        }
      ],
      "declared_subprocessors": [
        {
          "name": "Google Analytics",
          "domain_or_host": "google-analytics.com",
          "purpose": "Website usage analytics",
          "citation_excerpt": "Google Analytics provides visitor insights."
        }
      ],
      "declared_storage_items": [
        {
          "name": "_ga",
          "storage_type": "cookie",
          "provider": "Google Analytics",
          "purpose": "Analytics",
          "stated_lifespan": "2 years",
          "citation_excerpt": "_ga cookie persists for 2 years to distinguish unique users."
        },
        {
          "name": "app_user_settings",
          "storage_type": "local_storage",
          "provider": "First-Party",
          "purpose": "Functional UI state",
          "stated_lifespan": "Persistent",
          "citation_excerpt": "We store user UI themes in HTML5 LocalStorage."
        }
      ],
      "international_transfer_mechanisms": ["EU-US Data Privacy Framework"],
      "stated_retention_summary": "Analytics cookies expire after 24 months."
    }
    """

    result = ingestor._parse_llm_json(sample_llm_output, "Cookie Policy", 1200)

    assert result.document_title == "ACME Cookie Policy"
    assert len(result.declared_storage_items) == 2

    cookie = result.declared_storage_items[0]
    assert cookie.name == "_ga"
    assert cookie.storage_type == StorageTechnologyType.COOKIE
    assert cookie.stated_lifespan == "2 years"

    local_storage = result.declared_storage_items[1]
    assert local_storage.name == "app_user_settings"
    assert local_storage.storage_type == StorageTechnologyType.LOCAL_STORAGE