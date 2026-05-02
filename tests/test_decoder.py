import base64
import json
import urllib.parse
from data_flow_analyser.parsers.decoder import recursive_decode


def test_plain_text():
    """Plain strings should pass through unchanged."""
    assert recursive_decode("hello_world") == "hello_world"
    assert recursive_decode(123) == 123
    assert recursive_decode(None) is None


def test_url_decoding():
    """URL-encoded parameters should be unquoted."""
    encoded = "user%40surf.nl&status%3Dactive"
    expected = "user@surf.nl&status=active"
    assert recursive_decode(encoded) == expected


def test_json_decoding():
    """Valid JSON strings should be parsed into dictionaries or lists."""
    raw_json = '{"user": "test_person", "id": 100}'
    expected = {"user": "test_person", "id": 100}
    assert recursive_decode(raw_json) == expected


def test_base64_decoding():
    """Valid printable Base64 strings should be decoded to UTF-8 text."""
    plain = "PersonalDataToken123"
    b64_encoded = base64.b64encode(plain.encode("utf-8")).decode("utf-8")
    assert recursive_decode(b64_encoded) == plain


def test_nested_multi_layer_decoding():
    """
    Simulate modern tracking payloads:
    A JSON object -> URL encoded -> Base64 encoded.
    """
    inner_data = {"email": "john.doe%40surf.nl", "token": "SGVsbG8="}
    json_str = json.dumps(inner_data)
    url_encoded = urllib.parse.quote(json_str)
    b64_encoded = base64.b64encode(url_encoded.encode("utf-8")).decode("utf-8")

    # The recursive decoder should unravel all layers down to the clean dict
    result = recursive_decode(b64_encoded)
    assert isinstance(result, dict)
    assert result["email"] == "john.doe@surf.nl"  # URL unquoted inside dict
    assert result["token"] == "Hello"             # Base64 decoded inside dict


def test_dictionary_and_list_traversal():
    """Dictionaries and lists containing encoded string values should be traversed."""
    payload = {
        "params": ["user%20name", "SGVsbG8="],
        "meta": {"auth": "bearer%3A12345"}
    }
    expected = {
        "params": ["user name", "Hello"],
        "meta": {"auth": "bearer:12345"}
    }
    assert recursive_decode(payload) == expected


def test_max_depth_prevention():
    """Make sure that max_depth prevents infinite or overly deep recursion."""
    raw_str = "user%2520name"  # Double URL-encoded
    # With max_depth=1, it only unquotes once > "user%20name"
    assert recursive_decode(raw_str, max_depth=1) == "user%20name"


def test_graceful_binary_or_malformed_handling():
    """Invalid JSON or non-text base64 should be gracefully returned as string."""
    invalid_json = "{"
    assert recursive_decode(invalid_json) == "{"