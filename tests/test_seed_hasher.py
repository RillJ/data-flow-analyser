import hashlib
from data_flow_analyser.engines.seed_hasher import generate_seed_hash_map, scan_for_seed_matches


def test_seed_hash_generation():
    raw_seeds = {"email": "test@surf.nl"}
    seed_data = generate_seed_hash_map(raw_seeds)

    # Check Plaintext
    assert "test@surf.nl" in seed_data.hash_map

    # Check SHA-256 (and the others are similar so can be ingored for brevity)
    expected_sha256 = hashlib.sha256(b"test@surf.nl").hexdigest()
    assert expected_sha256 in seed_data.hash_map
    assert seed_data.hash_map[expected_sha256] == "email (SHA-256)"


def test_scan_payload_for_hashed_seeds():
    raw_seeds = {"email": "test@surf.nl"}
    seed_data = generate_seed_hash_map(raw_seeds)
    sha256_hash = hashlib.sha256(b"test@surf.nl").hexdigest()

    nested_payload = {
        "event": "page_view",
        "user_id": sha256_hash,
        "status": 200
    }

    matches = scan_for_seed_matches(nested_payload, seed_data)
    assert len(matches) > 0
    assert matches[0] == (sha256_hash, "email (SHA-256)")