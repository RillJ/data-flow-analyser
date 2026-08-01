from datetime import datetime, timezone

from data_flow_analyser.engines.presidio_detector import PresidioPersonalDataDetector
from data_flow_analyser.models.schemas import NetworkFlow


class FakeRecognizerResult:
    def __init__(self, entity_type: str, start: int, end: int, score: float):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score


class FakeAnalyzer:
    def __init__(self):
        self.calls = []

    def analyze(self, text, language, entities, score_threshold):
        self.calls.append(text)
        if text == "Julian Rill":
            return [FakeRecognizerResult("PERSON", 0, len(text), 0.91)]
        return []


def _detector_with_fake_analyzer() -> PresidioPersonalDataDetector:
    detector = object.__new__(PresidioPersonalDataDetector)
    detector.score_threshold = 0.65
    detector.language = "nl"
    detector.max_unique_values = 25000
    detector.max_values_per_flow = 250
    detector.full_ner = False
    detector.max_text_length = 50000
    detector.chunk_overlap = 512
    detector.max_ner_text_length = 10000
    detector._non_ner_entities = ["EMAIL_ADDRESS"]
    detector.analyser = FakeAnalyzer()
    detector.deterministic_analyser = detector.analyser
    detector.entities = ["PERSON"]
    detector.warning = None
    detector._analysis_cache = {}
    detector._limit_reached = False
    return detector


def test_presidio_detection_maps_decoded_values_to_flow_context():
    detector = _detector_with_fake_analyzer()
    flow = NetworkFlow(
        flow_id="flow-1",
        timestamp=datetime.now(timezone.utc),
        method="POST",
        url="https://example.nl/profile",
        host="example.nl",
        path="/profile",
        request_body='{"name": "Julian Rill"}',
    )

    findings = detector.detect_flows([flow])

    assert len(findings) == 1
    assert findings[0]["flow_id"] == "flow-1"
    assert findings[0]["endpoint"] == "example.nl"
    assert findings[0]["direction"] == "request"
    assert findings[0]["location"] == "request.body.name"
    assert findings[0]["data_label"] == "person"
    assert findings[0]["sample_value"] == "Julian Rill"
    assert findings[0]["detection_method"] == "presidio"


def test_presidio_detection_caches_identical_values():
    detector = _detector_with_fake_analyzer()
    flow = NetworkFlow(
        flow_id="flow-1",
        timestamp=datetime.now(timezone.utc),
        method="POST",
        url="https://example.nl/profile",
        host="example.nl",
        path="/profile",
        request_body='{"first": "Julian Rill", "second": "Julian Rill"}',
    )

    findings = detector.detect_flows([flow])

    assert len(findings) == 2
    assert detector.analyser.calls.count("Julian Rill") == 1


def test_presidio_detector_without_analyzer_returns_no_findings():
    detector = object.__new__(PresidioPersonalDataDetector)
    detector.analyser = None

    assert detector.detect_flows([]) == []


def test_presidio_detector_uses_one_regex_pass_for_oversized_values():
    detector = _detector_with_fake_analyzer()
    detector.max_ner_text_length = 16

    class ChunkAnalyzer(FakeAnalyzer):
        def analyze(self, text, language, entities, score_threshold):
            self.calls.append(text)
            marker = "Julian Rill"
            if marker in text:
                start = text.index(marker)
                return [FakeRecognizerResult("PERSON", start, start + len(marker), 0.91)]
            return []

    detector.analyser = ChunkAnalyzer()
    detector.deterministic_analyser = detector.analyser
    value = "x" * 10 + "Julian Rill" + "y" * 10

    findings = detector._analyse_value(value, "flow-1", "response.body")

    assert findings == [("PERSON", 10, 21)]
    assert detector.analyser.calls == [value]


def test_presidio_full_ner_chunks_large_values():
    detector = _detector_with_fake_analyzer()
    detector.full_ner = True
    detector.max_ner_text_length = 4
    detector.max_text_length = 8
    detector.chunk_overlap = 2
    value = "x" * 20

    detector._analyse_value(value, "flow-1", "response.body")

    assert len(detector.analyser.calls) > 1
    assert all(len(chunk) <= 8 for chunk in detector.analyser.calls)
