from pathlib import Path

from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from api.analyzer import MAX_PACKETS, MAX_UPLOAD_BYTES, _packet_event, analyze_pcap
from api.feature_ops import EVENTS, HISTORY_LEN, N_EVENTS, SlidingWindow, event_to_onehot
from api.index import app
from api.inference import MODEL


SAMPLE = Path("public/samples/suspicious-demo.pcap")
client = TestClient(app)


def test_one_hot_and_sliding_window_dimensions() -> None:
    assert event_to_onehot("open_socket").shape == (N_EVENTS,)
    assert event_to_onehot("open_socket").dtype.name == "float32"
    window = SlidingWindow()
    for event in EVENTS[:3]:
        window.push_event(event)
    assert window.get_observation().shape == (HISTORY_LEN * N_EVENTS,)
    assert window.get_observation().dtype.name == "float32"


def test_legacy_packet_mappings() -> None:
    syn = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443, flags="S")
    fin = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443, flags="F")
    raw = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53) / Raw(load=b"safe")
    assert _packet_event(syn)[0] == "open_socket"
    assert _packet_event(fin)[0] == "close_socket"
    assert _packet_event(raw)[0] == "read_file"


def test_real_sample_uses_parser_and_model() -> None:
    assert SAMPLE.exists()
    assert MODEL.loaded is True
    result = analyze_pcap(SAMPLE.read_bytes(), SAMPLE.name)
    assert result.packet_count == 9
    assert result.modeled_event_count >= 5
    assert 0 <= result.threat.score <= 1
    assert 0 <= result.threat.peak_score <= 1
    assert len(result.score_timeline) <= 250
    assert len(result.modeled_events) <= 250


def test_model_score_is_numeric_and_bounded() -> None:
    result = analyze_pcap(SAMPLE.read_bytes(), SAMPLE.name)
    assert isinstance(result.threat.score, float)
    assert isinstance(result.threat.peak_score, float)
    assert result.model.runtime == "onnxruntime"


def test_health_proves_model_initialization() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["model_runtime"] == "onnxruntime"
    assert body["max_upload_bytes"] == MAX_UPLOAD_BYTES
    assert body["max_packets"] == MAX_PACKETS


def test_invalid_pcap_fails_cleanly() -> None:
    response = client.post("/api/analyze", files={"file": ("broken.pcap", b"not a capture", "application/octet-stream")})
    assert response.status_code == 400
    assert "parse" in response.json()["detail"].lower()


def test_oversized_request_is_rejected() -> None:
    response = client.post("/api/analyze", files={"file": ("large.pcap", b"0" * (MAX_UPLOAD_BYTES + 1), "application/octet-stream")})
    assert response.status_code == 413


def test_result_bounds_and_no_raw_payload() -> None:
    result = client.post("/api/analyze", files={"file": (SAMPLE.name, SAMPLE.read_bytes(), "application/vnd.tcpdump.pcap")})
    assert result.status_code == 200
    body = result.json()
    assert body["packet_count"] <= MAX_PACKETS
    assert len(body["score_timeline"]) <= 250
    assert len(body["modeled_events"]) <= 250
    assert "GET /demo" not in result.text
