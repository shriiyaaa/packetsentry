"""Safe in-memory PCAP parsing and bounded model analysis."""

from __future__ import annotations

import io
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import PcapReader

from .feature_ops import EVENTS, HISTORY_LEN, SlidingWindow
from .inference import MODEL
from .schemas import (
    AnalysisResult,
    ExplanationItem,
    ModeledEvent,
    ModelMetadata,
    ProtocolStat,
    ThreatSummary,
    TimelinePoint,
)

LOGGER = logging.getLogger("packetsentry.analyzer")

MAX_UPLOAD_BYTES = 3_000_000
MAX_PACKETS = 10_000
MAX_RETURNED_EVENTS = 250
MAX_TIMELINE_POINTS = 250
MAX_EXPLANATION_ITEMS = 5


class AnalysisError(ValueError):
    """An expected, user-safe capture parsing or model error."""


def risk_level(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.55:
        return "MEDIUM"
    return "LOW"


def _bounded_items(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if len(items) <= limit:
        return items
    # Preserve the beginning, middle, and end of a long capture without
    # returning every packet or event.
    indexes = [round(index * (len(items) - 1) / (limit - 1)) for index in range(limit)]
    return [items[index] for index in indexes]


def _packet_protocol(packet: Any) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "Other"


def _packet_event(packet: Any) -> tuple[str | None, int | None, int | None]:
    """Map packet metadata to the legacy behavioral event vocabulary."""

    source_port: int | None = None
    destination_port: int | None = None
    transport = None
    if packet.haslayer(TCP):
        transport = packet[TCP]
    elif packet.haslayer(UDP):
        transport = packet[UDP]

    if transport is not None:
        source_port = int(getattr(transport, "sport", 0) or 0)
        destination_port = int(getattr(transport, "dport", 0) or 0)

    if packet.haslayer(TCP):
        flags = int(packet[TCP].flags)
        if flags & 0x02:  # SYN
            return "open_socket", source_port, destination_port
        if flags & 0x01:  # FIN
            return "close_socket", source_port, destination_port
    if packet.haslayer(Raw):
        return "read_file", source_port, destination_port
    return None, source_port, destination_port


def _explain_final_window(window: SlidingWindow, base_score: float) -> list[ExplanationItem]:
    items: list[ExplanationItem] = []
    for position, event_name in enumerate(window.events):
        event_index = window.event_indices[position]
        if not event_name or event_index is None:
            continue
        original = window.window[position]
        window.window[position] = original * 0.0
        try:
            masked_score = MODEL.score_window(window)
        finally:
            window.window[position] = original
        impact = float(base_score - masked_score)
        items.append(
            ExplanationItem(
                event_index=event_index,
                window_position=position + 1,
                event_type=event_name,
                impact=round(impact, 4),
                score_without_event=round(masked_score, 4),
                note=(
                    "Higher impact means masking this final-window event lowered "
                    "the model score more."
                ),
            )
        )
    items.sort(key=lambda item: item.impact, reverse=True)
    return items[:MAX_EXPLANATION_ITEMS]


def analyze_pcap(data: bytes, filename: str) -> AnalysisResult:
    if not MODEL.loaded:
        raise AnalysisError("The ONNX model could not be initialized.")
    if not data:
        raise AnalysisError("The uploaded capture is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise AnalysisError("The capture exceeds the 3 MB upload limit.")

    started = time.perf_counter()
    protocol_counts = {name: 0 for name in ("TCP", "UDP", "ICMP", "Other")}
    modeled_events: list[dict[str, Any]] = []
    window = SlidingWindow()
    packet_count = 0
    truncated = False
    reader = None

    try:
        reader = PcapReader(io.BytesIO(data))
        for packet in reader:
            if packet_count >= MAX_PACKETS:
                truncated = True
                break
            packet_count += 1
            protocol_counts[_packet_protocol(packet)] += 1
            event_name, source_port, destination_port = _packet_event(packet)
            if event_name is None:
                continue

            event_index = len(modeled_events) + 1
            window.push_event(event_name, event_index)
            score = MODEL.score_window(window)
            modeled_events.append(
                {
                    "event_index": event_index,
                    "packet_index": packet_count,
                    "event_type": event_name,
                    "score": round(score, 4),
                    "source_port": source_port,
                    "destination_port": destination_port,
                }
            )
    except Exception as exc:
        LOGGER.info("capture analysis failed category=%s", type(exc).__name__)
        raise AnalysisError("We could not parse that PCAP. Please choose a valid .pcap file.") from None
    finally:
        if reader is not None:
            reader.close()

    final_score = modeled_events[-1]["score"] if modeled_events else 0.0
    peak_score = max((event["score"] for event in modeled_events), default=0.0)
    protocols = [
        ProtocolStat(
            protocol=protocol,
            count=count,
            percentage=round((count / packet_count) * 100, 1) if packet_count else 0.0,
        )
        for protocol, count in protocol_counts.items()
    ]
    timeline = [
        TimelinePoint(**event)
        for event in _bounded_items(modeled_events, MAX_TIMELINE_POINTS)
    ]
    bounded_events = [ModeledEvent(**event) for event in _bounded_items(modeled_events, MAX_RETURNED_EVENTS)]

    if modeled_events:
        explanations = _explain_final_window(window, final_score)
        message = (
            "Analysis complete. Scores are prototype model outputs, not calibrated "
            "attack probabilities."
        )
    else:
        explanations = [
            ExplanationItem(
                event_type="No modeled events",
                impact=0.0,
                note=(
                    "This capture contained no TCP SYN, TCP FIN, or payload events "
                    "recognized by the prototype mapping."
                ),
            )
        ]
        message = (
            "Capture parsed successfully, but no events matched the prototype "
            "behavioral mapping."
        )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    LOGGER.info(
        "capture analyzed bytes=%d packets=%d modeled_events=%d duration_ms=%s",
        len(data),
        packet_count,
        len(modeled_events),
        elapsed_ms,
    )
    safe_filename = Path(filename or "capture.pcap").name
    return AnalysisResult(
        scan_id=str(uuid.uuid4()),
        filename=safe_filename,
        processed_at=datetime.now(timezone.utc),
        file_size_bytes=len(data),
        packet_count=packet_count,
        modeled_event_count=len(modeled_events),
        truncated=truncated,
        threat=ThreatSummary(
            score=round(final_score, 4),
            peak_score=round(peak_score, 4),
            level=risk_level(final_score),
        ),
        protocols=protocols,
        score_timeline=timeline,
        modeled_events=bounded_events,
        explanations=explanations,
        model=ModelMetadata(
            runtime=MODEL.runtime,
            input_shape=MODEL.input_shape,
            event_vocabulary=EVENTS,
            history_length=HISTORY_LEN,
            model_history_length=MODEL.model_history_length,
            model_feature_width=MODEL.feature_width,
            action_index_used=1,
            disclaimer=(
                "Experimental RL prototype trained on synthetic behavioral traces; "
                "known false-positive limitation; not a production IDS verdict."
            ),
        ),
        message=message,
    )
