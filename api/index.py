"""Vercel-compatible FastAPI entrypoint for PacketSentry."""

from __future__ import annotations

import logging

from fastapi import FastAPI, File, HTTPException, UploadFile

from .analyzer import (
    MAX_PACKETS,
    MAX_UPLOAD_BYTES,
    AnalysisError,
    analyze_pcap,
)
from .feature_ops import EVENTS
from .inference import MODEL
from .schemas import AnalysisResult

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger("packetsentry.api")

app = FastAPI(title="PacketSentry API", version="1.0.0")


@app.get("/api/health")
def health() -> dict[str, object]:
    return {
        "status": "ok" if MODEL.loaded else "degraded",
        "model_loaded": MODEL.loaded,
        "model_runtime": MODEL.runtime,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "max_packets": MAX_PACKETS,
        "event_vocabulary_size": len(EVENTS),
    }


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze(file: UploadFile = File(...)) -> AnalysisResult:
    filename = file.filename or "capture.pcap"
    if not filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=415, detail="Only .pcap files are supported.")

    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Capture exceeds the 3 MB upload limit.")
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded capture is empty.")

    try:
        return analyze_pcap(data, filename)
    except AnalysisError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:
        LOGGER.exception("unexpected analysis error category=internal")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed safely. Please try a small, valid .pcap file.",
        ) from None
