"""Typed API response models for bounded capture analysis."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ThreatSummary(BaseModel):
    score: float = Field(ge=0, le=1)
    peak_score: float = Field(ge=0, le=1)
    level: str


class ProtocolStat(BaseModel):
    protocol: str
    count: int = Field(ge=0)
    percentage: float = Field(ge=0, le=100)


class TimelinePoint(BaseModel):
    event_index: int = Field(ge=1)
    packet_index: int = Field(ge=1)
    event_type: str
    score: float = Field(ge=0, le=1)


class ModeledEvent(BaseModel):
    event_index: int = Field(ge=1)
    packet_index: int = Field(ge=1)
    event_type: str
    score: float = Field(ge=0, le=1)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)


class ExplanationItem(BaseModel):
    event_index: int | None = Field(default=None, ge=1)
    window_position: int | None = Field(default=None, ge=1, le=10)
    event_type: str
    impact: float
    score_without_event: float | None = Field(default=None, ge=0, le=1)
    note: str


class ModelMetadata(BaseModel):
    runtime: str
    input_shape: list[str]
    event_vocabulary: list[str]
    history_length: int
    model_history_length: int
    model_feature_width: int
    action_index_used: int
    disclaimer: str


class AnalysisResult(BaseModel):
    scan_id: str
    filename: str
    processed_at: datetime
    file_size_bytes: int = Field(ge=0)
    packet_count: int = Field(ge=0)
    modeled_event_count: int = Field(ge=0)
    truncated: bool
    threat: ThreatSummary
    protocols: list[ProtocolStat]
    score_timeline: list[TimelinePoint]
    modeled_events: list[ModeledEvent]
    explanations: list[ExplanationItem]
    model: ModelMetadata
    message: str
