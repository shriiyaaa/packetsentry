"""ONNX Runtime wrapper for the committed prototype policy model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from .feature_ops import HISTORY_LEN, N_EVENTS, SlidingWindow

MODEL_PATH = Path(__file__).resolve().parent / "assets" / "policy_model.onnx"


class InferenceEngine:
    """Load the model once and expose bounded, CPU-only inference."""

    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.session: Any | None = None
        self.error: str | None = None
        self.input_name: str | None = None
        self.input_shape: list[str] = []
        self.feature_width = HISTORY_LEN * N_EVENTS

        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(
                str(model_path), providers=["CPUExecutionProvider"]
            )
            input_meta = self.session.get_inputs()[0]
            self.input_name = input_meta.name
            self.input_shape = [str(value) for value in input_meta.shape]
            input_width = input_meta.shape[-1]
            if not isinstance(input_width, int) or input_width <= 0:
                raise RuntimeError("model_input_width_unknown")
            self.feature_width = input_width
            # A warm-up call makes the health endpoint meaningful: the model is
            # not merely present on disk; it can actually execute.
            zero_input = np.zeros((1, self.feature_width), dtype=np.float32)
            self.session.run(None, {self.input_name: zero_input})
        except Exception as exc:  # pragma: no cover - exercised in deployments
            self.error = type(exc).__name__
            self.session = None

    @property
    def loaded(self) -> bool:
        return self.session is not None and self.input_name is not None

    @property
    def runtime(self) -> str:
        return "onnxruntime"

    @property
    def model_history_length(self) -> int:
        return self.feature_width // N_EVENTS if self.feature_width % N_EVENTS == 0 else 0

    def score_window(self, window: SlidingWindow) -> float:
        if not self.loaded:
            raise RuntimeError("model_unavailable")

        full_observation = window.get_observation()
        if self.feature_width <= full_observation.size:
            observation_vector = full_observation[-self.feature_width :]
        else:
            observation_vector = np.pad(
                full_observation,
                (self.feature_width - full_observation.size, 0),
                mode="constant",
            )
        observation = observation_vector[None, :].astype(np.float32)
        output = self.session.run(None, {self.input_name: observation})[0]
        values = np.asarray(output, dtype=np.float32).reshape(-1)
        if values.size == 0:
            raise RuntimeError("model_empty_output")
        score = float(values[1] if values.size > 1 else values[0])
        return float(np.clip(score, 0.0, 1.0))


MODEL = InferenceEngine()
