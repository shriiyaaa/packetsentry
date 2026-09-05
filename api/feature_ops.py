"""Feature operations preserved from the original Packet Sniffer RL project."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

EVENTS = [
    "read_file",
    "write_file",
    "open_socket",
    "close_socket",
    "create_process",
    "terminate_process",
    "load_library",
    "delete_file",
]
EVENT_IDX = {event: index for index, event in enumerate(EVENTS)}
N_EVENTS = len(EVENTS)
HISTORY_LEN = 10


def event_to_onehot(event_name: str) -> np.ndarray:
    """Return the legacy float32 one-hot representation for an event."""

    vector = np.zeros(N_EVENTS, dtype=np.float32)
    index = EVENT_IDX.get(event_name)
    if index is not None:
        vector[index] = 1.0
    return vector


@dataclass
class SlidingWindow:
    """Maintain the last ten event vectors and their provenance."""

    history_len: int = HISTORY_LEN

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.window = [
            np.zeros(N_EVENTS, dtype=np.float32) for _ in range(self.history_len)
        ]
        self.events = ["" for _ in range(self.history_len)]
        self.event_indices: list[int | None] = [None for _ in range(self.history_len)]

    def push_event(self, event_name: str, event_index: int | None = None) -> None:
        self.window.pop(0)
        self.window.append(event_to_onehot(event_name))
        self.events.pop(0)
        self.events.append(event_name if event_name in EVENT_IDX else "")
        self.event_indices.pop(0)
        self.event_indices.append(event_index)

    def get_observation(self) -> np.ndarray:
        return np.concatenate(self.window).astype(np.float32)
