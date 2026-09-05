export const MAX_UPLOAD_BYTES = 3_000_000;

export type Threat = {
  score: number;
  peak_score: number;
  level: "LOW" | "MEDIUM" | "HIGH";
};

export type ProtocolStat = { protocol: string; count: number; percentage: number };
export type TimelinePoint = { event_index: number; packet_index: number; event_type: string; score: number };
export type ModeledEvent = TimelinePoint & {
  source_port: number | null;
  destination_port: number | null;
};
export type ExplanationItem = {
  event_index: number | null;
  window_position: number | null;
  event_type: string;
  impact: number;
  score_without_event: number | null;
  note: string;
};
export type AnalysisResult = {
  scan_id: string;
  filename: string;
  processed_at: string;
  file_size_bytes: number;
  packet_count: number;
  modeled_event_count: number;
  truncated: boolean;
  threat: Threat;
  protocols: ProtocolStat[];
  score_timeline: TimelinePoint[];
  modeled_events: ModeledEvent[];
  explanations: ExplanationItem[];
  model: {
    runtime: string;
    input_shape: string[];
    event_vocabulary: string[];
    history_length: number;
    model_history_length: number;
    model_feature_width: number;
    action_index_used: number;
    disclaimer: string;
  };
  message: string;
};

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch("/api/analyze", { method: "POST", body });
  const payload = (await response.json().catch(() => ({}))) as { detail?: string } | AnalysisResult;
  if (!response.ok) {
    const detail = "detail" in payload && payload.detail ? payload.detail : "The analysis service returned an error.";
    throw new Error(detail);
  }
  return payload as AnalysisResult;
}

export function validateFile(file: File): string | null {
  if (!file.name.toLowerCase().endsWith(".pcap")) return "Choose a .pcap file. PacketSentry does not advertise .pcapng yet.";
  if (file.size === 0) return "That file is empty.";
  if (file.size > MAX_UPLOAD_BYTES) return "Keep captures under 3 MB for this demo.";
  return null;
}
