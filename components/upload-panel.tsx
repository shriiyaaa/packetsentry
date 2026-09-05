"use client";

import { useRef, useState } from "react";
import { MAX_UPLOAD_BYTES } from "@/lib/api";

type UploadPanelProps = {
  busy: boolean;
  selectedFile: File | null;
  error: string | null;
  onFile: (file: File) => void;
  onAnalyze: () => void;
  onSample: () => void;
};

function formatBytes(size: number): string {
  return `${(size / 1024 / 1024).toFixed(2)} MB`;
}

export function UploadPanel({ busy, selectedFile, error, onFile, onAnalyze, onSample }: UploadPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  return (
    <div className="card p-5 sm:p-7">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">Start a scan</p>
          <h2 className="mt-2 text-xl font-bold tracking-tight">Bring a small capture into focus.</h2>
        </div>
        <span className="mono rounded-full bg-[#e8f0eb] px-3 py-1.5 text-[11px] font-bold text-[#1e6d5d]">IN-MEMORY ONLY</span>
      </div>

      <button
        className={`drop-zone mt-6 flex min-h-[178px] w-full flex-col items-center justify-center rounded-2xl px-5 text-center ${dragging ? "is-dragging" : ""}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => { event.preventDefault(); setDragging(false); const file = event.dataTransfer.files[0]; if (file) onFile(file); }}
        type="button"
        disabled={busy}
      >
        <span className="mb-3 grid h-11 w-11 place-items-center rounded-full bg-[#eaf3ed] text-2xl text-[#1e6d5d]">↑</span>
        <span className="font-semibold">Drop a capture here or choose a file</span>
        <span className="mt-2 text-sm text-[#6b7777]">.pcap only · up to 3 MB · no packet payloads leave this request</span>
        <input ref={inputRef} className="hidden" type="file" accept=".pcap" onChange={(event) => { const file = event.target.files?.[0]; if (file) onFile(file); event.target.value = ""; }} />
      </button>

      {selectedFile && (
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-[#f0f2ec] px-4 py-3 text-sm">
          <span className="min-w-0 truncate font-semibold">{selectedFile.name}</span>
          <span className="mono text-xs text-[#6b7777]">{formatBytes(selectedFile.size)}</span>
        </div>
      )}

      {error && <p className="mt-4 rounded-xl border border-[#f2c4b2] bg-[#fff4ef] px-4 py-3 text-sm font-medium text-[#a04427]">{error}</p>}

      <div className="mt-5 grid gap-3 sm:grid-cols-[1fr_auto]">
        <button className="rounded-xl bg-[#e66d42] px-5 py-3.5 text-sm font-bold text-white transition hover:bg-[#ca5733] disabled:cursor-not-allowed disabled:opacity-45" onClick={onAnalyze} disabled={busy || !selectedFile} type="button">
          {busy ? <span className="inline-flex items-center gap-2"><span className="pulse-dot h-2 w-2 rounded-full bg-white" />Reading capture…</span> : "Analyze selected file"}
        </button>
        <button className="rounded-xl border border-[#c7d2ca] bg-white px-5 py-3.5 text-sm font-bold text-[#174f45] transition hover:border-[#1e6d5d] hover:bg-[#f1f7f3] disabled:cursor-not-allowed disabled:opacity-45" onClick={onSample} disabled={busy} type="button">
          Try sample capture <span aria-hidden="true">↗</span>
        </button>
      </div>
      <p className="mt-4 text-xs leading-5 text-[#7c8782]">Synthetic sample: {MAX_UPLOAD_BYTES / 1_000_000} MB guardrail, safe parsing, no storage, no replay.</p>
    </div>
  );
}
