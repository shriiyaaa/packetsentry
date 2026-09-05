"use client";

import { useState } from "react";
import { AnalysisDashboard } from "@/components/analysis-dashboard";
import { UploadPanel } from "@/components/upload-panel";
import { analyzeFile, type AnalysisResult, validateFile } from "@/lib/api";

export function AnalyzerShell() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const chooseFile = (file: File) => {
    const validationError = validateFile(file);
    setError(validationError);
    setResult(null);
    if (!validationError) setSelectedFile(file);
    else setSelectedFile(null);
  };

  const runAnalysis = async (file: File) => {
    setBusy(true); setError(null); setResult(null);
    try { setResult(await analyzeFile(file)); setSelectedFile(file); }
    catch (analysisError) { setError(analysisError instanceof Error ? analysisError.message : "The analysis failed safely. Try again with a valid .pcap."); }
    finally { setBusy(false); }
  };

  const analyzeSelected = () => { if (selectedFile) void runAnalysis(selectedFile); };
  const trySample = async () => {
    setBusy(true); setError(null); setResult(null);
    try {
      const response = await fetch("/samples/suspicious-demo.pcap");
      if (!response.ok) throw new Error("The synthetic sample asset is unavailable.");
      const blob = await response.blob();
      await runAnalysis(new File([blob], "suspicious-demo.pcap", { type: "application/vnd.tcpdump.pcap" }));
    } catch (sampleError) {
      setBusy(false); setError(sampleError instanceof Error ? sampleError.message : "The sample analysis failed safely.");
    }
  };

  return (
    <main className="shell page-grid">
      <div className="mx-auto max-w-6xl px-5 pb-8 pt-6 sm:px-8 lg:px-10">
        <header className="flex items-center justify-between"><div className="flex items-center gap-3"><span className="grid h-9 w-9 place-items-center rounded-xl bg-[#174f45] text-lg font-black text-[#f5c85b]">⌁</span><span className="font-bold tracking-[-.03em]">PacketSentry</span></div><span className="mono rounded-full border border-[#d5ddd5] bg-white/60 px-3 py-1.5 text-[10px] font-bold uppercase tracking-[.14em] text-[#6b7777]">prototype / v1</span></header>
        {!result && <><section className="grid gap-10 pb-12 pt-16 lg:grid-cols-[.95fr_1.05fr] lg:items-end lg:pt-24"><div><p className="eyebrow">Capture triage, made legible</p><h1 className="mt-4 max-w-3xl text-5xl font-extrabold leading-[.96] tracking-[-.07em] sm:text-6xl">A calmer first look at suspicious traffic.</h1><p className="mt-6 max-w-xl text-base leading-7 text-[#6b7777] sm:text-lg">PacketSentry turns a small network capture into safe behavioral signals, a prototype model score, and the context you need to decide what to inspect next.</p><div className="mt-7 flex flex-wrap gap-3 text-xs font-semibold text-[#6b7777]"><span className="rounded-full bg-white/75 px-3 py-2">Scapy parsing</span><span className="rounded-full bg-white/75 px-3 py-2">ONNX inference</span><span className="rounded-full bg-white/75 px-3 py-2">No storage</span></div></div><div className="relative hidden min-h-[210px] lg:block"><div className="absolute right-6 top-2 w-72 rotate-[-4deg] rounded-2xl border border-[#d9e2d8] bg-[#edf5ee] p-5 shadow-xl"><div className="mono text-[10px] font-bold uppercase tracking-[.16em] text-[#1e6d5d]">behavioral window</div><div className="mt-4 grid grid-cols-5 gap-2">{["SYN", "RAW", "UDP", "FIN", "RAW", "·", "·", "·", "·", "·"].map((label, index) => <span className={`grid aspect-square place-items-center rounded-lg text-[9px] font-bold ${label === "·" ? "bg-white text-[#9aa59f]" : "bg-[#1e6d5d] text-white"}`} key={`${label}-${index}`}>{label}</span>)}</div><div className="mt-5 flex items-end justify-between"><span className="mono text-[10px] text-[#6b7777]">MODEL SIGNAL</span><span className="text-2xl font-extrabold text-[#e66d42]">0.68</span></div></div><div className="absolute bottom-0 left-16 h-32 w-32 rounded-full border border-[#e6c8ad] bg-[#fff3d6]" /></div></section><div className="mx-auto max-w-3xl"><UploadPanel busy={busy} selectedFile={selectedFile} error={error} onFile={chooseFile} onAnalyze={analyzeSelected} onSample={() => void trySample()} /></div><div className="mt-8 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-center text-xs text-[#7c8782]"><span>Uploads are analyzed in memory.</span><span className="hidden h-1 w-1 rounded-full bg-[#b2bbb4] sm:block" /><span>Payload contents are never returned.</span><span className="hidden h-1 w-1 rounded-full bg-[#b2bbb4] sm:block" /><span>Experimental security/ML prototype.</span></div></>}
        {result && <AnalysisDashboard result={result} onNewScan={() => { setResult(null); setSelectedFile(null); setError(null); }} />}
      </div>
    </main>
  );
}
