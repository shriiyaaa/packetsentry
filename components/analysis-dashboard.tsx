"use client";

import type { AnalysisResult, ExplanationItem, TimelinePoint } from "@/lib/api";

function scorePercent(score: number) { return `${Math.round(score * 100)}%`; }
function formatBytes(size: number) { return size < 1024 * 1024 ? `${Math.round(size / 1024)} KB` : `${(size / 1024 / 1024).toFixed(2)} MB`; }

function RiskBadge({ level }: { level: AnalysisResult["threat"]["level"] }) {
  const palette = { LOW: "bg-[#e6f1e9] text-[#1e6d5d]", MEDIUM: "bg-[#fff3d6] text-[#91651a]", HIGH: "bg-[#fff0ea] text-[#a04427]" };
  return <span className={`rounded-full px-3 py-1 text-[11px] font-extrabold tracking-[.16em] ${palette[level]}`}>{level}</span>;
}

function Timeline({ points }: { points: TimelinePoint[] }) {
  if (!points.length) return <div className="grid h-48 place-items-center rounded-xl bg-[#f2f3ed] text-sm text-[#6b7777]">No modeled events to plot.</div>;
  const width = 720; const height = 210; const padX = 22; const padY = 18;
  const x = (index: number) => points.length === 1 ? width / 2 : padX + (index / (points.length - 1)) * (width - padX * 2);
  const y = (score: number) => height - padY - score * (height - padY * 2);
  const path = points.map((point, index) => `${index ? "L" : "M"} ${x(index).toFixed(1)} ${y(point.score).toFixed(1)}`).join(" ");
  return (
    <div className="rounded-xl bg-[#f2f3ed] p-3 sm:p-4">
      <svg aria-label="Model score timeline" className="h-auto w-full" role="img" viewBox={`0 0 ${width} ${height}`}>
        {[0, .5, 1].map((value) => <g key={value}><line className="timeline-grid" x1={padX} x2={width - padX} y1={y(value)} y2={y(value)} /><text fill="#7c8782" fontSize="10" x="0" y={y(value) + 3}>{scorePercent(value)}</text></g>)}
        <path className="timeline-line" d={path} />
        {points.map((point, index) => <circle className="timeline-dot" cx={x(index)} cy={y(point.score)} key={`${point.event_index}-${index}`} r="4" />)}
      </svg>
      <div className="mono mt-1 flex justify-between px-1 text-[10px] text-[#7c8782]"><span>event 01</span><span>{points.length > 1 ? `event ${String(points[points.length - 1].event_index).padStart(2, "0")}` : "final window"}</span></div>
    </div>
  );
}

function Explanation({ item }: { item: ExplanationItem }) {
  const impact = item.impact;
  return <div className="flex gap-3 rounded-xl border border-[#e3e7df] bg-white/70 p-3.5"><span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full bg-[#fff0ea] text-xs font-bold text-[#a04427]">{item.window_position ?? "·"}</span><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-semibold">{item.event_type}</span>{item.event_index && <span className="mono text-[10px] text-[#7c8782]">event {item.event_index}</span>}<span className="mono text-[10px] font-bold text-[#a04427]">impact {impact >= 0 ? "+" : ""}{impact.toFixed(3)}</span></div><p className="mt-1 text-xs leading-5 text-[#6b7777]">{item.note}</p></div></div>;
}

export function AnalysisDashboard({ result, onNewScan }: { result: AnalysisResult; onNewScan: () => void }) {
  const maxProtocol = Math.max(...result.protocols.map((protocol) => protocol.count), 1);
  return (
    <section className="mt-8 space-y-5 pb-16">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="eyebrow">Scan complete · {new Date(result.processed_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</p><h2 className="mt-2 text-3xl font-bold tracking-[-.04em] sm:text-4xl">A readable first pass.</h2></div><button className="rounded-xl border border-[#c7d2ca] bg-white px-4 py-2.5 text-sm font-bold text-[#174f45] hover:bg-[#f1f7f3]" onClick={onNewScan} type="button">New scan</button></div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.18fr)_minmax(0,.82fr)]">
        <div className="card flex flex-col justify-between gap-8 p-6 sm:p-8"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="eyebrow">Prototype risk signal</p><h3 className="mt-2 text-2xl font-bold">{result.message}</h3></div><RiskBadge level={result.threat.level} /></div><div className="flex flex-wrap items-center gap-8 sm:gap-12"><div className="risk-ring grid h-32 w-32 place-items-center rounded-full border-[10px] border-[#e66d42] bg-[#fffaf6]"><div className="text-center"><div className="metric-value text-4xl font-extrabold">{scorePercent(result.threat.score)}</div><div className="mono text-[10px] font-bold uppercase tracking-widest text-[#7c8782]">final score</div></div></div><div className="grid grid-cols-2 gap-x-8 gap-y-4"><div><div className="mono text-[10px] uppercase tracking-widest text-[#7c8782]">peak score</div><div className="metric-value mt-1 text-2xl font-bold">{scorePercent(result.threat.peak_score)}</div></div><div><div className="mono text-[10px] uppercase tracking-widest text-[#7c8782]">model events</div><div className="metric-value mt-1 text-2xl font-bold">{result.modeled_event_count}</div></div><div><div className="mono text-[10px] uppercase tracking-widest text-[#7c8782]">packets read</div><div className="metric-value mt-1 text-2xl font-bold">{result.packet_count.toLocaleString()}</div></div><div><div className="mono text-[10px] uppercase tracking-widest text-[#7c8782]">capture size</div><div className="metric-value mt-1 text-2xl font-bold">{formatBytes(result.file_size_bytes)}</div></div></div></div>{result.truncated && <p className="rounded-xl bg-[#fff3d6] px-4 py-3 text-sm font-medium text-[#91651a]">Packet limit reached at 10,000 packets. Results are intentionally bounded.</p>}</div>
        <div className="card p-6 sm:p-8"><p className="eyebrow">Capture summary</p><h3 className="mt-2 truncate text-xl font-bold" title={result.filename}>{result.filename}</h3><dl className="mt-6 divide-y divide-[#e3e7df] text-sm"><div className="flex justify-between gap-4 py-3"><dt className="text-[#6b7777]">Scan ID</dt><dd className="mono max-w-[65%] truncate text-right text-xs">{result.scan_id}</dd></div><div className="flex justify-between gap-4 py-3"><dt className="text-[#6b7777]">Model runtime</dt><dd className="font-semibold">{result.model.runtime}</dd></div><div className="flex justify-between gap-4 py-3"><dt className="text-[#6b7777]">Feature input</dt><dd className="font-semibold">{result.model.model_feature_width} floats</dd></div><div className="flex justify-between gap-4 py-3"><dt className="text-[#6b7777]">Final window</dt><dd className="font-semibold">{result.model.history_length} events</dd></div></dl></div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[.78fr_1.22fr]"><div className="card p-6 sm:p-8"><p className="eyebrow">Protocol distribution</p><h3 className="mt-2 text-xl font-bold">What was in the wire mix?</h3><div className="mt-6 space-y-4">{result.protocols.map((protocol) => <div key={protocol.protocol}><div className="mb-1.5 flex justify-between text-sm"><span className="font-semibold">{protocol.protocol}</span><span className="mono text-xs text-[#6b7777]">{protocol.count} · {protocol.percentage}%</span></div><div className="h-2 overflow-hidden rounded-full bg-[#e6ebe4]"><div className="h-full rounded-full bg-[#1e6d5d]" style={{ width: `${(protocol.count / maxProtocol) * 100}%` }} /></div></div>)}</div></div><div className="card p-6 sm:p-8"><div className="flex flex-wrap items-end justify-between gap-3"><div><p className="eyebrow">Model score timeline</p><h3 className="mt-2 text-xl font-bold">Signal as events arrived</h3></div><span className="mono text-xs text-[#7c8782]">{result.score_timeline.length} points shown</span></div><div className="mt-6"><Timeline points={result.score_timeline} /></div></div></div>

      <div className="card p-6 sm:p-8"><div className="flex flex-wrap items-end justify-between gap-3"><div><p className="eyebrow">Behavioral events</p><h3 className="mt-2 text-xl font-bold">The model saw these safe signals</h3></div><span className="mono text-xs text-[#7c8782]">{result.modeled_events.length} shown · no raw payloads</span></div><div className="table-scroll mt-6"><table className="w-full border-collapse text-left text-sm"><thead><tr className="border-b border-[#dce1db] text-[10px] uppercase tracking-[.15em] text-[#7c8782]"><th className="pb-3 pr-4">Event</th><th className="pb-3 pr-4">Packet</th><th className="pb-3 pr-4">Type</th><th className="pb-3 pr-4">Score</th><th className="pb-3">Ports</th></tr></thead><tbody>{result.modeled_events.map((event) => <tr className="border-b border-[#edf0eb] last:border-0" key={`${event.event_index}-${event.packet_index}`}><td className="py-3 pr-4 mono text-xs">{String(event.event_index).padStart(2, "0")}</td><td className="py-3 pr-4 mono text-xs text-[#6b7777]">#{event.packet_index}</td><td className="py-3 pr-4"><span className="rounded-md bg-[#eaf3ed] px-2 py-1 text-xs font-bold text-[#1e6d5d]">{event.event_type}</span></td><td className="py-3 pr-4 font-bold">{scorePercent(event.score)}</td><td className="py-3 mono text-xs text-[#6b7777]">{event.source_port && event.destination_port ? `${event.source_port} → ${event.destination_port}` : "—"}</td></tr>)}</tbody></table></div>{!result.modeled_events.length && <p className="mt-4 text-sm text-[#6b7777]">No mapped events were found in this capture.</p>}</div>

      <div className="grid gap-5 lg:grid-cols-[1.05fr_.95fr]"><div className="card p-6 sm:p-8"><p className="eyebrow">Why this score?</p><h3 className="mt-2 text-xl font-bold">Final-window sensitivity</h3><p className="mt-2 max-w-2xl text-sm leading-6 text-[#6b7777]">Each populated slot in the final 10-event window was masked and rescored. These are model-sensitivity hints, not SHAP values or causal attribution.</p><div className="mt-5 space-y-3">{result.explanations.map((item, index) => <Explanation item={item} key={`${item.event_index ?? "none"}-${index}`} />)}</div></div><div className="card bg-[#174f45] p-6 text-[#eff6ee] sm:p-8"><p className="eyebrow !text-[#a9d6bb]">Model limitations</p><h3 className="mt-2 text-xl font-bold">Useful triage, not a verdict.</h3><ul className="mt-5 space-y-3 text-sm leading-6 text-[#d8e8dc]"><li><span className="mr-2 text-[#f5c85b]">01</span> Experimental RL prototype trained on synthetic behavioral traces.</li><li><span className="mr-2 text-[#f5c85b]">02</span> The model is known to produce false positives on benign traffic.</li><li><span className="mr-2 text-[#f5c85b]">03</span> Risk bands are display thresholds, not calibrated attack probabilities.</li><li><span className="mr-2 text-[#f5c85b]">04</span> Only SYN, FIN, and payload presence map to events in v1.</li></ul><p className="mt-6 border-t border-white/15 pt-5 text-xs leading-5 text-[#a9d6bb]">{result.model.disclaimer}</p></div></div>
    </section>
  );
}
