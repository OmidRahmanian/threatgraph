import type { ReactNode } from "react";
import type { Provenance } from "@/lib/types";

export function Panel({ children, className = "", id }: { children: ReactNode; className?: string; id?: string }) {
  return (
    <section id={id} className={`min-w-0 rounded-xl border border-line bg-panel p-4 sm:p-5 ${className}`}>
      {children}
    </section>
  );
}

export function SectionTitle({ title, subtitle, right }: { title: string; subtitle?: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="text-base font-semibold text-ink">{title}</h2>
        {subtitle ? <p className="mt-1 text-sm text-ink-2">{subtitle}</p> : null}
      </div>
      {right}
    </div>
  );
}

export function StatTile({ label, value, note, testId }: { label: string; value: ReactNode; note?: ReactNode; testId?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3" data-testid={testId}>
      <div className="text-xs text-ink-3">{label}</div>
      <div className="mt-1 text-2xl font-semibold tracking-tight text-ink tabular-nums">{value}</div>
      {note ? <div className="mt-1 text-xs text-ink-3">{note}</div> : null}
    </div>
  );
}

/** Dataset-mode badge. Always rendered with text, never color alone. */
export function ProvenanceBadge({ provenance }: { provenance: Provenance | null }) {
  if (!provenance) return null;
  if (provenance.is_synthetic) {
    return (
      <span
        data-testid="provenance-badge"
        title={provenance.source}
        className="inline-flex items-center gap-1.5 rounded-full border border-synthetic-line bg-synthetic-bg px-2.5 py-0.5 text-xs font-medium text-synthetic-ink"
      >
        <svg aria-hidden width="10" height="10" viewBox="0 0 10 10">
          <rect x="1.5" y="1.5" width="7" height="7" transform="rotate(45 5 5)" fill="none" stroke="currentColor" strokeWidth="1.5" />
        </svg>
        {provenance.mode_label}
      </span>
    );
  }
  return (
    <span
      data-testid="provenance-badge"
      title={provenance.source}
      className="inline-flex items-center gap-1.5 rounded-full border border-line bg-panel-2 px-2.5 py-0.5 text-xs font-medium text-ink-2"
    >
      {provenance.mode_label}
    </span>
  );
}

export function KnownRedteamBadge({ count }: { count?: number }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-redteam-soft px-2 py-0.5 text-xs font-medium text-ink">
      <svg aria-hidden width="9" height="9" viewBox="0 0 10 10">
        <path d="M5 0 L10 5 L5 10 L0 5 Z" fill="var(--redteam)" />
      </svg>
      Known red-team{count !== undefined && count > 1 ? ` ×${count}` : ""}
    </span>
  );
}

export function UnlabeledBadge() {
  return (
    <span className="inline-flex items-center rounded-full border border-line px-2 py-0.5 text-xs text-ink-3" title="Not in the red-team file. Not confirmed benign.">
      Unlabeled
    </span>
  );
}

export function AlertBadge({ flagged }: { flagged: boolean }) {
  return flagged ? (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-model-soft px-2 py-0.5 text-xs font-medium text-ink">
      <svg aria-hidden width="9" height="9" viewBox="0 0 10 10">
        <circle cx="5" cy="5" r="4" fill="var(--model)" />
      </svg>
      Model alert
    </span>
  ) : (
    <span className="text-xs text-ink-3">Below threshold</span>
  );
}

export function Callout({ title, children, tone = "neutral" }: { title: string; children: ReactNode; tone?: "neutral" | "synthetic" }) {
  const cls = tone === "synthetic" ? "border-synthetic-line bg-synthetic-bg text-synthetic-ink" : "border-line bg-panel-2 text-ink-2";
  return (
    <div className={`rounded-lg border px-4 py-3 text-sm ${cls}`} role="note">
      <div className="font-medium text-ink">{title}</div>
      <div className="mt-1 space-y-1 leading-relaxed">{children}</div>
    </div>
  );
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="animate-pulse rounded-lg border border-line bg-panel-2 px-4 py-6 text-sm text-ink-3" role="status">
      {label}
    </div>
  );
}

export function ErrorBlock({ error }: { error: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-4 text-sm text-ink-2" role="alert">
      <div className="font-medium text-ink">Could not load data</div>
      <p className="mt-1 break-words">{error}</p>
      <p className="mt-2 text-ink-3">
        Build the bundle with <code className="font-mono">python scripts/run_pipeline.py --dataset demo</code>.
      </p>
    </div>
  );
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex flex-wrap rounded-lg border border-line bg-panel-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={o.value === value}
          onClick={() => onChange(o.value)}
          className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
            o.value === value ? "bg-panel text-ink shadow-sm" : "text-ink-2 hover:text-ink"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
