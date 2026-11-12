import type { Severity } from "@/lib/live";

// Severity and state use reserved status colors, always with an icon shape and a text label.
const SEV: Record<Severity, { color: string; shape: "diamond" | "triangle" | "circle" | "ring" }> = {
  critical: { color: "var(--status-critical)", shape: "diamond" },
  high: { color: "var(--status-serious)", shape: "triangle" },
  medium: { color: "var(--status-warning)", shape: "triangle" },
  low: { color: "var(--ink-3)", shape: "circle" },
  info: { color: "var(--ink-3)", shape: "ring" },
};

function Icon({ shape, color }: { shape: string; color: string }) {
  return (
    <svg aria-hidden width="10" height="10" viewBox="0 0 10 10">
      {shape === "diamond" ? <path d="M5 0 L10 5 L5 10 L0 5 Z" fill={color} /> : null}
      {shape === "triangle" ? <path d="M5 0.5 L9.5 9 L0.5 9 Z" fill={color} /> : null}
      {shape === "circle" ? <circle cx="5" cy="5" r="4" fill={color} /> : null}
      {shape === "ring" ? <circle cx="5" cy="5" r="3.5" fill="none" stroke={color} strokeWidth="1.5" /> : null}
    </svg>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV[severity];
  return (
    <span data-testid={`severity-${severity}`} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-panel px-2 py-0.5 text-xs font-medium text-ink">
      <Icon shape={s.shape} color={s.color} />
      {severity.toUpperCase()}
    </span>
  );
}

export function UpDown({ up, label }: { up: boolean; label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm font-medium text-ink">
      <svg aria-hidden width="10" height="10" viewBox="0 0 10 10">
        {up ? <circle cx="5" cy="5" r="4.5" fill="var(--status-good)" /> : <path d="M5 0 L10 5 L5 10 L0 5 Z" fill="var(--status-critical)" />}
      </svg>
      {label ?? (up ? "Up" : "Down")}
    </span>
  );
}

export function AgentState({ status }: { status: "online" | "offline" | "never_connected" | "disabled" }) {
  const map = {
    online: { up: true, label: "Online" },
    offline: { up: false, label: "Offline: no data" },
    never_connected: { up: false, label: "Never connected" },
    disabled: { up: false, label: "Disabled" },
  } as const;
  return <UpDown {...map[status]} />;
}

export function SimulatedBadge() {
  return (
    <span className="inline-flex items-center rounded-full border border-synthetic-line bg-synthetic-bg px-2 py-0.5 text-xs font-medium text-synthetic-ink">
      Simulated test data
    </span>
  );
}

export function LiveBadge() {
  return (
    <span data-testid="live-mode-badge" className="inline-flex items-center gap-1.5 rounded-full border border-line bg-panel-2 px-2.5 py-0.5 text-xs font-medium text-ink-2">
      <svg aria-hidden width="8" height="8" viewBox="0 0 8 8">
        <circle cx="4" cy="4" r="3.5" fill="var(--status-good)" />
      </svg>
      Live monitoring · private
    </span>
  );
}
