const DAY = 86_400;

/** LANL time is relative seconds from an unknown epoch: never render a calendar date. */
export function relTime(seconds: number): string {
  const day = Math.floor(seconds / DAY);
  const rem = seconds - day * DAY;
  return `Day ${day} · +${rem.toLocaleString("en-US")}s`;
}

export function windowLabel(start: number, end: number): string {
  const day = Math.floor(start / DAY);
  return `Day ${day} · +${(start - day * DAY).toLocaleString("en-US")}s → +${(end - day * DAY).toLocaleString("en-US")}s`;
}

export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

export function int(n: number): string {
  return n.toLocaleString("en-US");
}

export function compact(n: number): string {
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

/** Ratios; `null` means not estimable, which is shown explicitly rather than as 0. */
export function ratio(v: number | null | undefined, digits = 3): string {
  return v === null || v === undefined ? "n/e" : v.toFixed(digits);
}

export function pct(v: number | null | undefined, digits = 1): string {
  return v === null || v === undefined ? "n/e" : `${(v * 100).toFixed(digits)}%`;
}

export function score(v: number): string {
  return Math.abs(v) >= 100 ? v.toFixed(1) : v.toFixed(4);
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
