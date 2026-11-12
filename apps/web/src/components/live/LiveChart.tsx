"use client";

import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { int } from "@/lib/format";
import { missingCount, toRows, type LiveRange } from "@/lib/live";

const AXIS = { stroke: "var(--line)", tick: { fill: "var(--ink-3)", fontSize: 12 }, tickLine: false };

/** One measure over time. Buckets without telemetry (null) are gaps, never zeros. */
export function LiveSeries({
  title,
  buckets,
  values,
  range,
  unit,
  kind = "bar",
  testId,
  digits = 0,
}: {
  title: string;
  buckets: number[];
  values: (number | null)[];
  range: LiveRange;
  unit: string;
  kind?: "bar" | "line";
  testId?: string;
  digits?: number;
}) {
  const rows = toRows(buckets, values, range);
  const missing = missingCount(values);
  const fmt = (v: number) => (digits ? v.toFixed(digits) : int(Math.round(v)));
  const tooltip = (
    <Tooltip
      cursor={{ fill: "var(--panel-2)", stroke: "var(--ink-3)" }}
      content={({ active, payload }) => {
        if (!active || !payload?.length) return null;
        const r = payload[0].payload as { label: string; value: number | null };
        return (
          <div className="rounded-md border border-line bg-panel px-3 py-2 text-xs text-ink-2 shadow-lg">
            <div className="text-ink-3">{r.label} UTC</div>
            <div className="font-medium text-ink">{r.value === null ? "No data from agents" : `${fmt(r.value)} ${unit}`}</div>
          </div>
        );
      }}
    />
  );
  const common = { data: rows, margin: { top: 8, right: 8, bottom: 0, left: 0 } };
  return (
    <figure data-testid={testId}>
      <figcaption className="mb-1 flex flex-wrap items-baseline justify-between gap-2 text-sm">
        <span className="font-medium text-ink">{title}</span>
        {missing ? (
          <span className="text-xs text-ink-3" data-testid={testId ? `${testId}-missing` : undefined}>
            {missing} of {values.length} intervals without telemetry (shown as gaps)
          </span>
        ) : null}
      </figcaption>
      <div className="h-40 w-full" role="img" aria-label={`${title}; ${missing} intervals without telemetry`}>
        <ResponsiveContainer width="100%" height="100%">
          {kind === "bar" ? (
            <BarChart {...common} barCategoryGap={2}>
              <CartesianGrid stroke="var(--grid)" vertical={false} />
              <XAxis {...AXIS} dataKey="label" interval="preserveStartEnd" minTickGap={32} />
              <YAxis {...AXIS} width={44} allowDecimals={false} />
              {tooltip}
              <Bar dataKey="value" fill="var(--model)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
            </BarChart>
          ) : (
            <LineChart {...common}>
              <CartesianGrid stroke="var(--grid)" vertical={false} />
              <XAxis {...AXIS} dataKey="label" interval="preserveStartEnd" minTickGap={32} />
              <YAxis {...AXIS} width={44} />
              {tooltip}
              <Line type="monotone" dataKey="value" stroke="var(--model)" strokeWidth={2} dot={false} connectNulls={false} isAnimationActive={false} />
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    </figure>
  );
}
