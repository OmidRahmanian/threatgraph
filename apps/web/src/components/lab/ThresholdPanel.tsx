"use client";

import { int, pct, ratio, score as fmtScore } from "@/lib/format";
import { indexToSlider, ladderIndexFor, SLIDER_STEPS, sliderToIndex, type ThresholdMetrics } from "@/lib/threshold";
import { StatTile } from "../ui";

export function ThresholdPanel({
  ladder,
  threshold,
  calibrated,
  m,
  onChange,
}: {
  ladder: number[];
  threshold: number;
  calibrated: number;
  m: ThresholdMetrics;
  onChange: (t: number) => void;
}) {
  const idx = ladderIndexFor(ladder, threshold);
  const isCalibrated = threshold === calibrated;
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <label htmlFor="threshold" className="text-sm font-medium text-ink">
            Alert threshold{" "}
            <span className="font-mono text-ink-2" data-testid="threshold-value">
              {fmtScore(threshold)}
            </span>
            {isCalibrated ? <span className="ml-2 text-xs font-normal text-ink-3">(calibrated on validation)</span> : null}
          </label>
          <button
            onClick={() => onChange(calibrated)}
            disabled={isCalibrated}
            className="rounded-md border border-line px-2.5 py-1 text-xs text-ink-2 enabled:hover:text-ink disabled:opacity-50"
          >
            Reset to validation-calibrated threshold
          </button>
        </div>
        <input
          id="threshold"
          data-testid="threshold-slider"
          type="range"
          min={0}
          max={SLIDER_STEPS}
          step={1}
          value={indexToSlider(idx, ladder.length)}
          onChange={(e) => onChange(ladder[sliderToIndex(Number(e.target.value), ladder.length)])}
          aria-valuetext={`threshold ${fmtScore(threshold)}, ${m.alerts} alerts`}
          className="w-full"
        />
        <div className="flex justify-between text-xs text-ink-3">
          <span>← Stricter (fewer alerts)</span>
          <span>More alerts →</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          testId="metric-alerts"
          label="Alerts (analyst workload)"
          value={int(m.alerts)}
          note={`${m.alertsPerDay === null ? "n/a" : m.alertsPerDay.toFixed(1)} per day · ${pct(m.alertRate, 2)} of windows`}
        />
        <StatTile
          testId="metric-caught"
          label="Known red-team windows alerted"
          value={`${m.knownPositiveAlerts} / ${m.knownPositives}`}
          note={`${m.missedKnownPositives} known windows missed`}
        />
        <StatTile testId="metric-precision" label="Precision (lower bound)" value={ratio(m.precisionLowerBound)} note="unlabeled alerts counted as false" />
        <StatTile testId="metric-recall" label="Known-label recall" value={ratio(m.knownLabelRecall)} note="of documented red-team windows only" />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[360px] border-collapse text-sm" aria-describedby="cm-note">
          <caption id="cm-note" className="mb-2 text-left text-xs text-ink-3">
            Confusion counts under an explicit assumption: unlabeled windows are treated as negatives. Some may be undocumented
            malicious activity.
          </caption>
          <thead>
            <tr className="text-xs text-ink-3">
              <th className="p-2 text-left font-normal" />
              <th className="p-2 text-right font-normal">Alerted</th>
              <th className="p-2 text-right font-normal">Not alerted</th>
            </tr>
          </thead>
          <tbody className="tabular-nums">
            <tr className="border-t border-line">
              <th className="p-2 text-left font-normal text-ink-2">Known red-team</th>
              <td className="p-2 text-right" data-testid="cm-tp">{int(m.knownPositiveAlerts)}</td>
              <td className="p-2 text-right">{int(m.missedKnownPositives)}</td>
            </tr>
            <tr className="border-t border-line">
              <th className="p-2 text-left font-normal text-ink-2">Unlabeled</th>
              <td className="p-2 text-right">{int(m.unlabeledAlerts)}</td>
              <td className="p-2 text-right">{int(m.unlabeledNotAlerted)}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
