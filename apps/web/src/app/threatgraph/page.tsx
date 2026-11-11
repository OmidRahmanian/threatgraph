import type { Metadata } from "next";
import Link from "next/link";
import { OverviewStats } from "@/components/OverviewStats";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Overview",
};

const REPO_URL = process.env.NEXT_PUBLIC_REPO_URL ?? "";

const STEPS = [
  ["Ingest", "Stream LANL-format auth + red-team files in bounded chunks; validate, null `?`, report data quality."],
  ["Label join", "Match red-team records on (time, user, source, destination). Unmatched events stay unlabeled, not benign."],
  ["Causal features", "Per principal and hour: failures, fan-out, first-seen hosts and edges, deviation from its own past."],
  ["Models", "M0 robust z-score baseline and M1 Isolation Forest, trained without labels on the earliest period."],
  ["Evaluation", "Chronological train → validation → test. Threshold fixed on validation; test metrics reported as-is."],
];

export default function OverviewPage() {
  return (
    <div className="space-y-10 fade-in">
      <section className="max-w-3xl">
        <p className="text-sm font-medium text-ink-3">Security data science · portfolio project</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
          Which logins look like lateral movement, and how sure can we be?
        </h1>
        <p className="mt-4 text-base leading-relaxed text-ink-2">
          ThreatGraph AI scores hourly authentication behavior per account, explains each alert with the
          exact feature values and source events behind it, and evaluates models on a strict
          chronological split. It reads the format of the Los Alamos National Laboratory (LANL) 2015
          cyber-security dataset. Model anomalies, known red-team labels and synthetic data are always
          shown separately: an anomaly score is not proof of compromise.
        </p>
      </section>

      <OverviewStats />

      <section aria-labelledby="actions" className="space-y-3">
        <h2 id="actions" className="text-base font-semibold">Explore</h2>
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <Link
            href="/threatgraph/lab"
            className="group rounded-xl border border-line bg-panel p-5 transition-colors hover:border-model"
          >
            <div className="text-sm font-semibold text-ink">Compare models →</div>
            <p className="mt-2 text-sm text-ink-2">
              Move the alert threshold and watch precision, known-label recall and alert volume recompute
              from stored held-out scores. Inspect any alert&apos;s evidence.
            </p>
          </Link>
          <Link
            href="/threatgraph/network"
            className="group rounded-xl border border-line bg-panel p-5 transition-colors hover:border-model"
          >
            <div className="text-sm font-semibold text-ink">Map the network →</div>
            <p className="mt-2 text-sm text-ink-2">
              See every alerted and red-team account with the computers it used, zoom into shared computers, filter by day,
              and jump to the hour or incident behind any node.
            </p>
          </Link>
          <Link
            href="/threatgraph/explorer"
            className="group rounded-xl border border-line bg-panel p-5 transition-colors hover:border-model"
          >
            <div className="text-sm font-semibold text-ink">Explore one hour →</div>
            <p className="mt-2 text-sm text-ink-2">
              See which computers an alerted account moved between in that hour, with every edge backed by its
              authentication events and every known red-team edge marked.
            </p>
          </Link>
          <Link
            href="/threatgraph/replay"
            className="group rounded-xl border border-line bg-panel p-5 transition-colors hover:border-model"
          >
            <div className="text-sm font-semibold text-ink">Replay an incident →</div>
            <p className="mt-2 text-sm text-ink-2">
              Step through documented red-team activity event by event and see when each model would have
              alerted, with a generated write-up of what happened.
            </p>
          </Link>
        </div>
      </section>

      <section aria-labelledby="how" className="space-y-3">
        <h2 id="how" className="text-base font-semibold">How it works</h2>
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {STEPS.map(([title, body], i) => (
            <li key={title} className="rounded-lg border border-line bg-panel p-4">
              <div className="text-xs text-ink-3">Step {i + 1}</div>
              <div className="mt-1 text-sm font-medium text-ink">{title}</div>
              <p className="mt-1 text-sm text-ink-2">{body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="links" className="space-y-2 text-sm text-ink-2">
        <h2 id="links" className="text-base font-semibold text-ink">Methodology &amp; sources</h2>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            Source dataset:{" "}
            <a className="text-model underline-offset-2 hover:underline" href="https://csr.lanl.gov/data/cyber1/" rel="noreferrer" target="_blank">
              LANL Comprehensive, Multi-Source Cyber-Security Events
            </a>{" "}
            (A. D. Kent, 2015). Downloading it requires LANL&apos;s data-use form; this site never redistributes it.
          </li>
          <li>
            Methodology, evaluation and limitations:{" "}
            {REPO_URL ? (
              <a className="text-model underline-offset-2 hover:underline" href={`${REPO_URL}/tree/main/docs`} rel="noreferrer" target="_blank">
                docs/ in the repository
              </a>
            ) : (
              <span>
                <code className="font-mono">docs/modeling.md</code>, <code className="font-mono">docs/evaluation.md</code> and{" "}
                <code className="font-mono">docs/limitations.md</code> in the repository
              </span>
            )}
            .
          </li>
          {REPO_URL ? (
            <li>
              Code:{" "}
              <a className="text-model underline-offset-2 hover:underline" href={REPO_URL} rel="noreferrer" target="_blank">
                GitHub repository
              </a>
            </li>
          ) : null}
        </ul>
      </section>
    </div>
  );
}
