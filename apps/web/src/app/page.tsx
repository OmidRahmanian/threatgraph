import Link from "next/link";

// Stand-alone entry point. When embedded in a personal site, only /threatgraph/* is used.
export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-4 px-4">
      <h1 className="text-2xl font-semibold">ThreatGraph AI</h1>
      <p className="text-ink-2">
        Explainable behavioral anomaly detection for authentication events.
      </p>
      <Link href="/threatgraph" className="w-fit rounded-lg bg-model px-4 py-2 text-sm font-medium text-white">
        Open ThreatGraph AI
      </Link>
    </main>
  );
}
