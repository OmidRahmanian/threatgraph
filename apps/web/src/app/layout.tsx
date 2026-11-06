import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatGraph AI",
  description:
    "Explainable behavioral anomaly detection on authentication events: causal features, chronological evaluation, and evidence-linked explanations.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
