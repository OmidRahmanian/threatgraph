import type { Metadata } from "next";
import { Replay } from "@/components/replay/Replay";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Incident replay",
};

export default function ReplayPage() {
  return <Replay />;
}
