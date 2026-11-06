import type { Metadata } from "next";
import { Lab } from "@/components/lab/Lab";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Experiment Lab",
};

export default function LabPage() {
  return <Lab />;
}
