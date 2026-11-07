import type { Metadata } from "next";
import { Methodology } from "@/components/methodology/Methodology";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Methodology",
};

export default function MethodologyPage() {
  return <Methodology />;
}
