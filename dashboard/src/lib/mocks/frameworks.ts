import type { Framework, FrameworkId } from "../types";

export const FRAMEWORK_CATALOG: Record<FrameworkId, { name: string; shortName: string; description: string; totalControls: number }> = {
  "pci-dss": {
    name: "PCI DSS v4.0",
    shortName: "PCI-DSS",
    description: "Payment Card Industry Data Security Standard",
    totalControls: 312,
  },
  "iso-27001": {
    name: "ISO/IEC 27001:2022",
    shortName: "ISO 27001",
    description: "Information Security Management System",
    totalControls: 93,
  },
  cis: {
    name: "CIS Controls v8.1",
    shortName: "CIS",
    description: "Center for Internet Security controls",
    totalControls: 153,
  },
  "nist-800-53": {
    name: "NIST SP 800-53 Rev. 5",
    shortName: "NIST",
    description: "US federal information systems controls",
    totalControls: 287,
  },
  gdpr: {
    name: "GDPR / Ley 6534/20",
    shortName: "GDPR",
    description: "Data protection (EU GDPR + Paraguay credit data law)",
    totalControls: 47,
  },
  soc2: {
    name: "SOC 2 Type II",
    shortName: "SOC 2",
    description: "Trust Services Criteria (security, availability, confidentiality)",
    totalControls: 64,
  },
  hipaa: {
    name: "HIPAA Security Rule",
    shortName: "HIPAA",
    description: "Health information privacy and security",
    totalControls: 54,
  },
  owasp: {
    name: "OWASP ASVS 4.0",
    shortName: "OWASP",
    description: "Application Security Verification Standard",
    totalControls: 286,
  },
  "mitre-attack": {
    name: "MITRE ATT&CK Enterprise",
    shortName: "MITRE",
    description: "Adversary tactics and techniques coverage",
    totalControls: 193,
  },
};

// Compliance state per framework — tuned so the dashboard shows a credible
// mix of "clearly compliant", "needs work" and "red flag" items without
// any single vertical looking bulletproof or catastrophic.
const FRAMEWORK_STATE: Record<
  FrameworkId,
  { passedPercent: number; daysAgo: number }
> = {
  "pci-dss": { passedPercent: 0.92, daysAgo: 0 },
  "iso-27001": { passedPercent: 0.85, daysAgo: 0 },
  cis: { passedPercent: 0.78, daysAgo: 1 },
  "nist-800-53": { passedPercent: 0.81, daysAgo: 0 },
  gdpr: { passedPercent: 0.89, daysAgo: 2 },
  soc2: { passedPercent: 0.93, daysAgo: 0 },
  hipaa: { passedPercent: 0.7, daysAgo: 6 },
  owasp: { passedPercent: 0.82, daysAgo: 0 },
  "mitre-attack": { passedPercent: 0.67, daysAgo: 0 },
};

export function getFrameworks(referenceDate = new Date()): Framework[] {
  return (Object.keys(FRAMEWORK_CATALOG) as FrameworkId[]).map((id) => {
    const catalog = FRAMEWORK_CATALOG[id];
    const state = FRAMEWORK_STATE[id];
    const passed = Math.round(catalog.totalControls * state.passedPercent);
    const failed = catalog.totalControls - passed;
    const lastEval = new Date(referenceDate);
    lastEval.setDate(lastEval.getDate() - state.daysAgo);
    lastEval.setHours(lastEval.getHours() - Math.floor(Math.random() * 24));

    return {
      id,
      name: catalog.name,
      shortName: catalog.shortName,
      description: catalog.description,
      totalControls: catalog.totalControls,
      passedControls: passed,
      failedControls: failed,
      compliancePercent: Math.round(state.passedPercent * 100),
      lastEvaluatedAt: lastEval.toISOString(),
    };
  });
}
