import { apiFetch } from './client';

export interface ComplianceFramework {
	id: string;
	name: string;
	controls: number;
}

export interface ComplianceAssessment {
	framework: string;
	controls_assessed: number;
	controls_passed: number;
	controls_failed: number;
	compliance_percentage: number;
	evidence: { control_id: string; status: string; findings: unknown[] }[];
}

export interface ZeroTrustAssessment {
	pillar: string;
	maturity_level: string;
	controls_assessed: number;
	controls_met: number;
	gaps: string[];
}

export async function listFrameworks(): Promise<{ frameworks: ComplianceFramework[] }> {
	return apiFetch('/compliance/frameworks');
}

export async function assessCompliance(
	framework: string,
	client_id = ''
): Promise<ComplianceAssessment> {
	return apiFetch('/compliance/assess', {
		method: 'POST',
		body: JSON.stringify({ framework, client_id })
	});
}

export async function getZeroTrustAssessment(
	client_id = ''
): Promise<{ assessments: ZeroTrustAssessment[] }> {
	const params = new URLSearchParams();
	if (client_id) params.set('client_id', client_id);
	return apiFetch(`/compliance/zero-trust?${params}`);
}
