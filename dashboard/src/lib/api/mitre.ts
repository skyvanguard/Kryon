import { apiFetch } from './client';

export interface CoverageData {
	techniques_covered: number;
	techniques_list: string[];
	tactics_covered: number;
	tactics_total: number;
	tactic_coverage_pct: number;
	uncovered_tactics: string[];
}

export async function getMITRECoverage(client_id = ''): Promise<CoverageData> {
	const params = new URLSearchParams();
	if (client_id) params.set('client_id', client_id);
	return apiFetch(`/validation/coverage?${params}`);
}
