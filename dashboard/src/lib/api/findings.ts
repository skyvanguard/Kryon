import { apiFetch } from './client';

export interface Finding {
	id: string;
	scan_id: string;
	client_id: string;
	finding_json: string;
	status: string;
	first_seen: string;
	last_seen: string;
	occurrences: number;
}

export interface ParsedFinding {
	id: string;
	scan_id: string;
	client_id: string;
	title: string;
	severity: string;
	affected_asset: string;
	description: string;
	cvss_score: number | null;
	tool_source: string;
	remediation: string;
	status: string;
	first_seen: string;
	last_seen: string;
	occurrences: number;
}

export interface FindingsListResponse {
	items: Finding[];
	total: number;
	offset: number;
	limit: number;
}

export function parseFinding(f: Finding): ParsedFinding {
	let parsed: Record<string, unknown> = {};
	try {
		parsed = f.finding_json ? JSON.parse(f.finding_json) : {};
	} catch {
		/* invalid json */
	}
	return {
		id: f.id,
		scan_id: f.scan_id,
		client_id: f.client_id,
		title: (parsed.title as string) || (parsed.name as string) || 'Untitled',
		severity: (parsed.severity as string) || 'info',
		affected_asset: (parsed.affected_asset as string) || (parsed.host as string) || '',
		description: (parsed.description as string) || '',
		cvss_score: (parsed.cvss_score as number) ?? null,
		tool_source: (parsed.tool_source as string) || '',
		remediation: (parsed.remediation as string) || '',
		status: f.status,
		first_seen: f.first_seen,
		last_seen: f.last_seen,
		occurrences: f.occurrences
	};
}

export async function listFindings(
	offset = 0,
	limit = 50,
	severity?: string,
	status?: string,
	client_id?: string,
	tool_source?: string
): Promise<FindingsListResponse> {
	const params = new URLSearchParams();
	params.set('offset', offset.toString());
	params.set('limit', limit.toString());
	if (severity) params.set('severity', severity);
	if (status) params.set('status', status);
	if (client_id) params.set('client_id', client_id);
	if (tool_source) params.set('tool_source', tool_source);
	return apiFetch<FindingsListResponse>(`/findings?${params}`);
}

export async function getFinding(id: string): Promise<Finding> {
	return apiFetch<Finding>(`/findings/${id}`);
}

export async function updateFindingStatus(id: string, status: string): Promise<void> {
	await apiFetch(`/findings/${id}/status`, {
		method: 'PUT',
		body: JSON.stringify({ status })
	});
}
