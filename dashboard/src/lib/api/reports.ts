import { apiFetch } from './client';

export interface ReportRequest {
	client_id?: string;
	scan_id?: string;
	report_type?: string;
	format?: string;
}

export interface Report {
	id: string;
	filename: string;
	format: string;
	report_type: string;
	created_at: string;
	size_bytes: number;
}

export async function generateReport(req: ReportRequest): Promise<Report> {
	return apiFetch<Report>('/reports/generate', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function listReports(): Promise<Report[]> {
	return apiFetch<Report[]>('/reports');
}

export async function downloadReport(id: string): Promise<Blob> {
	const token = localStorage.getItem('kryon_token');
	const apiKey = localStorage.getItem('kryon_api_key');
	const headers: Record<string, string> = {};
	if (token) headers['Authorization'] = `Bearer ${token}`;
	else if (apiKey) headers['X-API-Key'] = apiKey;

	const resp = await fetch(`/api/v1/reports/${id}/download`, { headers });
	if (!resp.ok) throw new Error(`Download failed: ${resp.status}`);
	return resp.blob();
}
