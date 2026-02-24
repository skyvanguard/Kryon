/** Auto-scan API calls and SSE client. */

import { apiFetch } from './client';

export interface AutoScanRequest {
	targets: string[];
	profile?: string;
	client_id?: string;
	max_time_hours?: number;
	stealth_level?: string;
	output_format?: string;
	compliance_frameworks?: string[];
}

export interface AutoScanResponse {
	scan_id: string;
	status: string;
	message: string;
}

export interface AutoScanStatus {
	scan_id: string;
	status: string;
	phase_progress: number;
	hosts_discovered: number;
	hosts_scanned: number;
	findings_count: number;
	critical_count: number;
	high_count: number;
	elapsed_seconds: number;
	log_messages: string[];
	report_path: string | null;
	error: string | null;
}

export interface AutoScanFinding {
	id: string;
	title: string;
	severity: string;
	affected_asset: string;
	description: string;
	cvss_score: number | null;
	tool_source: string;
	remediation: string;
}

export async function startAutoScan(req: AutoScanRequest): Promise<AutoScanResponse> {
	return apiFetch<AutoScanResponse>('/scans/auto', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function getAutoScanStatus(scanId: string): Promise<AutoScanStatus> {
	return apiFetch<AutoScanStatus>(`/scans/auto/${scanId}`);
}

export async function getAutoScanFindings(scanId: string): Promise<AutoScanFinding[]> {
	return apiFetch<AutoScanFinding[]>(`/scans/auto/${scanId}/findings`);
}

export async function cancelAutoScan(scanId: string): Promise<void> {
	await apiFetch(`/scans/auto/${scanId}`, { method: 'DELETE' });
}

export function connectScanSSE(
	scanId: string,
	onStatus: (status: AutoScanStatus) => void,
	onLog: (message: string) => void,
	onDone: (status: AutoScanStatus) => void
): EventSource {
	const es = new EventSource(`/api/scans/auto/${scanId}/stream`);

	es.addEventListener('status', (e: MessageEvent) => {
		try {
			onStatus(JSON.parse(e.data));
		} catch {
			/* skip */
		}
	});

	es.addEventListener('log', (e: MessageEvent) => {
		try {
			const data = JSON.parse(e.data);
			onLog(data.message || '');
		} catch {
			/* skip */
		}
	});

	es.addEventListener('done', (e: MessageEvent) => {
		try {
			onDone(JSON.parse(e.data));
		} catch {
			/* skip */
		}
		es.close();
	});

	es.onerror = () => {
		es.close();
	};

	return es;
}
