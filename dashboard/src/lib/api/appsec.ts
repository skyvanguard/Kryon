import { apiFetch } from './client';

export interface SASTScanRequest {
	target_path: string;
	config?: string;
	severity?: string;
	language?: string;
}

export interface DASTScanRequest {
	target_url: string;
	minutes?: number;
	ajax_spider?: boolean;
}

export interface SBOMRequest {
	target: string;
	format?: string;
	source_type?: string;
}

export interface ScanResult {
	scan_id: string;
	tool: string;
	result: string;
}

export async function runSASTScan(req: SASTScanRequest): Promise<ScanResult> {
	return apiFetch<ScanResult>('/appsec/sast', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function runDASTScan(req: DASTScanRequest): Promise<ScanResult> {
	return apiFetch<ScanResult>('/appsec/dast', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function runSBOMScan(req: SBOMRequest): Promise<ScanResult> {
	return apiFetch<ScanResult>('/appsec/sbom', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}
