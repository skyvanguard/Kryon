import { writable, derived } from 'svelte/store';
import type { ParsedFinding } from '$lib/api/findings';
import { listFindings, parseFinding } from '$lib/api/findings';

export const findings = writable<ParsedFinding[]>([]);
export const findingsTotal = writable(0);
export const findingsLoading = writable(false);
export const findingsError = writable<string | null>(null);

export const criticalCount = derived(findings, ($f) => $f.filter((f) => f.severity === 'critical').length);
export const highCount = derived(findings, ($f) => $f.filter((f) => f.severity === 'high').length);
export const mediumCount = derived(findings, ($f) => $f.filter((f) => f.severity === 'medium').length);
export const lowCount = derived(findings, ($f) => $f.filter((f) => f.severity === 'low').length);

export async function loadFindings(
	offset = 0,
	limit = 100,
	severity?: string,
	status?: string,
	client_id?: string
) {
	findingsLoading.set(true);
	findingsError.set(null);
	try {
		const resp = await listFindings(offset, limit, severity, status, client_id);
		findings.set(resp.items.map(parseFinding));
		findingsTotal.set(resp.total);
	} catch (e) {
		findingsError.set(e instanceof Error ? e.message : 'Failed to load findings');
	} finally {
		findingsLoading.set(false);
	}
}
