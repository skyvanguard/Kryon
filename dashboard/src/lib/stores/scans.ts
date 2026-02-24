/** Auto-scan state store. */

import { writable, derived } from 'svelte/store';
import type { AutoScanStatus, AutoScanFinding } from '$lib/api/scans';

export const currentScanId = writable<string | null>(null);
export const scanStatus = writable<AutoScanStatus | null>(null);
export const scanFindings = writable<AutoScanFinding[]>([]);
export const scanLogs = writable<string[]>([]);
export const isScanRunning = writable(false);

export const scanPhaseLabel = derived(scanStatus, ($s) => {
	if (!$s) return '';
	const labels: Record<string, string> = {
		initializing: 'Initializing...',
		recon: 'Reconnaissance',
		vuln_scan: 'Vulnerability Assessment',
		exploitation: 'Exploitation',
		reporting: 'Report Generation',
		completed: 'Completed',
		failed: 'Failed'
	};
	return labels[$s.status] || $s.status;
});

export function resetScanState() {
	currentScanId.set(null);
	scanStatus.set(null);
	scanFindings.set([]);
	scanLogs.set([]);
	isScanRunning.set(false);
}

export function addScanLog(message: string) {
	scanLogs.update((l) => [...l, message]);
}
