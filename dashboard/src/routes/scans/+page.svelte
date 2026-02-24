<script lang="ts">
	import { onDestroy } from 'svelte';
	import ScanForm from '$lib/components/scans/ScanForm.svelte';
	import ScanProgress from '$lib/components/scans/ScanProgress.svelte';
	import FindingsTable from '$lib/components/scans/FindingsTable.svelte';
	import ScanLog from '$lib/components/scans/ScanLog.svelte';
	import {
		currentScanId,
		scanStatus,
		scanFindings,
		scanLogs,
		isScanRunning,
		resetScanState,
		addScanLog
	} from '$lib/stores/scans';
	import {
		startAutoScan,
		connectScanSSE,
		getAutoScanFindings,
		cancelAutoScan,
		type AutoScanRequest
	} from '$lib/api/scans';

	let eventSource: EventSource | null = null;
	let findingsInterval: ReturnType<typeof setInterval> | null = null;

	async function handleStart(e: CustomEvent<AutoScanRequest>) {
		resetScanState();

		try {
			const resp = await startAutoScan(e.detail);
			currentScanId.set(resp.scan_id);
			isScanRunning.set(true);

			// Connect SSE for real-time updates
			eventSource = connectScanSSE(
				resp.scan_id,
				(status) => {
					scanStatus.set(status);
				},
				(message) => {
					addScanLog(message);
				},
				(status) => {
					scanStatus.set(status);
					isScanRunning.set(false);
					// Fetch final findings
					refreshFindings();
				}
			);

			// Poll findings periodically
			findingsInterval = setInterval(refreshFindings, 5000);
		} catch (err) {
			addScanLog(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
			isScanRunning.set(false);
		}
	}

	async function refreshFindings() {
		const id = $currentScanId;
		if (!id) return;
		try {
			const findings = await getAutoScanFindings(id);
			scanFindings.set(findings);
		} catch {
			/* ignore */
		}
	}

	async function handleCancel() {
		const id = $currentScanId;
		if (!id) return;
		try {
			await cancelAutoScan(id);
			isScanRunning.set(false);
			addScanLog('Scan cancelled by user');
		} catch {
			/* ignore */
		}
	}

	function handleNewScan() {
		cleanup();
		resetScanState();
	}

	function cleanup() {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
		if (findingsInterval) {
			clearInterval(findingsInterval);
			findingsInterval = null;
		}
	}

	onDestroy(cleanup);
</script>

<div class="flex-1 p-6 max-w-6xl mx-auto w-full space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-xl font-bold text-kryon-400">Autonomous Scans</h1>
		{#if $currentScanId}
			<div class="flex items-center gap-3">
				<span class="text-xs text-gray-500 font-mono">ID: {$currentScanId}</span>
				{#if $isScanRunning}
					<button
						on:click={handleCancel}
						class="text-xs bg-red-900 hover:bg-red-800 text-red-300 px-3 py-1 rounded transition-colors"
					>
						Cancel
					</button>
				{:else}
					<button
						on:click={handleNewScan}
						class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1 rounded transition-colors"
					>
						New Scan
					</button>
				{/if}
			</div>
		{/if}
	</div>

	{#if !$currentScanId}
		<ScanForm on:start={handleStart} />
	{:else}
		<ScanProgress />

		<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
			<FindingsTable />
			<ScanLog />
		</div>
	{/if}
</div>
