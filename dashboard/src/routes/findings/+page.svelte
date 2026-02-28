<script lang="ts">
	import { onMount } from 'svelte';
	import { findings, findingsLoading, findingsError, loadFindings, findingsTotal } from '$lib/stores/findings';
	import FindingsStats from '$lib/components/findings/FindingsStats.svelte';
	import FindingsFilter from '$lib/components/findings/FindingsFilter.svelte';
	import FindingDetail from '$lib/components/findings/FindingDetail.svelte';
	import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';

	let filterSeverity = '';
	let filterStatus = '';
	let selectedId: string | null = null;

	$: selectedFinding = $findings.find((f) => f.id === selectedId) ?? null;

	function handleFilter(e: CustomEvent<{ severity: string; status: string }>) {
		filterSeverity = e.detail.severity;
		filterStatus = e.detail.status;
		loadFindings(0, 100, filterSeverity || undefined, filterStatus || undefined);
	}

	function exportCSV() {
		const header = 'ID,Title,Severity,CVSS,Asset,Status,Tool,First Seen\n';
		const rows = $findings
			.map(
				(f) =>
					`"${f.id}","${f.title}","${f.severity}","${f.cvss_score ?? ''}","${f.affected_asset}","${f.status}","${f.tool_source}","${f.first_seen}"`
			)
			.join('\n');
		const blob = new Blob([header + rows], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `kryon-findings-${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function exportJSON() {
		const blob = new Blob([JSON.stringify($findings, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `kryon-findings-${new Date().toISOString().slice(0, 10)}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	onMount(() => {
		loadFindings();
		const interval = setInterval(() => loadFindings(0, 100, filterSeverity || undefined, filterStatus || undefined), 30000);
		return () => clearInterval(interval);
	});
</script>

<div class="flex-1 p-8 max-w-7xl mx-auto w-full space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-kryon-400">Findings</h1>
			<p class="text-gray-500 text-sm mt-1">Consolidated security assessment results</p>
		</div>
		<div class="flex gap-2">
			<button
				on:click={exportCSV}
				class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded transition-colors"
			>
				Export CSV
			</button>
			<button
				on:click={exportJSON}
				class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded transition-colors"
			>
				Export JSON
			</button>
		</div>
	</div>

	<FindingsStats />

	<FindingsFilter severity={filterSeverity} status={filterStatus} on:filter={handleFilter} />

	{#if $findingsError}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-4 text-red-300 text-sm">
			{$findingsError}
		</div>
	{/if}

	{#if selectedFinding}
		<div class="mb-4">
			<button
				on:click={() => (selectedId = null)}
				class="text-xs text-gray-500 hover:text-gray-300 mb-2"
			>
				&larr; Back to list
			</button>
			<FindingDetail finding={selectedFinding} on:updated={() => loadFindings(0, 100, filterSeverity || undefined, filterStatus || undefined)} />
		</div>
	{:else if $findingsLoading && $findings.length === 0}
		<div class="text-gray-500 text-sm py-8 text-center">Loading findings...</div>
	{:else if $findings.length === 0}
		<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
			<p class="text-gray-500">No findings yet. Run a scan to discover vulnerabilities.</p>
		</div>
	{:else}
		<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
			<div class="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
				<h3 class="text-sm font-semibold text-gray-300">
					{$findings.length} of {$findingsTotal} findings
				</h3>
			</div>
			<div class="overflow-x-auto max-h-[600px] overflow-y-auto">
				<table class="w-full text-sm">
					<thead class="sticky top-0 bg-gray-900 z-10">
						<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
							<th class="px-4 py-2">Severity</th>
							<th class="px-4 py-2">Title</th>
							<th class="px-4 py-2">Asset</th>
							<th class="px-4 py-2">CVSS</th>
							<th class="px-4 py-2">Tool</th>
							<th class="px-4 py-2">Status</th>
							<th class="px-4 py-2">First Seen</th>
						</tr>
					</thead>
					<tbody>
						{#each $findings as finding (finding.id)}
							<tr
								class="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer"
								on:click={() => (selectedId = finding.id)}
							>
								<td class="px-4 py-2">
									<SeverityBadge severity={finding.severity} />
								</td>
								<td class="px-4 py-2 text-gray-200 max-w-xs truncate">{finding.title}</td>
								<td class="px-4 py-2 text-gray-400 font-mono text-xs">{finding.affected_asset}</td>
								<td class="px-4 py-2 text-gray-400">
									{finding.cvss_score ?? '-'}
								</td>
								<td class="px-4 py-2 text-gray-500 text-xs">{finding.tool_source}</td>
								<td class="px-4 py-2">
									<span
										class="px-2 py-0.5 rounded text-xs {finding.status === 'open'
											? 'bg-red-900/50 text-red-300'
											: finding.status === 'remediated'
												? 'bg-green-900/50 text-green-300'
												: 'bg-gray-800 text-gray-400'}"
									>
										{finding.status}
									</span>
								</td>
								<td class="px-4 py-2 text-gray-500 text-xs">
									{new Date(finding.first_seen).toLocaleDateString()}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{/if}
</div>
