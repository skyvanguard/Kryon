<script lang="ts">
	import type { CoverageData } from '$lib/api/mitre';

	export let coverage: CoverageData | null = null;

	const tactics = [
		{ id: 'TA0043', name: 'Recon' },
		{ id: 'TA0042', name: 'Resource Dev' },
		{ id: 'TA0001', name: 'Initial Access' },
		{ id: 'TA0002', name: 'Execution' },
		{ id: 'TA0003', name: 'Persistence' },
		{ id: 'TA0004', name: 'Priv Esc' },
		{ id: 'TA0005', name: 'Def Evasion' },
		{ id: 'TA0006', name: 'Cred Access' },
		{ id: 'TA0007', name: 'Discovery' },
		{ id: 'TA0008', name: 'Lateral Move' },
		{ id: 'TA0009', name: 'Collection' },
		{ id: 'TA0011', name: 'C2' },
		{ id: 'TA0010', name: 'Exfiltration' },
		{ id: 'TA0040', name: 'Impact' }
	];

	$: uncoveredSet = new Set(coverage?.uncovered_tactics || []);
</script>

<div class="bg-gray-800 rounded-lg p-4">
	<div class="flex items-center justify-between mb-4">
		<h3 class="text-sm font-semibold text-gray-300">MITRE ATT&CK Coverage</h3>
		{#if coverage}
			<span class="text-xs text-gray-400">
				{coverage.tactics_covered}/{coverage.tactics_total} tactics ({coverage.tactic_coverage_pct}%)
				&bull; {coverage.techniques_covered} techniques
			</span>
		{/if}
	</div>

	<div class="grid grid-cols-7 lg:grid-cols-14 gap-1">
		{#each tactics as tactic}
			<div
				class="rounded p-2 text-center transition-colors {uncoveredSet.has(tactic.id)
					? 'bg-red-500/20 border border-red-500/30'
					: 'bg-green-500/20 border border-green-500/30'}"
				title="{tactic.name} ({tactic.id})"
			>
				<p class="text-[10px] font-medium {uncoveredSet.has(tactic.id) ? 'text-red-400' : 'text-green-400'}">
					{tactic.name}
				</p>
			</div>
		{/each}
	</div>

	<div class="flex gap-4 mt-3 text-xs text-gray-500">
		<span class="flex items-center gap-1">
			<span class="w-3 h-3 rounded bg-green-500/20 border border-green-500/30"></span> Covered
		</span>
		<span class="flex items-center gap-1">
			<span class="w-3 h-3 rounded bg-red-500/20 border border-red-500/30"></span> Not covered
		</span>
	</div>
</div>
