<script lang="ts">
	import type { ClientProgress } from '$lib/api/clients';

	export let progress: ClientProgress | null = null;

	$: total = progress ? progress.critical + progress.high + progress.medium + progress.low : 0;
	$: pCritical = total > 0 && progress ? (progress.critical / total) * 100 : 0;
	$: pHigh = total > 0 && progress ? (progress.high / total) * 100 : 0;
	$: pMedium = total > 0 && progress ? (progress.medium / total) * 100 : 0;
	$: pLow = total > 0 && progress ? (progress.low / total) * 100 : 0;
</script>

<div class="bg-gray-900 border border-gray-800 rounded-lg p-5">
	<h3 class="text-sm font-semibold text-gray-300 mb-4">Risk Distribution</h3>

	{#if !progress || total === 0}
		<p class="text-gray-600 text-sm">No findings data yet.</p>
	{:else}
		<div class="flex h-6 rounded overflow-hidden mb-4">
			{#if pCritical > 0}
				<div class="bg-red-600" style="width: {pCritical}%" title="Critical: {progress.critical}"></div>
			{/if}
			{#if pHigh > 0}
				<div class="bg-orange-500" style="width: {pHigh}%" title="High: {progress.high}"></div>
			{/if}
			{#if pMedium > 0}
				<div class="bg-yellow-500" style="width: {pMedium}%" title="Medium: {progress.medium}"></div>
			{/if}
			{#if pLow > 0}
				<div class="bg-blue-500" style="width: {pLow}%" title="Low: {progress.low}"></div>
			{/if}
		</div>

		<div class="grid grid-cols-2 gap-3 text-sm">
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 bg-red-600 rounded"></span>
				<span class="text-gray-400">Critical: {progress.critical}</span>
			</div>
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 bg-orange-500 rounded"></span>
				<span class="text-gray-400">High: {progress.high}</span>
			</div>
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 bg-yellow-500 rounded"></span>
				<span class="text-gray-400">Medium: {progress.medium}</span>
			</div>
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 bg-blue-500 rounded"></span>
				<span class="text-gray-400">Low: {progress.low}</span>
			</div>
		</div>

		<div class="mt-4 pt-3 border-t border-gray-800 flex justify-between text-xs text-gray-500">
			<span>Total findings: {progress.total_findings}</span>
			<span>Remediated: {progress.remediated}</span>
			<span>Risk score: {progress.risk_score?.toFixed(1) ?? 'N/A'}</span>
		</div>
	{/if}
</div>
