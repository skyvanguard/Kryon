<script lang="ts">
	import { afterUpdate } from 'svelte';
	import { scanLogs } from '$lib/stores/scans';

	let logContainer: HTMLDivElement;

	afterUpdate(() => {
		if (logContainer) {
			logContainer.scrollTop = logContainer.scrollHeight;
		}
	});
</script>

<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
	<div class="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
		<h3 class="text-sm font-semibold text-gray-300">Scan Log</h3>
		<span class="text-xs text-gray-600">{$scanLogs.length} entries</span>
	</div>

	<div
		bind:this={logContainer}
		class="px-4 py-3 font-mono text-xs max-h-64 overflow-y-auto space-y-0.5 bg-gray-950"
	>
		{#if $scanLogs.length === 0}
			<span class="text-gray-600">Waiting for scan to start...</span>
		{:else}
			{#each $scanLogs as log}
				<div class="text-gray-400 leading-relaxed whitespace-pre-wrap">{log}</div>
			{/each}
		{/if}
	</div>
</div>
