<script lang="ts">
	import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';

	export let findings: { rule_id: string; severity: string; path: string; line: number; message: string }[] = [];
</script>

<div class="bg-gray-800 rounded-lg p-4">
	<h3 class="text-sm font-semibold text-gray-300 mb-3">SAST Findings ({findings.length})</h3>
	{#if findings.length > 0}
		<div class="space-y-2">
			{#each findings as finding}
				<div class="bg-gray-900 rounded p-3 border border-gray-700/50">
					<div class="flex items-center gap-2 mb-1">
						<SeverityBadge severity={finding.severity} />
						<span class="text-sm text-gray-200 font-mono">{finding.rule_id}</span>
					</div>
					<p class="text-xs text-gray-400 mb-1">{finding.message}</p>
					<p class="text-xs text-gray-500 font-mono">{finding.path}:{finding.line}</p>
				</div>
			{/each}
		</div>
	{:else}
		<p class="text-gray-500 text-sm">No SAST findings. Run a scan to check for vulnerabilities.</p>
	{/if}
</div>
