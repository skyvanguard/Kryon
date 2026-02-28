<script lang="ts">
	import type { ParsedFinding } from '$lib/api/findings';
	import { updateFindingStatus } from '$lib/api/findings';
	import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';
	import { createEventDispatcher } from 'svelte';

	export let finding: ParsedFinding;

	const dispatch = createEventDispatcher();

	async function changeStatus(newStatus: string) {
		try {
			await updateFindingStatus(finding.id, newStatus);
			finding.status = newStatus;
			dispatch('updated');
		} catch {
			/* ignore */
		}
	}
</script>

<div class="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
	<div class="flex items-start justify-between">
		<div>
			<h3 class="text-lg font-semibold text-gray-200">{finding.title}</h3>
			<div class="flex items-center gap-3 mt-2">
				<SeverityBadge severity={finding.severity} />
				{#if finding.cvss_score}
					<span class="text-xs text-gray-500">CVSS {finding.cvss_score}</span>
				{/if}
				<span class="text-xs text-gray-600">{finding.tool_source}</span>
			</div>
		</div>
		<div class="flex gap-2">
			{#each ['open', 'remediated', 'accepted', 'false_positive'] as s}
				<button
					on:click={() => changeStatus(s)}
					class="px-2 py-1 text-xs rounded transition-colors {finding.status === s
						? 'bg-kryon-600 text-white'
						: 'bg-gray-800 text-gray-400 hover:bg-gray-700'}"
				>
					{s.replace('_', ' ')}
				</button>
			{/each}
		</div>
	</div>

	{#if finding.affected_asset}
		<div>
			<span class="text-xs text-gray-500 uppercase">Asset</span>
			<p class="text-sm text-gray-300 mt-1">{finding.affected_asset}</p>
		</div>
	{/if}

	{#if finding.description}
		<div>
			<span class="text-xs text-gray-500 uppercase">Description</span>
			<p class="text-sm text-gray-400 mt-1 whitespace-pre-wrap">{finding.description}</p>
		</div>
	{/if}

	{#if finding.remediation}
		<div>
			<span class="text-xs text-gray-500 uppercase">Remediation</span>
			<p class="text-sm text-green-400/80 mt-1 whitespace-pre-wrap">{finding.remediation}</p>
		</div>
	{/if}

	<div class="flex gap-6 text-xs text-gray-600 pt-2 border-t border-gray-800">
		<span>First seen: {new Date(finding.first_seen).toLocaleDateString()}</span>
		<span>Last seen: {new Date(finding.last_seen).toLocaleDateString()}</span>
		<span>Occurrences: {finding.occurrences}</span>
		<span>Scan: {finding.scan_id}</span>
	</div>
</div>
