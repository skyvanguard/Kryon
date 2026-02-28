<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import type { ScopeRule } from '$lib/api/scope';

	export let rules: ScopeRule[] = [];

	const dispatch = createEventDispatcher();

	function handleDelete(rule: ScopeRule) {
		if (!confirm(`Delete scope rule for "${rule.target}"?`)) return;
		dispatch('delete', { id: rule.id });
	}
</script>

{#if rules.length === 0}
	<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
		<p class="text-gray-500">No scope rules defined. Add one to restrict agent operations.</p>
	</div>
{:else}
	<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
		<table class="w-full text-sm">
			<thead>
				<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
					<th class="px-4 py-2">Target</th>
					<th class="px-4 py-2">Type</th>
					<th class="px-4 py-2">Action</th>
					<th class="px-4 py-2">Notes</th>
					<th class="px-4 py-2">Created</th>
					<th class="px-4 py-2"></th>
				</tr>
			</thead>
			<tbody>
				{#each rules as rule (rule.id)}
					<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
						<td class="px-4 py-2 text-gray-200 font-mono text-xs">{rule.target}</td>
						<td class="px-4 py-2">
							<span class="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400">
								{rule.rule_type}
							</span>
						</td>
						<td class="px-4 py-2">
							<span class="px-2 py-0.5 rounded text-xs {
								rule.action === 'allow' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
							}">
								{rule.action}
							</span>
						</td>
						<td class="px-4 py-2 text-gray-500 text-xs">{rule.notes || '—'}</td>
						<td class="px-4 py-2 text-gray-500 text-xs">
							{rule.created_at ? new Date(rule.created_at).toLocaleDateString() : '—'}
						</td>
						<td class="px-4 py-2">
							<button
								on:click={() => handleDelete(rule)}
								class="text-red-400 hover:text-red-300 text-xs transition-colors"
							>
								Delete
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
