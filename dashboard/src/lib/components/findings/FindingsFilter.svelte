<script lang="ts">
	import { createEventDispatcher } from 'svelte';

	export let severity = '';
	export let status = '';

	const dispatch = createEventDispatcher();

	function apply() {
		dispatch('filter', { severity, status });
	}
</script>

<div class="flex flex-wrap gap-3 items-center">
	<select
		bind:value={severity}
		on:change={apply}
		class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
	>
		<option value="">All Severities</option>
		<option value="critical">Critical</option>
		<option value="high">High</option>
		<option value="medium">Medium</option>
		<option value="low">Low</option>
		<option value="info">Info</option>
	</select>

	<select
		bind:value={status}
		on:change={apply}
		class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
	>
		<option value="">All Statuses</option>
		<option value="open">Open</option>
		<option value="remediated">Remediated</option>
		<option value="accepted">Accepted</option>
		<option value="false_positive">False Positive</option>
	</select>

	<button
		on:click={() => {
			severity = '';
			status = '';
			apply();
		}}
		class="text-xs text-gray-500 hover:text-gray-300 transition-colors"
	>
		Clear filters
	</button>
</div>
