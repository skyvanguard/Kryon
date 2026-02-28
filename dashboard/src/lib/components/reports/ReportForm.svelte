<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import type { Client } from '$lib/api/clients';

	export let clients: Client[] = [];
	export let generating = false;

	const dispatch = createEventDispatcher();

	let client_id = '';
	let report_type = 'technical';
	let format = 'html';

	function handleSubmit() {
		dispatch('generate', { client_id: client_id || undefined, report_type, format });
	}
</script>

<form on:submit|preventDefault={handleSubmit} class="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
	<h3 class="text-sm font-semibold text-gray-300">Generate Report</h3>

	<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
		<div>
			<label class="block text-xs text-gray-500 mb-1" for="rpt-client">Client</label>
			<select
				id="rpt-client"
				bind:value={client_id}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			>
				<option value="">All clients</option>
				{#each clients as c}
					<option value={c.id}>{c.name}</option>
				{/each}
			</select>
		</div>

		<div>
			<label class="block text-xs text-gray-500 mb-1" for="rpt-type">Report Type</label>
			<select
				id="rpt-type"
				bind:value={report_type}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			>
				<option value="technical">Technical</option>
				<option value="executive">Executive</option>
				<option value="compliance">Compliance</option>
			</select>
		</div>

		<div>
			<label class="block text-xs text-gray-500 mb-1" for="rpt-format">Format</label>
			<select
				id="rpt-format"
				bind:value={format}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			>
				<option value="html">HTML</option>
				<option value="pdf">PDF</option>
			</select>
		</div>
	</div>

	<button
		type="submit"
		disabled={generating}
		class="px-4 py-2 bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
	>
		{generating ? 'Generating...' : 'Generate Report'}
	</button>
</form>
