<script lang="ts">
	import { createEventDispatcher } from 'svelte';

	export let creating = false;

	const dispatch = createEventDispatcher();

	let target = '';
	let rule_type = 'ip';
	let action = 'allow';
	let notes = '';

	function handleSubmit() {
		dispatch('create', { target, rule_type, action, notes });
		target = '';
		notes = '';
	}
</script>

<form on:submit|preventDefault={handleSubmit} class="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
	<h3 class="text-sm font-semibold text-gray-300">Add Scope Rule</h3>

	<div class="grid grid-cols-1 md:grid-cols-4 gap-4">
		<div>
			<label class="block text-xs text-gray-500 mb-1" for="scope-target">Target *</label>
			<input
				id="scope-target"
				bind:value={target}
				required
				placeholder="192.168.1.0/24 or *.example.com"
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			/>
		</div>

		<div>
			<label class="block text-xs text-gray-500 mb-1" for="scope-type">Type</label>
			<select
				id="scope-type"
				bind:value={rule_type}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			>
				<option value="ip">IP / CIDR</option>
				<option value="domain">Domain</option>
				<option value="url">URL</option>
				<option value="port">Port Range</option>
			</select>
		</div>

		<div>
			<label class="block text-xs text-gray-500 mb-1" for="scope-action">Action</label>
			<select
				id="scope-action"
				bind:value={action}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			>
				<option value="allow">Allow</option>
				<option value="deny">Deny</option>
			</select>
		</div>

		<div>
			<label class="block text-xs text-gray-500 mb-1" for="scope-notes">Notes</label>
			<input
				id="scope-notes"
				bind:value={notes}
				placeholder="Optional notes"
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			/>
		</div>
	</div>

	<button
		type="submit"
		disabled={creating}
		class="px-4 py-2 bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
	>
		{creating ? 'Adding...' : 'Add Rule'}
	</button>
</form>
