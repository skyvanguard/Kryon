<script lang="ts">
	import { createEventDispatcher } from 'svelte';

	export let name = '';
	export let industry = '';
	export let contact_email = '';
	export let notes = '';
	export let submitLabel = 'Create Client';

	const dispatch = createEventDispatcher();

	function handleSubmit() {
		dispatch('submit', { name, industry, contact_email, notes });
	}
</script>

<form on:submit|preventDefault={handleSubmit} class="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
	<div>
		<label class="block text-xs text-gray-500 mb-1" for="name">Name *</label>
		<input
			id="name"
			bind:value={name}
			required
			class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			placeholder="Client name"
		/>
	</div>
	<div>
		<label class="block text-xs text-gray-500 mb-1" for="industry">Industry</label>
		<input
			id="industry"
			bind:value={industry}
			class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			placeholder="e.g. Finance, Healthcare"
		/>
	</div>
	<div>
		<label class="block text-xs text-gray-500 mb-1" for="email">Contact Email</label>
		<input
			id="email"
			bind:value={contact_email}
			type="email"
			class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			placeholder="contact@company.com"
		/>
	</div>
	<div>
		<label class="block text-xs text-gray-500 mb-1" for="notes">Notes</label>
		<textarea
			id="notes"
			bind:value={notes}
			rows="3"
			class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
			placeholder="Additional notes..."
		></textarea>
	</div>
	<button
		type="submit"
		class="px-4 py-2 bg-kryon-600 hover:bg-kryon-500 text-white text-sm font-medium rounded-lg transition-colors"
	>
		{submitLabel}
	</button>
</form>
