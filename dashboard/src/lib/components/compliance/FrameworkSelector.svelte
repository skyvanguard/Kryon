<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import type { ComplianceFramework } from '$lib/api/compliance';

	export let frameworks: ComplianceFramework[] = [];
	export let selected: string = '';

	const dispatch = createEventDispatcher();

	function select(id: string) {
		selected = id;
		dispatch('select', id);
	}
</script>

<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
	{#each frameworks as fw}
		<button
			on:click={() => select(fw.id)}
			class="p-3 rounded-lg border text-left transition-all {selected === fw.id
				? 'border-kryon-500 bg-kryon-500/10'
				: 'border-gray-700 bg-gray-800 hover:border-gray-600'}"
		>
			<p class="text-sm font-medium text-gray-200">{fw.name}</p>
			<p class="text-xs text-gray-500 mt-1">{fw.controls} controls</p>
		</button>
	{/each}
</div>
