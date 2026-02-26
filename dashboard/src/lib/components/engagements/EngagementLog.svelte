<script lang="ts">
	import { afterUpdate } from 'svelte';

	export let logs: string[] = [];

	let container: HTMLElement;

	afterUpdate(() => {
		if (container) {
			container.scrollTop = container.scrollHeight;
		}
	});
</script>

<div
	bind:this={container}
	class="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4 h-48 overflow-y-auto font-mono text-xs text-gray-400 space-y-0.5"
>
	{#if logs.length === 0}
		<p class="text-gray-600">Waiting for activity...</p>
	{:else}
		{#each logs as log}
			<p>{log}</p>
		{/each}
	{/if}
</div>
