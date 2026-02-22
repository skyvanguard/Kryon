<script lang="ts">
	import { onMount } from 'svelte';
	import { agents, loadAgents } from '$lib/stores/agents';
	import AgentCard from '$lib/components/agents/AgentCard.svelte';

	let health: { status: string; version: string; agents_count: number } | null = null;

	onMount(async () => {
		loadAgents();
		try {
			const resp = await fetch('/api/health');
			health = await resp.json();
		} catch {
			// API not available
		}
	});
</script>

<div class="flex-1 p-8">
	<!-- Hero -->
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">
			<span class="text-kryon-500">KRYON</span> Dashboard
		</h1>
		<p class="text-gray-400">Autonomous Cybersecurity Intelligence Platform</p>
		{#if health}
			<div class="mt-3 flex gap-4 text-sm">
				<span class="text-green-400">Server: {health.status}</span>
				<span class="text-gray-500">v{health.version}</span>
				<span class="text-gray-500">{health.agents_count} agents</span>
			</div>
		{:else}
			<p class="mt-3 text-sm text-yellow-500">API server not connected. Start with: kryon serve</p>
		{/if}
	</div>

	<!-- Agent grid -->
	<h2 class="text-lg font-semibold mb-4">Available Agents</h2>
	<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
		{#each $agents as agent}
			<AgentCard {agent} />
		{/each}
	</div>
</div>
