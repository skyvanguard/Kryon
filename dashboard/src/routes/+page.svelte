<script lang="ts">
	import { onMount } from 'svelte';
	import { agents, loadAgents } from '$lib/stores/agents';
	import AgentCard from '$lib/components/agents/AgentCard.svelte';

	let health: { status: string; version: string; agents_count: number } | null = null;
	let searchQuery = '';
	let showPatterns = false;

	$: coreAgents = $agents.filter((a) => a.category === 'agent');
	$: patterns = $agents.filter((a) => a.category === 'pattern');

	$: filteredAgents = searchQuery
		? coreAgents.filter(
				(a) =>
					a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
					a.key.toLowerCase().includes(searchQuery.toLowerCase()) ||
					(a.description || '').toLowerCase().includes(searchQuery.toLowerCase())
			)
		: coreAgents;

	$: filteredPatterns = searchQuery
		? patterns.filter(
				(a) =>
					a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
					(a.description || '').toLowerCase().includes(searchQuery.toLowerCase())
			)
		: patterns;

	onMount(async () => {
		loadAgents();
		try {
			const resp = await fetch('/api/v1/health');
			health = await resp.json();
		} catch {
			// API not available
		}
	});
</script>

<div class="flex-1 p-8 max-w-7xl mx-auto">
	<!-- Hero -->
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">
			<span class="text-kryon-500">KRYON</span> Dashboard
		</h1>
		<p class="text-gray-400">Autonomous Cybersecurity Intelligence Platform</p>
		{#if health}
			<div class="mt-3 flex gap-4 text-sm">
				<span class="px-2 py-0.5 bg-green-500/10 text-green-400 rounded-full text-xs font-medium">
					{health.status.toUpperCase()}
				</span>
				<span class="text-gray-500">v{health.version}</span>
				<span class="text-gray-500">{coreAgents.length} agents</span>
				{#if patterns.length > 0}
					<span class="text-gray-500">{patterns.length} patterns</span>
				{/if}
			</div>
		{:else}
			<p class="mt-3 text-sm text-yellow-500/80">Connecting to API server...</p>
		{/if}
	</div>

	<!-- Search -->
	<div class="mb-6">
		<input
			type="text"
			bind:value={searchQuery}
			placeholder="Search agents..."
			class="w-full max-w-md bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-kryon-500/50 focus:ring-1 focus:ring-kryon-500/20"
		/>
	</div>

	<!-- Core Agents -->
	<section class="mb-10">
		<h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
			<span class="text-kryon-400">Agents</span>
			<span class="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
				{filteredAgents.length}
			</span>
		</h2>
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each filteredAgents as agent (agent.key)}
				<AgentCard {agent} />
			{/each}
		</div>
		{#if filteredAgents.length === 0 && searchQuery}
			<p class="text-gray-500 text-sm">No agents match "{searchQuery}"</p>
		{/if}
	</section>

	<!-- Patterns (collapsible) -->
	{#if patterns.length > 0}
		<section>
			<button
				on:click={() => (showPatterns = !showPatterns)}
				class="text-lg font-semibold mb-4 flex items-center gap-2 hover:text-kryon-400 transition-colors"
			>
				<span class="text-gray-400 text-sm">{showPatterns ? '▼' : '▶'}</span>
				<span class="text-gray-300">Agentic Patterns</span>
				<span class="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
					{filteredPatterns.length}
				</span>
			</button>
			{#if showPatterns}
				<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
					{#each filteredPatterns as pattern (pattern.key)}
						<div
							class="bg-gray-800/30 border border-gray-700/30 rounded-xl p-5 border-dashed"
						>
							<div class="flex items-start gap-3">
								<span class="text-2xl mt-0.5">🔀</span>
								<div class="flex-1 min-w-0">
									<h3 class="text-gray-300 font-semibold truncate">{pattern.name}</h3>
									<p class="text-gray-500 text-sm mt-1 line-clamp-2 leading-relaxed">
										{pattern.description || 'Agentic pattern'}
									</p>
								</div>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</section>
	{/if}
</div>
