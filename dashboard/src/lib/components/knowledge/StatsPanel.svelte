<script lang="ts">
	import { onMount } from 'svelte';
	import { knowledgeStats, isScraping, scrapeMessage } from '$lib/stores/knowledge';
	import { getKnowledgeStats, startScrape, getScrapeStatus } from '$lib/api/knowledge';

	let loading = false;

	async function loadStats() {
		loading = true;
		try {
			const stats = await getKnowledgeStats();
			knowledgeStats.set(stats);
		} catch {
			// API not available
		} finally {
			loading = false;
		}
	}

	async function handleScrape() {
		isScraping.set(true);
		scrapeMessage.set('Starting scrape...');
		try {
			const resp = await startScrape({ sources: ['intelligence', 'nvd'] });
			scrapeMessage.set(resp.message);

			// Poll for completion
			const interval = setInterval(async () => {
				try {
					const status = await getScrapeStatus(resp.task_id);
					if (status.status === 'completed') {
						clearInterval(interval);
						scrapeMessage.set(`Done! ${status.documents_added} documents added.`);
						isScraping.set(false);
						loadStats();
					} else if (status.status !== 'running') {
						clearInterval(interval);
						scrapeMessage.set(`Scrape finished with status: ${status.status}`);
						isScraping.set(false);
					}
				} catch {
					clearInterval(interval);
					isScraping.set(false);
				}
			}, 3000);
		} catch (err) {
			scrapeMessage.set(`Error: ${err instanceof Error ? err.message : 'Unknown'}`);
			isScraping.set(false);
		}
	}

	onMount(loadStats);
</script>

<div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
	<div class="flex items-center justify-between mb-3">
		<h2 class="text-sm font-semibold text-kryon-400">Knowledge Base Stats</h2>
		<button
			on:click={loadStats}
			disabled={loading}
			class="text-xs text-gray-400 hover:text-gray-200 transition-colors"
		>
			Refresh
		</button>
	</div>

	{#if $knowledgeStats}
		<div class="grid grid-cols-2 gap-3 text-sm mb-4">
			<div class="bg-gray-800 rounded p-2">
				<span class="text-gray-500 text-xs">Documents</span>
				<p class="text-lg font-bold text-gray-100">{$knowledgeStats.total_documents}</p>
			</div>
			<div class="bg-gray-800 rounded p-2">
				<span class="text-gray-500 text-xs">LLM Model</span>
				<p class="text-sm font-mono text-gray-300 truncate">{$knowledgeStats.llm_model}</p>
				<span class="text-xs {$knowledgeStats.llm_configured ? 'text-green-400' : 'text-yellow-500'}">
					{$knowledgeStats.llm_configured ? 'Connected' : 'Not configured'}
				</span>
			</div>
		</div>

		{#if Object.keys($knowledgeStats.sources).length > 0}
			<div class="mb-4">
				<span class="text-xs text-gray-500">Sources:</span>
				<div class="flex flex-wrap gap-2 mt-1">
					{#each Object.entries($knowledgeStats.sources) as [name, count]}
						<span class="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">
							{name}: {count}
						</span>
					{/each}
				</div>
			</div>
		{/if}
	{:else if loading}
		<p class="text-xs text-gray-500">Loading stats...</p>
	{:else}
		<p class="text-xs text-gray-500">Could not load stats.</p>
	{/if}

	<div class="border-t border-gray-800 pt-3 mt-3">
		<button
			on:click={handleScrape}
			disabled={$isScraping}
			class="w-full bg-gray-800 hover:bg-gray-700 disabled:bg-gray-800 disabled:text-gray-600 text-sm text-gray-300 px-3 py-2 rounded transition-colors"
		>
			{$isScraping ? 'Scraping...' : 'Scrape New Data'}
		</button>
		{#if $scrapeMessage}
			<p class="text-xs text-gray-400 mt-2">{$scrapeMessage}</p>
		{/if}
	</div>
</div>
