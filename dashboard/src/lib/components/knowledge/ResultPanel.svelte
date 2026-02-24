<script lang="ts">
	import { queryResult, queryError } from '$lib/stores/knowledge';
</script>

<div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
	<h2 class="text-sm font-semibold text-kryon-400 mb-3">Results</h2>

	{#if $queryError}
		<p class="text-red-400 text-sm">{$queryError}</p>
	{:else if $queryResult}
		{#if $queryResult.answer}
			<div class="mb-4 p-3 bg-gray-800 rounded text-sm text-gray-200 whitespace-pre-wrap">
				{$queryResult.answer}
			</div>
		{/if}

		<p class="text-xs text-gray-500 mb-2">{$queryResult.num_sources} source(s) found</p>

		<div class="space-y-2 max-h-96 overflow-y-auto">
			{#each $queryResult.sources as src, i}
				<details class="bg-gray-800 rounded p-2">
					<summary class="text-xs text-gray-300 cursor-pointer">
						Source {i + 1}: {src.metadata?.source || 'unknown'}
						<span class="text-gray-500 ml-2">score: {(src.score ?? 0).toFixed(2)}</span>
					</summary>
					<pre class="text-xs text-gray-400 mt-2 whitespace-pre-wrap">{src.content}</pre>
				</details>
			{/each}
		</div>
	{:else}
		<p class="text-gray-500 text-sm">No query yet. Use the search above.</p>
	{/if}
</div>
