<script lang="ts">
	import QueryPanel from '$lib/components/knowledge/QueryPanel.svelte';
	import ResultPanel from '$lib/components/knowledge/ResultPanel.svelte';
	import StatsPanel from '$lib/components/knowledge/StatsPanel.svelte';
	import {
		queryResult,
		isQuerying,
		queryError,
		resetQueryState
	} from '$lib/stores/knowledge';
	import { queryKnowledge, type KnowledgeQueryRequest } from '$lib/api/knowledge';

	async function handleQuery(e: CustomEvent<KnowledgeQueryRequest>) {
		resetQueryState();
		isQuerying.set(true);

		try {
			const result = await queryKnowledge(e.detail);
			queryResult.set(result);
		} catch (err) {
			queryError.set(err instanceof Error ? err.message : 'Query failed');
		} finally {
			isQuerying.set(false);
		}
	}
</script>

<div class="flex-1 p-6 max-w-6xl mx-auto w-full space-y-6">
	<h1 class="text-xl font-bold text-kryon-400">Knowledge Base</h1>

	<QueryPanel on:query={handleQuery} />

	<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
		<div class="lg:col-span-2">
			<ResultPanel />
		</div>
		<div>
			<StatsPanel />
		</div>
	</div>
</div>
