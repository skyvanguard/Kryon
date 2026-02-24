<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { isQuerying } from '$lib/stores/knowledge';

	const dispatch = createEventDispatcher<{ query: { question: string; top_k: number; use_llm: boolean } }>();

	let question = '';
	let topK = 5;
	let useLlm = false;

	function handleSubmit() {
		if (!question.trim()) return;
		dispatch('query', { question: question.trim(), top_k: topK, use_llm: useLlm });
	}
</script>

<div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
	<h2 class="text-sm font-semibold text-kryon-400 mb-3">Query Knowledge Base</h2>
	<form on:submit|preventDefault={handleSubmit} class="space-y-3">
		<div>
			<input
				type="text"
				bind:value={question}
				placeholder="Ask about vulnerabilities, techniques, tools..."
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-kryon-500 focus:outline-none"
				disabled={$isQuerying}
			/>
		</div>
		<div class="flex items-center gap-4">
			<label class="flex items-center gap-2 text-xs text-gray-400">
				<span>Top K:</span>
				<input
					type="number"
					bind:value={topK}
					min="1"
					max="20"
					class="w-16 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100"
				/>
			</label>
			<label class="flex items-center gap-2 text-xs text-gray-400">
				<input type="checkbox" bind:checked={useLlm} class="accent-kryon-500" />
				<span>Use LLM for answer</span>
			</label>
			<button
				type="submit"
				disabled={$isQuerying || !question.trim()}
				class="ml-auto bg-kryon-600 hover:bg-kryon-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm px-4 py-1.5 rounded transition-colors"
			>
				{$isQuerying ? 'Querying...' : 'Search'}
			</button>
		</div>
	</form>
</div>
