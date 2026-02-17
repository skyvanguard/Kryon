<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import { currentAgentKey } from '$lib/stores/session';
	import { clearChat } from '$lib/stores/runs';
	import { fetchAgent, type AgentDetail } from '$lib/api/agents';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';
	import AgentSelector from '$lib/components/agents/AgentSelector.svelte';

	let agentDetail: AgentDetail | null = null;

	$: key = $page.params.key;

	$: if (key) {
		currentAgentKey.set(key);
		clearChat();
		fetchAgent(key)
			.then((d) => (agentDetail = d))
			.catch(() => (agentDetail = null));
	}
</script>

<div class="flex-1 flex flex-col">
	<!-- Agent header -->
	<div class="border-b border-gray-800 px-6 py-3 flex items-center justify-between">
		<div>
			<h1 class="text-lg font-bold text-kryon-400">{agentDetail?.name || key}</h1>
			{#if agentDetail?.description}
				<p class="text-xs text-gray-500">{agentDetail.description}</p>
			{/if}
		</div>
		<div class="flex items-center gap-4 text-xs text-gray-500">
			{#if agentDetail}
				<span>{agentDetail.tools.length} tools</span>
				<span>{agentDetail.handoffs.length} handoffs</span>
				{#if agentDetail.model}
					<span class="font-mono">{agentDetail.model}</span>
				{/if}
			{/if}
		</div>
	</div>

	<!-- Chat -->
	<div class="flex-1">
		<ChatPanel />
	</div>
</div>
