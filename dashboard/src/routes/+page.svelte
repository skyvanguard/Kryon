<script lang="ts">
	import { onMount } from 'svelte';
	import { agents, loadAgents } from '$lib/stores/agents';
	import { currentAgentKey, currentSessionId, prefillInput } from '$lib/stores/session';
	import { messages, clearChat, isRunning } from '$lib/stores/runs';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';
	import AgentSelector from '$lib/components/agents/AgentSelector.svelte';

	let health: { status: string; version: string } | null = null;

	const examples = [
		{ label: 'Analiza la seguridad de example.com', text: 'Analyze the security of example.com' },
		{ label: 'Escanea vulnerabilidades en 10.10.10.1', text: 'Scan for vulnerabilities on 10.10.10.1' },
		{ label: 'Genera un reporte de pentest', text: 'Generate a pentest report for the current engagement' },
		{ label: 'Investiga el CVE-2024-1234', text: 'Research CVE-2024-1234 and assess its impact' }
	];

	onMount(async () => {
		loadAgents();
		if (!$currentAgentKey) {
			currentAgentKey.set('central_core');
		}
		try {
			const resp = await fetch('/api/v1/health');
			health = await resp.json();
		} catch {
			/* API not available */
		}
	});

	function newChat() {
		clearChat();
		currentSessionId.set(null);
	}

	function fillInput(text: string) {
		prefillInput.set(text);
	}
</script>

<div class="flex-1 flex flex-col h-full">
	<!-- Compact header -->
	<div class="px-6 py-3 border-b border-gray-800/50 flex items-center justify-between">
		<div class="flex items-center gap-4">
			<h1 class="text-xl font-bold">
				<span class="text-kryon-500">KRYON</span>
			</h1>
			<AgentSelector />
			{#if health}
				<span class="px-2 py-0.5 bg-green-500/10 text-green-400 rounded-full text-xs">
					{health.status.toUpperCase()}
				</span>
			{/if}
		</div>
		<button
			on:click={newChat}
			class="text-sm text-gray-400 hover:text-white px-3 py-1 rounded border border-gray-700/50 hover:border-gray-600 transition-colors"
		>
			+ New Chat
		</button>
	</div>

	<!-- Chat area -->
	<div class="flex-1 overflow-hidden relative">
		<ChatPanel />

		<!-- Welcome overlay when no messages -->
		{#if $messages.length === 0 && !$isRunning}
			<div
				class="absolute inset-x-0 top-0 bottom-16 flex flex-col items-center justify-center pointer-events-none z-10"
			>
				<div class="pointer-events-auto text-center px-4">
					<h2 class="text-2xl font-bold text-gray-200 mb-2">Describe tu objetivo</h2>
					<p class="text-gray-500 mb-6 max-w-md mx-auto">
						KRYON analiza tu solicitud y selecciona el agente adecuado automáticamente.
					</p>
					<div class="flex flex-wrap gap-2 justify-center max-w-lg mx-auto">
						{#each examples as ex}
							<button
								on:click={() => fillInput(ex.text)}
								class="text-sm px-3 py-1.5 rounded-full border border-gray-700/50
									text-gray-400 hover:text-white hover:border-kryon-500/50 transition-colors"
							>
								{ex.label}
							</button>
						{/each}
					</div>
				</div>
			</div>
		{/if}
	</div>
</div>
