<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchSessions, type SessionResponse } from '$lib/api/runs';

	let sessions: SessionResponse[] = [];
	let loading = true;

	onMount(async () => {
		try {
			sessions = await fetchSessions();
		} catch {
			// API not available
		} finally {
			loading = false;
		}
	});
</script>

<div class="flex-1 p-8">
	<h1 class="text-2xl font-bold mb-6">Sessions</h1>

	{#if loading}
		<p class="text-gray-500">Loading...</p>
	{:else if sessions.length === 0}
		<p class="text-gray-500">No active sessions. Start a conversation with an agent to create one.</p>
	{:else}
		<div class="space-y-3">
			{#each sessions as session}
				<div class="bg-gray-800 border border-gray-700 rounded-lg p-4 flex justify-between items-center">
					<div>
						<div class="font-semibold text-sm">{session.agent_key}</div>
						<div class="text-xs text-gray-500">
							ID: {session.session_id} | Messages: {session.message_count}
						</div>
					</div>
					<div class="text-xs text-gray-600">{session.created_at}</div>
				</div>
			{/each}
		</div>
	{/if}
</div>
