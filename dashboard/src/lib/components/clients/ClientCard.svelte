<script lang="ts">
	import type { Client } from '$lib/api/clients';

	export let client: Client;

	function timeAgo(iso: string): string {
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 60) return `${mins}m ago`;
		const hrs = Math.floor(mins / 60);
		if (hrs < 24) return `${hrs}h ago`;
		return `${Math.floor(hrs / 24)}d ago`;
	}
</script>

<a
	href="/clients/{client.id}"
	class="block bg-gray-800/50 border border-gray-700/50 rounded-xl p-4 hover:border-kryon-500/40 transition-all"
>
	<div class="flex items-center justify-between">
		<div>
			<h3 class="text-gray-200 font-medium">{client.name}</h3>
			{#if client.industry}
				<span class="text-xs text-gray-500">{client.industry}</span>
			{/if}
		</div>
		<div class="text-xs text-gray-600">
			{timeAgo(client.created_at)}
		</div>
	</div>
	{#if client.contact_email}
		<p class="text-xs text-gray-500 mt-2">{client.contact_email}</p>
	{/if}
</a>
