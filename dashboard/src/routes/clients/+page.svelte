<script lang="ts">
	import { onMount } from 'svelte';
	import { clients, clientsLoading, clientsError, loadClients } from '$lib/stores/clients';
	import { createClient } from '$lib/api/clients';
	import ClientCard from '$lib/components/clients/ClientCard.svelte';
	import ClientForm from '$lib/components/clients/ClientForm.svelte';

	let showForm = false;
	let creating = false;

	async function handleCreate(e: CustomEvent<{ name: string; industry: string; contact_email: string; notes: string }>) {
		creating = true;
		try {
			await createClient(e.detail);
			await loadClients();
			showForm = false;
		} catch (err) {
			alert('Failed to create client');
		} finally {
			creating = false;
		}
	}

	onMount(() => {
		loadClients();
	});
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-kryon-400">Clients</h1>
			<p class="text-gray-500 text-sm mt-1">Manage pentesting clients and engagements</p>
		</div>
		<button
			on:click={() => (showForm = !showForm)}
			class="px-4 py-2 bg-kryon-600 hover:bg-kryon-500 text-white text-sm font-medium rounded-lg transition-colors"
		>
			{showForm ? 'Cancel' : '+ New Client'}
		</button>
	</div>

	{#if showForm}
		<ClientForm on:submit={handleCreate} submitLabel={creating ? 'Creating...' : 'Create Client'} />
	{/if}

	{#if $clientsError}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-4 text-red-300 text-sm">
			{$clientsError}
		</div>
	{/if}

	{#if $clientsLoading && $clients.length === 0}
		<p class="text-gray-500 text-sm">Loading clients...</p>
	{:else if $clients.length === 0}
		<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
			<p class="text-gray-500">No clients yet. Create one to get started.</p>
		</div>
	{:else}
		<div class="space-y-3">
			{#each $clients as client (client.id)}
				<ClientCard {client} />
			{/each}
		</div>
	{/if}
</div>
