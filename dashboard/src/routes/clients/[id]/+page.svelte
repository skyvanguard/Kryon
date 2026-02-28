<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { getClient, getClientProgress, getClientFindings, deleteClient, type Client, type ClientProgress } from '$lib/api/clients';
	import { parseFinding, type ParsedFinding } from '$lib/api/findings';
	import { goto } from '$app/navigation';
	import RiskChart from '$lib/components/clients/RiskChart.svelte';
	import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';

	let client: Client | null = null;
	let progress: ClientProgress | null = null;
	let findings: ParsedFinding[] = [];
	let activeTab: 'overview' | 'findings' | 'scans' = 'overview';
	let loading = true;

	$: clientId = $page.params.id;

	async function load() {
		loading = true;
		try {
			client = await getClient(clientId);
			try { progress = await getClientProgress(clientId); } catch { progress = null; }
			try {
				const raw = await getClientFindings(clientId);
				findings = (raw as Array<Record<string, unknown>>).map((f: Record<string, unknown>) =>
					parseFinding(f as import('$lib/api/findings').Finding)
				);
			} catch { findings = []; }
		} catch {
			client = null;
		} finally {
			loading = false;
		}
	}

	async function handleDelete() {
		if (!confirm(`Delete client "${client?.name}"? This cannot be undone.`)) return;
		try {
			await deleteClient(clientId);
			goto('/clients');
		} catch {
			alert('Failed to delete client');
		}
	}

	onMount(() => {
		load();
	});
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	{#if loading}
		<p class="text-gray-500">Loading client...</p>
	{:else if !client}
		<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
			<p class="text-gray-500">Client not found.</p>
			<a href="/clients" class="text-kryon-400 text-sm mt-2 inline-block">Back to clients</a>
		</div>
	{:else}
		<div class="flex items-center justify-between">
			<div>
				<a href="/clients" class="text-xs text-gray-500 hover:text-gray-300">&larr; Clients</a>
				<h1 class="text-2xl font-bold text-kryon-400 mt-1">{client.name}</h1>
				<div class="flex gap-3 text-xs text-gray-500 mt-1">
					{#if client.industry}<span>{client.industry}</span>{/if}
					{#if client.contact_email}<span>{client.contact_email}</span>{/if}
				</div>
			</div>
			<button
				on:click={handleDelete}
				class="px-3 py-1.5 bg-red-900/50 hover:bg-red-800/50 text-red-300 text-xs rounded transition-colors"
			>
				Delete
			</button>
		</div>

		<!-- Tabs -->
		<div class="flex gap-4 border-b border-gray-800 pb-1">
			{#each ['overview', 'findings', 'scans'] as tab}
				<button
					on:click={() => (activeTab = tab as typeof activeTab)}
					class="px-3 py-2 text-sm transition-colors {activeTab === tab
						? 'text-kryon-400 border-b-2 border-kryon-400'
						: 'text-gray-500 hover:text-gray-300'}"
				>
					{tab.charAt(0).toUpperCase() + tab.slice(1)}
				</button>
			{/each}
		</div>

		{#if activeTab === 'overview'}
			<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
				<RiskChart {progress} />
				<div class="bg-gray-900 border border-gray-800 rounded-lg p-5">
					<h3 class="text-sm font-semibold text-gray-300 mb-3">Details</h3>
					<dl class="space-y-2 text-sm">
						<div class="flex justify-between">
							<dt class="text-gray-500">Created</dt>
							<dd class="text-gray-300">{new Date(client.created_at).toLocaleDateString()}</dd>
						</div>
						{#if progress}
							<div class="flex justify-between">
								<dt class="text-gray-500">Total Scans</dt>
								<dd class="text-gray-300">{progress.total_scans}</dd>
							</div>
							<div class="flex justify-between">
								<dt class="text-gray-500">Total Findings</dt>
								<dd class="text-gray-300">{progress.total_findings}</dd>
							</div>
						{/if}
					</dl>
					{#if client.notes}
						<div class="mt-4 pt-3 border-t border-gray-800">
							<span class="text-xs text-gray-500 uppercase">Notes</span>
							<p class="text-sm text-gray-400 mt-1 whitespace-pre-wrap">{client.notes}</p>
						</div>
					{/if}
				</div>
			</div>

		{:else if activeTab === 'findings'}
			{#if findings.length === 0}
				<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
					<p class="text-gray-500">No findings for this client.</p>
				</div>
			{:else}
				<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
					<div class="overflow-x-auto max-h-[500px] overflow-y-auto">
						<table class="w-full text-sm">
							<thead class="sticky top-0 bg-gray-900">
								<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
									<th class="px-4 py-2">Severity</th>
									<th class="px-4 py-2">Title</th>
									<th class="px-4 py-2">Asset</th>
									<th class="px-4 py-2">Status</th>
								</tr>
							</thead>
							<tbody>
								{#each findings as f (f.id)}
									<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
										<td class="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
										<td class="px-4 py-2 text-gray-200">{f.title}</td>
										<td class="px-4 py-2 text-gray-400 font-mono text-xs">{f.affected_asset}</td>
										<td class="px-4 py-2 text-gray-500 text-xs">{f.status}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}

		{:else if activeTab === 'scans'}
			<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
				<p class="text-gray-500">Scan history coming soon.</p>
			</div>
		{/if}
	{/if}
</div>
