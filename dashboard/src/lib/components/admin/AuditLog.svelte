<script lang="ts">
	import { onMount } from 'svelte';
	import { getAuditLog, type AuditEntry } from '$lib/api/admin';

	let entries: AuditEntry[] = [];
	let loading = true;
	let actionFilter = '';
	let error = '';

	async function load() {
		loading = true;
		error = '';
		try {
			entries = await getAuditLog(0, 200, actionFilter || undefined);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load audit log';
		} finally {
			loading = false;
		}
	}

	function handleFilter() {
		load();
	}

	onMount(() => { load(); });
</script>

<div class="space-y-4">
	<div class="flex items-center gap-3">
		<h3 class="text-sm font-semibold text-gray-300">Audit Log</h3>
		<select
			bind:value={actionFilter}
			on:change={handleFilter}
			class="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:border-kryon-500 focus:outline-none"
		>
			<option value="">All actions</option>
			<option value="POST">POST</option>
			<option value="PUT">PUT</option>
			<option value="DELETE">DELETE</option>
		</select>
	</div>

	{#if error}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-3 text-red-300 text-xs">{error}</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading audit log...</p>
	{:else if entries.length === 0}
		<div class="bg-gray-900 border border-gray-800 rounded-lg p-6 text-center">
			<p class="text-gray-500 text-sm">No audit entries found.</p>
		</div>
	{:else}
		<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
			<div class="overflow-x-auto max-h-[500px] overflow-y-auto">
				<table class="w-full text-sm">
					<thead class="sticky top-0 bg-gray-900">
						<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
							<th class="px-4 py-2">Time</th>
							<th class="px-4 py-2">User</th>
							<th class="px-4 py-2">Action</th>
							<th class="px-4 py-2">Resource</th>
							<th class="px-4 py-2">IP</th>
						</tr>
					</thead>
					<tbody>
						{#each entries as entry (entry.id)}
							<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
								<td class="px-4 py-2 text-gray-500 text-xs whitespace-nowrap">
									{new Date(entry.timestamp).toLocaleString()}
								</td>
								<td class="px-4 py-2 text-gray-300 text-xs">{entry.user}</td>
								<td class="px-4 py-2">
									<span class="px-2 py-0.5 rounded text-xs {
										entry.action === 'DELETE' ? 'bg-red-900/50 text-red-300' :
										entry.action === 'POST' ? 'bg-green-900/50 text-green-300' :
										'bg-yellow-900/50 text-yellow-300'
									}">
										{entry.action}
									</span>
								</td>
								<td class="px-4 py-2 text-gray-400 font-mono text-xs">{entry.resource}</td>
								<td class="px-4 py-2 text-gray-500 text-xs font-mono">{entry.ip}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{/if}
</div>
