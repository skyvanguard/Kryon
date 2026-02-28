<script lang="ts">
	export let columns: { key: string; label: string; sortable?: boolean }[] = [];
	export let items: Record<string, unknown>[] = [];
	export let emptyMessage = 'No data available';

	let sortKey = '';
	let sortDir: 'asc' | 'desc' = 'asc';

	function toggleSort(key: string) {
		if (sortKey === key) {
			sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		} else {
			sortKey = key;
			sortDir = 'asc';
		}
	}

	$: sortedItems = sortKey
		? [...items].sort((a, b) => {
				const av = a[sortKey] ?? '';
				const bv = b[sortKey] ?? '';
				const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
				return sortDir === 'asc' ? cmp : -cmp;
			})
		: items;
</script>

<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
	{#if items.length === 0}
		<div class="px-4 py-8 text-center text-gray-600 text-sm">{emptyMessage}</div>
	{:else}
		<div class="overflow-x-auto max-h-[600px] overflow-y-auto">
			<table class="w-full text-sm">
				<thead class="sticky top-0 bg-gray-900 z-10">
					<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
						{#each columns as col}
							<th class="px-4 py-2">
								{#if col.sortable}
									<button
										class="hover:text-gray-300 transition-colors"
										on:click={() => toggleSort(col.key)}
									>
										{col.label}
										{#if sortKey === col.key}
											<span class="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>
										{/if}
									</button>
								{:else}
									{col.label}
								{/if}
							</th>
						{/each}
					</tr>
				</thead>
				<tbody>
					{#each sortedItems as item}
						<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
							{#each columns as col}
								<td class="px-4 py-2 text-gray-300">
									<slot name="cell" {col} {item}>
										{item[col.key] ?? ''}
									</slot>
								</td>
							{/each}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
