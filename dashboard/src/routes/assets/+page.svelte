<script lang="ts">
	import { onMount } from 'svelte';
	import AssetTable from '$lib/components/assets/AssetTable.svelte';
	import { listAssets, type Asset } from '$lib/api/assets';

	let assets: Asset[] = [];
	let total = 0;
	let searchQuery = '';
	let typeFilter = '';
	let loading = true;

	const assetTypes = ['', 'domain', 'subdomain', 'ip', 'service', 'certificate', 'cloud_resource'];

	async function loadAssets() {
		loading = true;
		try {
			const data = await listAssets(0, 50, searchQuery, typeFilter);
			assets = data.items;
			total = data.total;
		} catch (e) {
			console.error('Failed to load assets:', e);
		}
		loading = false;
	}

	onMount(loadAssets);

	function handleSearch() {
		loadAssets();
	}
</script>

<svelte:head>
	<title>Assets | KRYON</title>
</svelte:head>

<div class="p-6 space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-gray-100">Asset Inventory</h1>
		<span class="text-sm text-gray-400">{total} total assets</span>
	</div>

	<!-- Filters -->
	<div class="flex gap-3">
		<input
			bind:value={searchQuery}
			on:keydown={(e) => e.key === 'Enter' && handleSearch()}
			placeholder="Search assets..."
			class="flex-1 bg-gray-800 text-gray-200 rounded px-3 py-2 text-sm border border-gray-700"
		/>
		<select
			bind:value={typeFilter}
			on:change={loadAssets}
			class="bg-gray-800 text-gray-200 rounded px-3 py-2 text-sm border border-gray-700"
		>
			{#each assetTypes as t}
				<option value={t}>{t || 'All types'}</option>
			{/each}
		</select>
		<button
			on:click={handleSearch}
			class="bg-kryon-600 hover:bg-kryon-500 text-white text-sm px-4 py-2 rounded transition-colors"
		>
			Search
		</button>
	</div>

	<!-- Table -->
	{#if loading}
		<div class="text-center py-8">
			<div class="animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500 mx-auto"></div>
		</div>
	{:else}
		<div class="bg-gray-800 rounded-lg border border-gray-700">
			<AssetTable {assets} />
		</div>
	{/if}
</div>
