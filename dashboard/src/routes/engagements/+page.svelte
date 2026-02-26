<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { engagements, loadEngagements } from '$lib/stores/engagements';
	import { createEngagement, type CreateEngagementRequest } from '$lib/api/engagements';
	import EngagementForm from '$lib/components/engagements/EngagementForm.svelte';
	import EngagementList from '$lib/components/engagements/EngagementList.svelte';

	let showForm = false;
	let creating = false;

	async function handleCreate(e: CustomEvent<CreateEngagementRequest>) {
		creating = true;
		try {
			const result = await createEngagement(e.detail);
			await loadEngagements();
			showForm = false;
			goto(`/engagements/${result.id}`);
		} catch (err) {
			alert('Failed to create engagement');
		} finally {
			creating = false;
		}
	}

	onMount(() => {
		loadEngagements();
		const interval = setInterval(loadEngagements, 10000);
		return () => clearInterval(interval);
	});
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-kryon-400">Engagements</h1>
			<p class="text-gray-500 text-sm mt-1">Multi-day autonomous pentesting operations</p>
		</div>
		<button
			on:click={() => (showForm = !showForm)}
			class="px-4 py-2 bg-kryon-600 hover:bg-kryon-500 text-white text-sm font-medium rounded-lg transition-colors"
		>
			{showForm ? 'Cancel' : '+ New Engagement'}
		</button>
	</div>

	{#if showForm}
		<EngagementForm on:create={handleCreate} />
	{/if}

	<EngagementList items={$engagements} />
</div>
