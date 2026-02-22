<script lang="ts">
	import { onMount } from 'svelte';
	import { loadUsage } from '$lib/stores/usage';
	import UsageSummaryComponent from '$lib/components/usage/UsageSummary.svelte';
	import CostChart from '$lib/components/usage/CostChart.svelte';
	import DailyChart from '$lib/components/usage/DailyChart.svelte';

	onMount(() => {
		loadUsage();
	});
</script>

<div class="flex-1 p-8 space-y-6">
	<h1 class="text-2xl font-bold">Usage & Cost</h1>
	<UsageSummaryComponent />
	<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
		<CostChart />
		<DailyChart />
	</div>
</div>
