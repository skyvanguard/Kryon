<script lang="ts">
	import { onMount } from 'svelte';
	import { listClients, type Client } from '$lib/api/clients';
	import { generateReport, listReports, type Report, type ReportRequest } from '$lib/api/reports';
	import ReportForm from '$lib/components/reports/ReportForm.svelte';
	import ReportList from '$lib/components/reports/ReportList.svelte';

	let clients: Client[] = [];
	let reports: Report[] = [];
	let loading = true;
	let generating = false;
	let error = '';

	async function load() {
		loading = true;
		error = '';
		try {
			const [c, r] = await Promise.all([listClients(), listReports()]);
			clients = c;
			reports = r;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
		} finally {
			loading = false;
		}
	}

	async function handleGenerate(e: CustomEvent<{ client_id?: string; report_type: string; format: string }>) {
		generating = true;
		error = '';
		try {
			const req: ReportRequest = {
				report_type: e.detail.report_type,
				format: e.detail.format
			};
			if (e.detail.client_id) req.client_id = e.detail.client_id;
			await generateReport(req);
			reports = await listReports();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to generate report';
		} finally {
			generating = false;
		}
	}

	onMount(() => {
		load();
	});
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	<div>
		<h1 class="text-2xl font-bold text-kryon-400">Reports</h1>
		<p class="text-gray-500 text-sm mt-1">Generate and download security reports</p>
	</div>

	{#if error}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-4 text-red-300 text-sm">
			{error}
		</div>
	{/if}

	<ReportForm {clients} {generating} on:generate={handleGenerate} />

	{#if loading}
		<p class="text-gray-500 text-sm">Loading reports...</p>
	{:else}
		<div>
			<h2 class="text-sm font-semibold text-gray-300 mb-3">Generated Reports</h2>
			<ReportList {reports} />
		</div>
	{/if}
</div>
