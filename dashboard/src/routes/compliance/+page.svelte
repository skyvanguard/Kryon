<script lang="ts">
	import { onMount } from 'svelte';
	import FrameworkSelector from '$lib/components/compliance/FrameworkSelector.svelte';
	import GapAnalysis from '$lib/components/compliance/GapAnalysis.svelte';
	import ComplianceChart from '$lib/components/compliance/ComplianceChart.svelte';
	import MITREHeatmap from '$lib/components/mitre/MITREHeatmap.svelte';
	import {
		listFrameworks,
		assessCompliance,
		type ComplianceFramework,
		type ComplianceAssessment
	} from '$lib/api/compliance';
	import { getMITRECoverage, type CoverageData } from '$lib/api/mitre';

	let frameworks: ComplianceFramework[] = [];
	let selectedFramework = '';
	let assessment: ComplianceAssessment | null = null;
	let coverage: CoverageData | null = null;
	let loading = false;

	onMount(async () => {
		try {
			const data = await listFrameworks();
			frameworks = data.frameworks;
		} catch (e) {
			console.error('Failed to load frameworks:', e);
		}
		try {
			coverage = await getMITRECoverage();
		} catch (e) {
			console.error('Failed to load MITRE coverage:', e);
		}
	});

	async function handleFrameworkSelect(e: CustomEvent<string>) {
		selectedFramework = e.detail;
		loading = true;
		try {
			assessment = await assessCompliance(selectedFramework);
		} catch (err) {
			console.error('Assessment failed:', err);
			assessment = null;
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>Compliance | KRYON</title>
</svelte:head>

<div class="p-6 space-y-6">
	<h1 class="text-2xl font-bold text-gray-100">Compliance & Coverage</h1>

	<!-- MITRE Heatmap -->
	<MITREHeatmap {coverage} />

	<!-- Framework Selector -->
	<div>
		<h2 class="text-sm font-semibold text-gray-300 mb-3">Select Framework</h2>
		<FrameworkSelector {frameworks} selected={selectedFramework} on:select={handleFrameworkSelect} />
	</div>

	{#if loading}
		<div class="text-center py-8">
			<div class="animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500 mx-auto"></div>
			<p class="text-gray-400 text-sm mt-2">Assessing compliance...</p>
		</div>
	{:else if assessment}
		<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
			<ComplianceChart {assessment} />
			<div class="lg:col-span-2">
				<GapAnalysis {assessment} />
			</div>
		</div>
	{/if}
</div>
