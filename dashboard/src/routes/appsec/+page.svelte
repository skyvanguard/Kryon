<script lang="ts">
	import SBOMViewer from '$lib/components/appsec/SBOMViewer.svelte';
	import SASTFindings from '$lib/components/appsec/SASTFindings.svelte';
	import { runSASTScan, runDASTScan, runSBOMScan, type ScanResult } from '$lib/api/appsec';

	let targetPath = '';
	let targetUrl = '';
	let sbomTarget = '';
	let loading = false;
	let lastResult: ScanResult | null = null;
	let sbomData = '';
	let sastFindings: { rule_id: string; severity: string; path: string; line: number; message: string }[] = [];

	async function handleSAST() {
		if (!targetPath) return;
		loading = true;
		try {
			lastResult = await runSASTScan({ target_path: targetPath });
		} catch (e) {
			console.error(e);
		}
		loading = false;
	}

	async function handleDAST() {
		if (!targetUrl) return;
		loading = true;
		try {
			lastResult = await runDASTScan({ target_url: targetUrl });
		} catch (e) {
			console.error(e);
		}
		loading = false;
	}

	async function handleSBOM() {
		if (!sbomTarget) return;
		loading = true;
		try {
			const result = await runSBOMScan({ target: sbomTarget });
			sbomData = result.result;
		} catch (e) {
			console.error(e);
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>AppSec | KRYON</title>
</svelte:head>

<div class="p-6 space-y-6">
	<h1 class="text-2xl font-bold text-gray-100">Application Security</h1>

	<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
		<!-- SAST -->
		<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
			<h2 class="text-sm font-semibold text-gray-300 mb-3">SAST (Semgrep)</h2>
			<input
				bind:value={targetPath}
				placeholder="Source code path..."
				class="w-full bg-gray-900 text-gray-200 rounded px-3 py-2 text-sm border border-gray-700 mb-2"
			/>
			<button
				on:click={handleSAST}
				disabled={loading || !targetPath}
				class="w-full bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-sm py-2 rounded transition-colors"
			>
				{loading ? 'Scanning...' : 'Run SAST Scan'}
			</button>
		</div>

		<!-- DAST -->
		<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
			<h2 class="text-sm font-semibold text-gray-300 mb-3">DAST (ZAP)</h2>
			<input
				bind:value={targetUrl}
				placeholder="https://target.com..."
				class="w-full bg-gray-900 text-gray-200 rounded px-3 py-2 text-sm border border-gray-700 mb-2"
			/>
			<button
				on:click={handleDAST}
				disabled={loading || !targetUrl}
				class="w-full bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-sm py-2 rounded transition-colors"
			>
				{loading ? 'Scanning...' : 'Run DAST Scan'}
			</button>
		</div>

		<!-- SBOM -->
		<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
			<h2 class="text-sm font-semibold text-gray-300 mb-3">SBOM (Syft/Grype)</h2>
			<input
				bind:value={sbomTarget}
				placeholder="Project path or image..."
				class="w-full bg-gray-900 text-gray-200 rounded px-3 py-2 text-sm border border-gray-700 mb-2"
			/>
			<button
				on:click={handleSBOM}
				disabled={loading || !sbomTarget}
				class="w-full bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-sm py-2 rounded transition-colors"
			>
				{loading ? 'Generating...' : 'Generate SBOM'}
			</button>
		</div>
	</div>

	<!-- Results -->
	{#if lastResult}
		<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
			<h2 class="text-sm font-semibold text-gray-300 mb-2">Last Scan Result</h2>
			<p class="text-xs text-gray-500 mb-2">Tool: {lastResult.tool} | ID: {lastResult.scan_id}</p>
			<pre class="text-xs text-gray-400 max-h-64 overflow-auto bg-gray-900 p-3 rounded">{lastResult.result}</pre>
		</div>
	{/if}

	<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
		<SASTFindings findings={sastFindings} />
		<SBOMViewer {sbomData} />
	</div>
</div>
