<script lang="ts">
	import type { Report } from '$lib/api/reports';
	import { downloadReport } from '$lib/api/reports';

	export let reports: Report[] = [];

	function formatSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1048576).toFixed(1)} MB`;
	}

	async function handleDownload(report: Report) {
		try {
			const blob = await downloadReport(report.id);
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = report.filename;
			a.click();
			URL.revokeObjectURL(url);
		} catch {
			alert('Failed to download report');
		}
	}
</script>

{#if reports.length === 0}
	<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
		<p class="text-gray-500">No reports generated yet.</p>
	</div>
{:else}
	<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
		<div class="overflow-x-auto">
			<table class="w-full text-sm">
				<thead>
					<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
						<th class="px-4 py-2">Filename</th>
						<th class="px-4 py-2">Type</th>
						<th class="px-4 py-2">Format</th>
						<th class="px-4 py-2">Size</th>
						<th class="px-4 py-2">Created</th>
						<th class="px-4 py-2"></th>
					</tr>
				</thead>
				<tbody>
					{#each reports as r (r.filename)}
						<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
							<td class="px-4 py-2 text-gray-200 font-mono text-xs">{r.filename}</td>
							<td class="px-4 py-2">
								<span class="px-2 py-0.5 rounded text-xs {
									r.report_type === 'executive' ? 'bg-purple-900/50 text-purple-300' :
									r.report_type === 'compliance' ? 'bg-yellow-900/50 text-yellow-300' :
									'bg-blue-900/50 text-blue-300'
								}">
									{r.report_type}
								</span>
							</td>
							<td class="px-4 py-2 text-gray-400 uppercase text-xs">{r.format}</td>
							<td class="px-4 py-2 text-gray-400 text-xs">{formatSize(r.size_bytes)}</td>
							<td class="px-4 py-2 text-gray-500 text-xs">
								{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}
							</td>
							<td class="px-4 py-2">
								<button
									on:click={() => handleDownload(r)}
									class="text-kryon-400 hover:text-kryon-300 text-xs transition-colors"
								>
									Download
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</div>
{/if}
