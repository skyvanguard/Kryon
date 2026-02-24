<script lang="ts">
	import { scanFindings } from '$lib/stores/scans';

	const severityColors: Record<string, string> = {
		critical: 'bg-red-900 text-red-300',
		high: 'bg-orange-900 text-orange-300',
		medium: 'bg-yellow-900 text-yellow-300',
		low: 'bg-blue-900 text-blue-300',
		info: 'bg-gray-800 text-gray-400'
	};
</script>

<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
	<div class="px-4 py-3 border-b border-gray-800">
		<h3 class="text-sm font-semibold text-gray-300">Findings ({$scanFindings.length})</h3>
	</div>

	{#if $scanFindings.length === 0}
		<div class="px-4 py-8 text-center text-gray-600 text-sm">No findings yet</div>
	{:else}
		<div class="overflow-x-auto max-h-96 overflow-y-auto">
			<table class="w-full text-sm">
				<thead class="sticky top-0 bg-gray-900">
					<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
						<th class="px-4 py-2">Severity</th>
						<th class="px-4 py-2">Title</th>
						<th class="px-4 py-2">Asset</th>
						<th class="px-4 py-2">CVSS</th>
						<th class="px-4 py-2">Source</th>
					</tr>
				</thead>
				<tbody>
					{#each $scanFindings as finding}
						<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
							<td class="px-4 py-2">
								<span class="px-2 py-0.5 rounded text-xs font-medium {severityColors[finding.severity] || 'bg-gray-800 text-gray-400'}">
									{finding.severity.toUpperCase()}
								</span>
							</td>
							<td class="px-4 py-2 text-gray-200">{finding.title}</td>
							<td class="px-4 py-2 font-mono text-xs text-gray-400">{finding.affected_asset}</td>
							<td class="px-4 py-2 text-gray-400">{finding.cvss_score ?? '-'}</td>
							<td class="px-4 py-2 text-gray-500 text-xs">{finding.tool_source}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
