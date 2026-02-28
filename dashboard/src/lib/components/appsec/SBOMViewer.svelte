<script lang="ts">
	export let sbomData: string = '';

	$: parsed = (() => {
		try {
			return sbomData ? JSON.parse(sbomData) : null;
		} catch {
			return null;
		}
	})();

	$: components = parsed?.components || parsed?.packages || [];
</script>

<div class="bg-gray-800 rounded-lg p-4">
	<h3 class="text-sm font-semibold text-gray-300 mb-3">SBOM Components</h3>
	{#if components.length > 0}
		<div class="overflow-x-auto">
			<table class="w-full text-sm">
				<thead>
					<tr class="text-gray-400 border-b border-gray-700">
						<th class="text-left py-2 px-2">Name</th>
						<th class="text-left py-2 px-2">Version</th>
						<th class="text-left py-2 px-2">Type</th>
					</tr>
				</thead>
				<tbody>
					{#each components.slice(0, 50) as component}
						<tr class="border-b border-gray-700/50 hover:bg-gray-700/30">
							<td class="py-1.5 px-2 text-gray-200">{component.name || 'N/A'}</td>
							<td class="py-1.5 px-2 text-gray-400">{component.version || '-'}</td>
							<td class="py-1.5 px-2 text-gray-400">{component.type || component.purl?.split(':')[0] || '-'}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		{#if components.length > 50}
			<p class="text-xs text-gray-500 mt-2">Showing 50 of {components.length} components</p>
		{/if}
	{:else if sbomData}
		<pre class="text-xs text-gray-400 max-h-64 overflow-auto">{sbomData.slice(0, 2000)}</pre>
	{:else}
		<p class="text-gray-500 text-sm">No SBOM data available. Run an SBOM scan to populate.</p>
	{/if}
</div>
