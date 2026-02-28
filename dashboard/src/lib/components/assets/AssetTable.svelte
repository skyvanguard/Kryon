<script lang="ts">
	import type { Asset } from '$lib/api/assets';

	export let assets: Asset[] = [];

	const typeColors: Record<string, string> = {
		domain: 'text-blue-400 bg-blue-400/10',
		subdomain: 'text-cyan-400 bg-cyan-400/10',
		ip: 'text-yellow-400 bg-yellow-400/10',
		service: 'text-purple-400 bg-purple-400/10',
		certificate: 'text-green-400 bg-green-400/10',
		cloud_resource: 'text-orange-400 bg-orange-400/10'
	};
</script>

<div class="overflow-x-auto">
	<table class="w-full text-sm">
		<thead>
			<tr class="text-gray-400 border-b border-gray-700">
				<th class="text-left py-2 px-3">Identifier</th>
				<th class="text-left py-2 px-3">Type</th>
				<th class="text-left py-2 px-3">Status</th>
				<th class="text-left py-2 px-3">First Seen</th>
				<th class="text-left py-2 px-3">Last Seen</th>
			</tr>
		</thead>
		<tbody>
			{#each assets as asset}
				<tr class="border-b border-gray-700/50 hover:bg-gray-700/30">
					<td class="py-2 px-3">
						<a href="/assets/{asset.id}" class="text-kryon-400 hover:underline">{asset.identifier}</a>
					</td>
					<td class="py-2 px-3">
						<span class="text-xs px-2 py-0.5 rounded {typeColors[asset.asset_type] || 'text-gray-400 bg-gray-400/10'}">
							{asset.asset_type}
						</span>
					</td>
					<td class="py-2 px-3">
						<span class="text-xs {asset.status === 'active' ? 'text-green-400' : 'text-gray-500'}">
							{asset.status}
						</span>
					</td>
					<td class="py-2 px-3 text-gray-400 text-xs">{asset.first_seen?.split('T')[0] || '-'}</td>
					<td class="py-2 px-3 text-gray-400 text-xs">{asset.last_seen?.split('T')[0] || '-'}</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
