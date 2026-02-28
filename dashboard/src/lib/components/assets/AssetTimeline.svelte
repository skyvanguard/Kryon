<script lang="ts">
	import type { AssetChange } from '$lib/api/assets';

	export let changes: AssetChange[] = [];
</script>

<div class="bg-gray-800 rounded-lg p-4">
	<h3 class="text-sm font-semibold text-gray-300 mb-3">Change Timeline</h3>
	{#if changes.length > 0}
		<div class="space-y-3">
			{#each changes as change}
				<div class="relative pl-6 border-l-2 border-gray-700">
					<div class="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-kryon-500"></div>
					<div>
						<p class="text-sm text-gray-200">
							<span class="font-medium text-kryon-400">{change.change_type}</span>
						</p>
						{#if change.old_value || change.new_value}
							<p class="text-xs text-gray-400 mt-0.5">
								{#if change.old_value}<span class="text-red-400 line-through">{change.old_value}</span>{/if}
								{#if change.old_value && change.new_value} &rarr; {/if}
								{#if change.new_value}<span class="text-green-400">{change.new_value}</span>{/if}
							</p>
						{/if}
						<p class="text-xs text-gray-500 mt-0.5">{change.detected_at?.split('T')[0] || ''}</p>
					</div>
				</div>
			{/each}
		</div>
	{:else}
		<p class="text-gray-500 text-sm">No changes recorded for this asset.</p>
	{/if}
</div>
