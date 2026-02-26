<script lang="ts">
	import type { Engagement } from '$lib/api/engagements';

	export let items: Engagement[] = [];

	const statusColors: Record<string, string> = {
		created: 'bg-gray-500/20 text-gray-400',
		planning: 'bg-yellow-500/20 text-yellow-400',
		active: 'bg-green-500/20 text-green-400',
		paused: 'bg-amber-500/20 text-amber-400',
		completed: 'bg-blue-500/20 text-blue-400',
		failed: 'bg-red-500/20 text-red-400',
		cancelled: 'bg-gray-500/20 text-gray-500'
	};

	function timeAgo(iso: string): string {
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 60) return `${mins}m ago`;
		const hrs = Math.floor(mins / 60);
		if (hrs < 24) return `${hrs}h ago`;
		return `${Math.floor(hrs / 24)}d ago`;
	}
</script>

{#if items.length === 0}
	<p class="text-gray-500 text-sm">No engagements yet.</p>
{:else}
	<div class="space-y-3">
		{#each items as eng (eng.id)}
			<a
				href="/engagements/{eng.id}"
				class="block bg-gray-800/50 border border-gray-700/50 rounded-xl p-4 hover:border-kryon-500/40 transition-all"
			>
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-3">
						<span
							class="px-2 py-0.5 text-xs rounded-full font-medium {statusColors[eng.status] ||
								'bg-gray-500/20 text-gray-400'}"
						>
							{eng.status === 'active' ? '● ' : ''}{eng.status.toUpperCase()}
						</span>
						<span class="text-gray-200 font-medium">{eng.client_name}</span>
						<span class="text-gray-500 text-xs">{eng.targets.length} target{eng.targets.length !== 1 ? 's' : ''}</span>
					</div>
					<div class="flex items-center gap-4 text-xs text-gray-500">
						<span>{eng.duration_days}d plan</span>
						{#if eng.total_findings > 0}
							<span class="text-kryon-400">{eng.total_findings} findings</span>
						{/if}
						<span>{timeAgo(eng.created_at)}</span>
					</div>
				</div>
				{#if eng.targets.length > 0}
					<p class="text-gray-500 text-xs mt-2 font-mono truncate">
						{eng.targets.slice(0, 3).join(', ')}{eng.targets.length > 3 ? ` +${eng.targets.length - 3}` : ''}
					</p>
				{/if}
			</a>
		{/each}
	</div>
{/if}
