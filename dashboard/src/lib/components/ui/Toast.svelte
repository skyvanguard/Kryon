<script lang="ts">
	import { toast, type Toast as ToastType } from '$lib/stores/toast';

	const colorMap: Record<ToastType['type'], string> = {
		error: 'bg-red-900/90 border-red-700 text-red-200',
		success: 'bg-green-900/90 border-green-700 text-green-200',
		warning: 'bg-yellow-900/90 border-yellow-700 text-yellow-200',
		info: 'bg-blue-900/90 border-blue-700 text-blue-200'
	};
</script>

<div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
	{#each $toast as item (item.id)}
		<div
			class="flex items-start gap-2 px-4 py-3 rounded-lg border shadow-lg text-sm {colorMap[item.type]}"
			role="alert"
		>
			<span class="flex-1">{item.message}</span>
			<button
				on:click={() => toast.remove(item.id)}
				class="text-current opacity-60 hover:opacity-100 transition-opacity ml-2"
				aria-label="Dismiss"
			>
				&times;
			</button>
		</div>
	{/each}
</div>
