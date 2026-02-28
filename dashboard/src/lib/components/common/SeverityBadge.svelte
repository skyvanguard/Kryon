<script lang="ts">
	export let severity: string;

	const colors: Record<string, string> = {
		critical: 'bg-red-900 text-red-300',
		high: 'bg-orange-900 text-orange-300',
		medium: 'bg-yellow-900 text-yellow-300',
		low: 'bg-blue-900 text-blue-300',
		info: 'bg-gray-800 text-gray-400'
	};
</script>

<span
	class="px-2 py-0.5 rounded text-xs font-medium {colors[severity?.toLowerCase()] ||
		'bg-gray-800 text-gray-400'}"
>
	{(severity || 'unknown').toUpperCase()}
</span>
