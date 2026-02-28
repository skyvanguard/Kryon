<script lang="ts">
	import { findings, findingsTotal, criticalCount, highCount, mediumCount, lowCount } from '$lib/stores/findings';
</script>

<div class="grid grid-cols-2 md:grid-cols-5 gap-4">
	<div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
		<div class="text-xs text-gray-500 uppercase">Total</div>
		<div class="text-2xl font-bold text-gray-200 mt-1">{$findingsTotal}</div>
	</div>
	<div class="bg-gray-900 border border-red-900/50 rounded-lg p-4">
		<div class="text-xs text-red-400 uppercase">Critical</div>
		<div class="text-2xl font-bold text-red-300 mt-1">{$criticalCount}</div>
	</div>
	<div class="bg-gray-900 border border-orange-900/50 rounded-lg p-4">
		<div class="text-xs text-orange-400 uppercase">High</div>
		<div class="text-2xl font-bold text-orange-300 mt-1">{$highCount}</div>
	</div>
	<div class="bg-gray-900 border border-yellow-900/50 rounded-lg p-4">
		<div class="text-xs text-yellow-400 uppercase">Medium</div>
		<div class="text-2xl font-bold text-yellow-300 mt-1">{$mediumCount}</div>
	</div>
	<div class="bg-gray-900 border border-blue-900/50 rounded-lg p-4">
		<div class="text-xs text-blue-400 uppercase">Low</div>
		<div class="text-2xl font-bold text-blue-300 mt-1">{$lowCount}</div>
	</div>
</div>
