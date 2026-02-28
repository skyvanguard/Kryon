<script lang="ts">
	import type { ComplianceAssessment } from '$lib/api/compliance';

	export let assessment: ComplianceAssessment | null = null;

	$: pct = assessment
		? Math.round((assessment.controls_passed / Math.max(assessment.controls_assessed, 1)) * 100)
		: 0;

	$: color = pct >= 80 ? '#22c55e' : pct >= 60 ? '#f59e0b' : '#ef4444';
	$: circumference = 2 * Math.PI * 45;
	$: offset = circumference - (pct / 100) * circumference;
</script>

<div class="bg-gray-800 rounded-lg p-4 flex flex-col items-center">
	<h3 class="text-sm font-semibold text-gray-300 mb-4">Compliance Score</h3>
	{#if assessment}
		<div class="relative w-32 h-32">
			<svg viewBox="0 0 100 100" class="transform -rotate-90">
				<circle cx="50" cy="50" r="45" fill="none" stroke="#374151" stroke-width="8" />
				<circle
					cx="50"
					cy="50"
					r="45"
					fill="none"
					stroke={color}
					stroke-width="8"
					stroke-linecap="round"
					stroke-dasharray={circumference}
					stroke-dashoffset={offset}
					class="transition-all duration-700"
				/>
			</svg>
			<div class="absolute inset-0 flex items-center justify-center">
				<span class="text-2xl font-bold" style="color: {color}">{pct}%</span>
			</div>
		</div>
		<p class="text-xs text-gray-500 mt-2">{assessment.framework}</p>
	{:else}
		<div class="w-32 h-32 flex items-center justify-center">
			<p class="text-gray-500 text-sm text-center">No assessment</p>
		</div>
	{/if}
</div>
