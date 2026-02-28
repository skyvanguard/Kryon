<script lang="ts">
	import type { ComplianceAssessment } from '$lib/api/compliance';

	export let assessment: ComplianceAssessment | null = null;

	$: failedControls = assessment?.evidence?.filter((e) => e.status === 'fail') || [];
	$: passedControls = assessment?.evidence?.filter((e) => e.status === 'pass') || [];
</script>

<div class="bg-gray-800 rounded-lg p-4">
	<h3 class="text-sm font-semibold text-gray-300 mb-3">Gap Analysis</h3>
	{#if assessment}
		<div class="grid grid-cols-3 gap-4 mb-4">
			<div class="bg-gray-900 rounded p-3 text-center">
				<p class="text-2xl font-bold text-gray-200">{assessment.controls_assessed}</p>
				<p class="text-xs text-gray-500">Assessed</p>
			</div>
			<div class="bg-gray-900 rounded p-3 text-center">
				<p class="text-2xl font-bold text-green-400">{assessment.controls_passed}</p>
				<p class="text-xs text-gray-500">Passed</p>
			</div>
			<div class="bg-gray-900 rounded p-3 text-center">
				<p class="text-2xl font-bold text-red-400">{assessment.controls_failed}</p>
				<p class="text-xs text-gray-500">Failed</p>
			</div>
		</div>

		{#if failedControls.length > 0}
			<h4 class="text-xs font-semibold text-red-400 mb-2">Failed Controls ({failedControls.length})</h4>
			<div class="space-y-1 max-h-64 overflow-y-auto">
				{#each failedControls as ctrl}
					<div class="flex items-center justify-between bg-red-500/10 rounded px-3 py-1.5">
						<span class="text-sm text-gray-200 font-mono">{ctrl.control_id}</span>
						<span class="text-xs text-red-400">{ctrl.findings.length} finding(s)</span>
					</div>
				{/each}
			</div>
		{/if}
	{:else}
		<p class="text-gray-500 text-sm">Select a framework and run assessment to see gap analysis.</p>
	{/if}
</div>
