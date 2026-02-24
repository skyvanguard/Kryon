<script lang="ts">
	import { scanStatus, scanPhaseLabel } from '$lib/stores/scans';

	const phases = ['recon', 'vuln_scan', 'exploitation', 'reporting'];
	const phaseLabels: Record<string, string> = {
		recon: 'Recon',
		vuln_scan: 'Vuln Scan',
		exploitation: 'Exploit',
		reporting: 'Report'
	};

	$: currentPhaseIdx = $scanStatus ? phases.indexOf($scanStatus.status) : -1;
	$: progressPct = $scanStatus ? Math.round($scanStatus.phase_progress * 100) : 0;
	$: elapsed = $scanStatus ? formatTime($scanStatus.elapsed_seconds) : '0:00';

	function formatTime(seconds: number): string {
		const m = Math.floor(seconds / 60);
		const s = Math.floor(seconds % 60);
		return `${m}:${s.toString().padStart(2, '0')}`;
	}
</script>

{#if $scanStatus}
	<div class="bg-gray-900 rounded-lg p-6 border border-gray-800 space-y-4">
		<div class="flex items-center justify-between">
			<h3 class="text-sm font-semibold text-kryon-400">{$scanPhaseLabel}</h3>
			<span class="text-xs text-gray-500">{elapsed} elapsed</span>
		</div>

		<!-- Phase steps -->
		<div class="flex gap-1">
			{#each phases as phase, i}
				{@const isActive = i === currentPhaseIdx}
				{@const isDone = i < currentPhaseIdx || $scanStatus?.status === 'completed'}
				<div class="flex-1 text-center">
					<div
						class="h-2 rounded-full transition-all duration-300"
						class:bg-kryon-500={isActive}
						class:bg-kryon-700={isDone}
						class:bg-gray-800={!isActive && !isDone}
					>
						{#if isActive}
							<div
								class="h-full bg-kryon-400 rounded-full transition-all duration-500"
								style="width: {progressPct}%"
							></div>
						{/if}
					</div>
					<span class="text-xs mt-1 block" class:text-kryon-400={isActive} class:text-gray-500={!isActive}>
						{phaseLabels[phase]}
					</span>
				</div>
			{/each}
		</div>

		<!-- Stats -->
		<div class="grid grid-cols-4 gap-3 text-center">
			<div>
				<div class="text-lg font-bold text-gray-100">{$scanStatus.hosts_discovered}</div>
				<div class="text-xs text-gray-500">Hosts</div>
			</div>
			<div>
				<div class="text-lg font-bold text-gray-100">{$scanStatus.findings_count}</div>
				<div class="text-xs text-gray-500">Findings</div>
			</div>
			<div>
				<div class="text-lg font-bold" class:text-red-400={$scanStatus.critical_count > 0} class:text-gray-100={$scanStatus.critical_count === 0}>
					{$scanStatus.critical_count}
				</div>
				<div class="text-xs text-gray-500">Critical</div>
			</div>
			<div>
				<div class="text-lg font-bold" class:text-orange-400={$scanStatus.high_count > 0} class:text-gray-100={$scanStatus.high_count === 0}>
					{$scanStatus.high_count}
				</div>
				<div class="text-xs text-gray-500">High</div>
			</div>
		</div>
	</div>
{/if}
