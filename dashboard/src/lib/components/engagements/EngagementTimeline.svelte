<script lang="ts">
	import type { EngagementPhase } from '$lib/api/engagements';

	export let phases: EngagementPhase[] = [];

	const phaseColors: Record<string, string> = {
		reconnaissance: 'bg-blue-500',
		vulnerability_assessment: 'bg-yellow-500',
		exploitation: 'bg-red-500',
		deep_exploitation: 'bg-red-700',
		lateral_movement: 'bg-purple-500',
		persistence_testing: 'bg-orange-500',
		reporting: 'bg-green-500'
	};

	const phaseLabels: Record<string, string> = {
		reconnaissance: 'Recon',
		vulnerability_assessment: 'Vuln Scan',
		exploitation: 'Exploit',
		deep_exploitation: 'Deep Exploit',
		lateral_movement: 'Lateral Mvmt',
		persistence_testing: 'Persistence',
		reporting: 'Report'
	};

	const statusIcons: Record<string, string> = {
		pending: '○',
		running: '◉',
		completed: '●',
		failed: '✕',
		skipped: '–'
	};

	// Group phases by day
	$: dayGroups = phases.reduce(
		(acc, phase) => {
			const day = phase.day_number;
			if (!acc[day]) acc[day] = [];
			acc[day].push(phase);
			return acc;
		},
		{} as Record<number, EngagementPhase[]>
	);
</script>

<div class="space-y-3">
	{#each Object.entries(dayGroups) as [day, dayPhases]}
		<div class="flex items-start gap-3">
			<div
				class="text-xs text-gray-500 font-mono w-12 pt-2 flex-shrink-0 text-right"
			>
				Day {day}
			</div>
			<div class="flex-1 flex flex-wrap gap-2">
				{#each dayPhases as phase (phase.id)}
					<div
						class="relative flex items-center gap-2 px-3 py-2 rounded-lg border text-xs
						{phase.status === 'running'
							? 'border-kryon-500/50 bg-kryon-500/10'
							: phase.status === 'completed'
								? 'border-gray-600 bg-gray-800/50'
								: phase.status === 'failed'
									? 'border-red-500/50 bg-red-500/10'
									: 'border-gray-700/50 bg-gray-800/30'}"
					>
						<span
							class="w-2 h-2 rounded-full {phaseColors[phase.phase_type] ||
								'bg-gray-500'} {phase.status === 'running' ? 'animate-pulse' : ''}"
						></span>
						<span class="text-gray-300">
							{phaseLabels[phase.phase_type] || phase.phase_type}
						</span>
						<span
							class="text-gray-500 {phase.status === 'running'
								? 'text-kryon-400'
								: phase.status === 'failed'
									? 'text-red-400'
									: phase.status === 'completed'
										? 'text-green-400'
										: ''}"
						>
							{statusIcons[phase.status] || '○'}
						</span>
						{#if phase.status === 'running' && phase.progress > 0}
							<div class="absolute bottom-0 left-0 h-0.5 bg-kryon-500 rounded-b-lg transition-all" style="width: {phase.progress * 100}%"></div>
						{/if}
					</div>
				{/each}
			</div>
		</div>
	{/each}
</div>
