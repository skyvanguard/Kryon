<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import type { CreateEngagementRequest } from '$lib/api/engagements';

	const dispatch = createEventDispatcher<{ create: CreateEngagementRequest }>();

	let clientName = '';
	let targetsText = '';
	let durationDays = 5;
	let stealthLevel = 'normal';
	let intervalMinutes = 30;
	let objectives = ['initial_access', 'vulnerability_assessment', 'exploitation'];

	const allObjectives = [
		{ value: 'initial_access', label: 'Initial Access' },
		{ value: 'vulnerability_assessment', label: 'Vulnerability Assessment' },
		{ value: 'exploitation', label: 'Exploitation' },
		{ value: 'lateral_movement', label: 'Lateral Movement' },
		{ value: 'persistence', label: 'Persistence Testing' }
	];

	function toggleObjective(val: string) {
		if (objectives.includes(val)) {
			objectives = objectives.filter((o) => o !== val);
		} else {
			objectives = [...objectives, val];
		}
	}

	function handleSubmit() {
		const targets = targetsText
			.split('\n')
			.map((t) => t.trim())
			.filter(Boolean);
		if (!clientName || targets.length === 0) return;

		dispatch('create', {
			client_name: clientName,
			targets,
			objectives,
			duration_days: durationDays,
			stealth_level: stealthLevel,
			phase_interval_minutes: intervalMinutes
		});
	}
</script>

<form
	on:submit|preventDefault={handleSubmit}
	class="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6 space-y-5"
>
	<h2 class="text-lg font-semibold text-kryon-400">New Engagement</h2>

	<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
		<div>
			<label for="client" class="block text-sm text-gray-400 mb-1">Client Name</label>
			<input
				id="client"
				type="text"
				bind:value={clientName}
				placeholder="ACME Corp"
				required
				class="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-kryon-500"
			/>
		</div>
		<div>
			<label for="duration" class="block text-sm text-gray-400 mb-1"
				>Duration (days): {durationDays}</label
			>
			<input
				id="duration"
				type="range"
				min="1"
				max="30"
				bind:value={durationDays}
				class="w-full accent-kryon-500"
			/>
		</div>
	</div>

	<div>
		<label for="targets" class="block text-sm text-gray-400 mb-1">Targets (one per line)</label>
		<textarea
			id="targets"
			bind:value={targetsText}
			placeholder="192.168.1.0/24&#10;10.0.0.1&#10;example.com"
			rows="3"
			required
			class="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 font-mono focus:outline-none focus:border-kryon-500"
		></textarea>
	</div>

	<div>
		<span class="block text-sm text-gray-400 mb-2">Objectives</span>
		<div class="flex flex-wrap gap-2">
			{#each allObjectives as obj}
				<button
					type="button"
					on:click={() => toggleObjective(obj.value)}
					class="px-3 py-1 text-xs rounded-full border transition-colors {objectives.includes(
						obj.value
					)
						? 'bg-kryon-500/20 border-kryon-500/50 text-kryon-300'
						: 'bg-gray-800 border-gray-700 text-gray-500 hover:border-gray-600'}"
				>
					{obj.label}
				</button>
			{/each}
		</div>
	</div>

	<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
		<div>
			<label for="stealth" class="block text-sm text-gray-400 mb-1">Stealth Level</label>
			<select
				id="stealth"
				bind:value={stealthLevel}
				class="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-kryon-500"
			>
				<option value="low">Low</option>
				<option value="normal">Normal</option>
				<option value="high">High</option>
			</select>
		</div>
		<div>
			<label for="interval" class="block text-sm text-gray-400 mb-1"
				>Phase Interval: {intervalMinutes} min</label
			>
			<input
				id="interval"
				type="range"
				min="0"
				max="120"
				step="5"
				bind:value={intervalMinutes}
				class="w-full accent-kryon-500"
			/>
		</div>
	</div>

	<button
		type="submit"
		class="w-full bg-kryon-600 hover:bg-kryon-500 text-white font-medium rounded-lg py-2.5 text-sm transition-colors"
	>
		Launch Engagement
	</button>
</form>
