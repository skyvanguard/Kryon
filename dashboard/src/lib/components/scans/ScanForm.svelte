<script lang="ts">
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	let targets = '';
	let profile = 'standard';
	let clientName = '';
	let maxTime = 4;
	let stealth = 'normal';
	let outputFormat = 'html';

	const profiles = [
		{ value: 'quick', label: 'Quick (5-10 min)' },
		{ value: 'standard', label: 'Standard (30-60 min)' },
		{ value: 'deep', label: 'Deep (2-4 hours)' },
		{ value: 'compliance', label: 'Compliance (1-2 hours)' },
		{ value: 'enterprise_quick', label: 'Enterprise Quick (30 min)' },
		{ value: 'enterprise_standard', label: 'Enterprise Standard (2h)' },
		{ value: 'enterprise_deep', label: 'Enterprise Deep (8h)' },
		{ value: 'enterprise_compliance', label: 'Enterprise Compliance (4h)' }
	];

	function handleSubmit() {
		const targetList = targets
			.split(',')
			.map((t) => t.trim())
			.filter(Boolean);
		if (!targetList.length) return;

		dispatch('start', {
			targets: targetList,
			profile,
			client_id: clientName,
			max_time_hours: maxTime,
			stealth_level: stealth,
			output_format: outputFormat
		});
	}
</script>

<form on:submit|preventDefault={handleSubmit} class="space-y-4 bg-gray-900 rounded-lg p-6 border border-gray-800">
	<h2 class="text-lg font-bold text-kryon-400">New Autonomous Scan</h2>

	<div>
		<label for="targets" class="block text-sm text-gray-400 mb-1">Targets</label>
		<input
			id="targets"
			bind:value={targets}
			placeholder="192.168.1.0/24 or 10.10.10.5, 10.10.10.6"
			class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:border-kryon-500 focus:outline-none"
			required
		/>
		<p class="text-xs text-gray-600 mt-1">CIDR notation, single IPs, or comma-separated</p>
	</div>

	<div class="grid grid-cols-2 gap-4">
		<div>
			<label for="profile" class="block text-sm text-gray-400 mb-1">Profile</label>
			<select
				id="profile"
				bind:value={profile}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:border-kryon-500 focus:outline-none"
			>
				{#each profiles as p}
					<option value={p.value}>{p.label}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="client" class="block text-sm text-gray-400 mb-1">Client</label>
			<input
				id="client"
				bind:value={clientName}
				placeholder="ACME Corp"
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:border-kryon-500 focus:outline-none"
			/>
		</div>
	</div>

	<div class="grid grid-cols-3 gap-4">
		<div>
			<label for="maxTime" class="block text-sm text-gray-400 mb-1">Max Time (hours)</label>
			<input
				id="maxTime"
				type="number"
				bind:value={maxTime}
				min="0.1"
				max="24"
				step="0.5"
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:border-kryon-500 focus:outline-none"
			/>
		</div>
		<div>
			<label for="stealth" class="block text-sm text-gray-400 mb-1">Stealth</label>
			<select
				id="stealth"
				bind:value={stealth}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:border-kryon-500 focus:outline-none"
			>
				<option value="low">Low</option>
				<option value="normal">Normal</option>
				<option value="high">High</option>
			</select>
		</div>
		<div>
			<label for="format" class="block text-sm text-gray-400 mb-1">Format</label>
			<select
				id="format"
				bind:value={outputFormat}
				class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:border-kryon-500 focus:outline-none"
			>
				<option value="html">HTML</option>
				<option value="pdf">PDF</option>
				<option value="json">JSON</option>
			</select>
		</div>
	</div>

	<button
		type="submit"
		class="w-full bg-kryon-600 hover:bg-kryon-500 text-white font-semibold py-2 px-4 rounded transition-colors"
	>
		Start Scan
	</button>
</form>
