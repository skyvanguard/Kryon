<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { page } from '$app/stores';
	import {
		getEngagement,
		pauseEngagement,
		resumeEngagement,
		cancelEngagement,
		connectEngagementSSE,
		type EngagementDetail
	} from '$lib/api/engagements';
	import EngagementTimeline from '$lib/components/engagements/EngagementTimeline.svelte';
	import EngagementLog from '$lib/components/engagements/EngagementLog.svelte';

	let engagement: EngagementDetail | null = null;
	let logs: string[] = [];
	let eventSource: EventSource | null = null;
	let pollInterval: ReturnType<typeof setInterval>;

	$: engId = $page.params.id;

	const statusColors: Record<string, string> = {
		created: 'bg-gray-500/20 text-gray-400',
		planning: 'bg-yellow-500/20 text-yellow-400',
		active: 'bg-green-500/20 text-green-400',
		paused: 'bg-amber-500/20 text-amber-400',
		completed: 'bg-blue-500/20 text-blue-400',
		failed: 'bg-red-500/20 text-red-400',
		cancelled: 'bg-gray-500/20 text-gray-500'
	};

	async function load() {
		try {
			engagement = await getEngagement(engId);
		} catch {
			/* not found */
		}
	}

	function connectSSE() {
		eventSource = connectEngagementSSE(
			engId,
			(event, data) => {
				if (event === 'log' && data.message) {
					logs = [...logs, data.message as string];
				} else if (event === 'phase_start') {
					logs = [
						...logs,
						`Phase started: ${data.phase_type} (${data.agent_key}) - Day ${data.day_number}`
					];
					load();
				} else if (event === 'phase_complete') {
					logs = [...logs, `Phase completed (${data.findings_count} findings)`];
					load();
				} else if (event === 'phase_update') {
					load();
				} else if (event === 'plan_ready') {
					logs = [...logs, `Plan ready: ${data.phase_count} phases`];
					load();
				} else if (event === 'status') {
					logs = [...logs, `Status: ${data.status}`];
					load();
				}
			},
			(data) => {
				logs = [...logs, `Engagement ${data.status}`];
				load();
			}
		);
	}

	async function handlePause() {
		await pauseEngagement(engId);
		load();
	}

	async function handleResume() {
		await resumeEngagement(engId);
		load();
		connectSSE();
	}

	async function handleCancel() {
		if (confirm('Cancel this engagement?')) {
			await cancelEngagement(engId);
			load();
		}
	}

	onMount(() => {
		load();
		connectSSE();
		pollInterval = setInterval(load, 5000);
	});

	onDestroy(() => {
		eventSource?.close();
		clearInterval(pollInterval);
	});
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	{#if engagement}
		<!-- Header -->
		<div class="flex items-start justify-between">
			<div>
				<div class="flex items-center gap-3 mb-1">
					<a href="/engagements" class="text-gray-500 hover:text-gray-300 text-sm"
						>&larr; Engagements</a
					>
				</div>
				<h1 class="text-2xl font-bold text-gray-100">{engagement.client_name}</h1>
				<div class="flex items-center gap-3 mt-2">
					<span
						class="px-2 py-0.5 text-xs rounded-full font-medium {statusColors[
							engagement.status
						] || 'bg-gray-500/20 text-gray-400'}"
					>
						{engagement.status === 'active' ? '● ' : ''}{engagement.status.toUpperCase()}
					</span>
					<span class="text-gray-500 text-xs">{engagement.duration_days}d plan</span>
					<span class="text-gray-500 text-xs"
						>{engagement.targets.length} target{engagement.targets.length !== 1
							? 's'
							: ''}</span
					>
					{#if engagement.total_findings > 0}
						<span class="text-kryon-400 text-xs"
							>{engagement.total_findings} findings</span
						>
					{/if}
				</div>
			</div>
			<div class="flex gap-2">
				{#if engagement.status === 'active'}
					<button
						on:click={handlePause}
						class="px-3 py-1.5 text-xs bg-amber-600/20 text-amber-400 border border-amber-600/30 rounded-lg hover:bg-amber-600/30 transition-colors"
					>
						Pause
					</button>
				{/if}
				{#if engagement.status === 'paused'}
					<button
						on:click={handleResume}
						class="px-3 py-1.5 text-xs bg-green-600/20 text-green-400 border border-green-600/30 rounded-lg hover:bg-green-600/30 transition-colors"
					>
						Resume
					</button>
				{/if}
				{#if ['active', 'paused', 'planning'].includes(engagement.status)}
					<button
						on:click={handleCancel}
						class="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 border border-red-600/30 rounded-lg hover:bg-red-600/30 transition-colors"
					>
						Cancel
					</button>
				{/if}
			</div>
		</div>

		<!-- Targets -->
		<div class="bg-gray-800/30 border border-gray-700/30 rounded-xl p-4">
			<h3 class="text-sm font-medium text-gray-400 mb-2">Targets</h3>
			<div class="flex flex-wrap gap-2">
				{#each engagement.targets as target}
					<span class="px-2 py-0.5 bg-gray-900/50 text-gray-300 text-xs font-mono rounded"
						>{target}</span
					>
				{/each}
			</div>
		</div>

		<!-- Timeline -->
		{#if engagement.phases && engagement.phases.length > 0}
			<div class="bg-gray-800/30 border border-gray-700/30 rounded-xl p-4">
				<h3 class="text-sm font-medium text-gray-400 mb-3">Execution Plan</h3>
				<EngagementTimeline phases={engagement.phases} />
			</div>
		{:else if engagement.status === 'planning'}
			<div
				class="bg-gray-800/30 border border-gray-700/30 rounded-xl p-8 text-center text-gray-500"
			>
				<p class="animate-pulse">Agents are planning the engagement...</p>
			</div>
		{/if}

		<!-- Stats -->
		{#if engagement.total_findings > 0}
			<div class="grid grid-cols-3 gap-4">
				<div class="bg-gray-800/30 border border-gray-700/30 rounded-xl p-4 text-center">
					<p class="text-2xl font-bold text-gray-200">{engagement.total_findings}</p>
					<p class="text-xs text-gray-500 mt-1">Total Findings</p>
				</div>
				<div class="bg-gray-800/30 border border-red-500/20 rounded-xl p-4 text-center">
					<p class="text-2xl font-bold text-red-400">{engagement.critical_findings}</p>
					<p class="text-xs text-gray-500 mt-1">Critical</p>
				</div>
				<div class="bg-gray-800/30 border border-orange-500/20 rounded-xl p-4 text-center">
					<p class="text-2xl font-bold text-orange-400">{engagement.high_findings}</p>
					<p class="text-xs text-gray-500 mt-1">High</p>
				</div>
			</div>
		{/if}

		<!-- Log -->
		<div>
			<h3 class="text-sm font-medium text-gray-400 mb-2">Activity Log</h3>
			<EngagementLog {logs} />
		</div>

		<!-- Error -->
		{#if engagement.error}
			<div class="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
				<p class="text-red-400 text-sm">{engagement.error}</p>
			</div>
		{/if}
	{:else}
		<p class="text-gray-500">Loading engagement...</p>
	{/if}
</div>
