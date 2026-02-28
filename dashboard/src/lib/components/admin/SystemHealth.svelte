<script lang="ts">
	import { onMount } from 'svelte';
	import { getAdminHealth, type SystemHealth } from '$lib/api/admin';

	let health: SystemHealth | null = null;
	let loading = true;
	let error = '';

	function formatUptime(seconds: number): string {
		const d = Math.floor(seconds / 86400);
		const h = Math.floor((seconds % 86400) / 3600);
		const m = Math.floor((seconds % 3600) / 60);
		if (d > 0) return `${d}d ${h}h ${m}m`;
		if (h > 0) return `${h}h ${m}m`;
		return `${m}m`;
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1048576).toFixed(1)} MB`;
	}

	async function load() {
		loading = true;
		error = '';
		try {
			health = await getAdminHealth();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load health data';
		} finally {
			loading = false;
		}
	}

	onMount(() => { load(); });
</script>

<div class="space-y-4">
	<h3 class="text-sm font-semibold text-gray-300">System Health</h3>

	{#if error}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-3 text-red-300 text-xs">{error}</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading health data...</p>
	{:else if health}
		<div class="grid grid-cols-2 md:grid-cols-4 gap-4">
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">Status</p>
				<p class="text-lg font-bold {health.status === 'healthy' ? 'text-green-400' : 'text-red-400'}">
					{health.status}
				</p>
			</div>
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">Uptime</p>
				<p class="text-lg font-bold text-gray-200">{formatUptime(health.uptime_seconds)}</p>
			</div>
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">DB Size</p>
				<p class="text-lg font-bold text-gray-200">{formatBytes(health.db_size_bytes)}</p>
			</div>
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">AI Provider</p>
				<p class="text-lg font-bold text-gray-200">{health.ai_provider}</p>
			</div>
		</div>

		<div class="grid grid-cols-2 md:grid-cols-4 gap-4">
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">Total Scans</p>
				<p class="text-2xl font-bold text-kryon-400">{health.total_scans}</p>
			</div>
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">Total Findings</p>
				<p class="text-2xl font-bold text-orange-400">{health.total_findings}</p>
			</div>
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">Total Clients</p>
				<p class="text-2xl font-bold text-blue-400">{health.total_clients}</p>
			</div>
			<div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
				<p class="text-xs text-gray-500 mb-1">RAG Documents</p>
				<p class="text-2xl font-bold text-purple-400">{health.rag_documents}</p>
			</div>
		</div>
	{/if}
</div>
