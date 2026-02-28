<script lang="ts">
	import { currentUser } from '$lib/stores/auth';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import UserManager from '$lib/components/admin/UserManager.svelte';
	import AuditLog from '$lib/components/admin/AuditLog.svelte';
	import SystemHealth from '$lib/components/admin/SystemHealth.svelte';
	import BackupPanel from '$lib/components/admin/BackupPanel.svelte';

	let activeTab: 'health' | 'users' | 'audit' | 'backup' = 'health';

	onMount(() => {
		if ($currentUser && $currentUser.role !== 'admin') {
			goto('/');
		}
	});
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	<div>
		<h1 class="text-2xl font-bold text-kryon-400">Admin Panel</h1>
		<p class="text-gray-500 text-sm mt-1">System management and administration</p>
	</div>

	{#if $currentUser?.role !== 'admin'}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-8 text-center">
			<p class="text-red-300">Access denied. Admin role required.</p>
		</div>
	{:else}
		<div class="flex gap-4 border-b border-gray-800 pb-1">
			{#each [
				{ key: 'health', label: 'System Health' },
				{ key: 'users', label: 'Users' },
				{ key: 'audit', label: 'Audit Log' },
				{ key: 'backup', label: 'Backup' }
			] as tab}
				<button
					on:click={() => (activeTab = tab.key as typeof activeTab)}
					class="px-3 py-2 text-sm transition-colors {activeTab === tab.key
						? 'text-kryon-400 border-b-2 border-kryon-400'
						: 'text-gray-500 hover:text-gray-300'}"
				>
					{tab.label}
				</button>
			{/each}
		</div>

		{#if activeTab === 'health'}
			<SystemHealth />
		{:else if activeTab === 'users'}
			<UserManager />
		{:else if activeTab === 'audit'}
			<AuditLog />
		{:else if activeTab === 'backup'}
			<BackupPanel />
		{/if}
	{/if}
</div>
