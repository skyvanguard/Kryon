<script lang="ts">
	import { triggerBackup } from '$lib/api/admin';

	let backing = false;
	let lastBackup = '';
	let error = '';

	async function handleBackup() {
		backing = true;
		error = '';
		try {
			const result = await triggerBackup();
			lastBackup = result.path;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Backup failed';
		} finally {
			backing = false;
		}
	}
</script>

<div class="space-y-4">
	<h3 class="text-sm font-semibold text-gray-300">Database Backup</h3>

	{#if error}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-3 text-red-300 text-xs">{error}</div>
	{/if}

	<div class="bg-gray-900 border border-gray-800 rounded-lg p-5">
		<p class="text-sm text-gray-400 mb-4">
			Create a backup of the SQLite database. Backups are stored on the server filesystem.
		</p>
		<button
			on:click={handleBackup}
			disabled={backing}
			class="px-4 py-2 bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
		>
			{backing ? 'Backing up...' : 'Create Backup'}
		</button>

		{#if lastBackup}
			<div class="mt-4 bg-green-900/20 border border-green-800/50 rounded-lg p-3">
				<p class="text-xs text-green-400">Backup created:</p>
				<p class="text-xs text-green-300 font-mono mt-1">{lastBackup}</p>
			</div>
		{/if}
	</div>
</div>
