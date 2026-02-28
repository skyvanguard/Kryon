<script lang="ts">
	import { onMount } from 'svelte';
	import { listUsers, createUser, deleteUser, type AdminUser } from '$lib/api/admin';

	let users: AdminUser[] = [];
	let loading = true;
	let showForm = false;
	let newUsername = '';
	let newPassword = '';
	let newRole = 'analyst';
	let creating = false;
	let error = '';

	async function load() {
		loading = true;
		try {
			users = await listUsers();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	async function handleCreate() {
		if (!newUsername || !newPassword) return;
		creating = true;
		error = '';
		try {
			await createUser({ username: newUsername, password: newPassword, role: newRole });
			newUsername = '';
			newPassword = '';
			newRole = 'analyst';
			showForm = false;
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to create user';
		} finally {
			creating = false;
		}
	}

	async function handleDelete(user: AdminUser) {
		if (!confirm(`Delete user "${user.username}"?`)) return;
		try {
			await deleteUser(user.id);
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete user';
		}
	}

	onMount(() => { load(); });
</script>

<div class="space-y-4">
	<div class="flex items-center justify-between">
		<h3 class="text-sm font-semibold text-gray-300">Users</h3>
		<button
			on:click={() => (showForm = !showForm)}
			class="px-3 py-1.5 bg-kryon-600 hover:bg-kryon-500 text-white text-xs rounded-lg transition-colors"
		>
			{showForm ? 'Cancel' : '+ New User'}
		</button>
	</div>

	{#if error}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-3 text-red-300 text-xs">{error}</div>
	{/if}

	{#if showForm}
		<form on:submit|preventDefault={handleCreate} class="bg-gray-800/50 border border-gray-700 rounded-lg p-4 space-y-3">
			<div class="grid grid-cols-3 gap-3">
				<input
					bind:value={newUsername}
					required
					placeholder="Username"
					class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
				/>
				<input
					bind:value={newPassword}
					required
					type="password"
					placeholder="Password"
					class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
				/>
				<select
					bind:value={newRole}
					class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-kryon-500 focus:outline-none"
				>
					<option value="admin">Admin</option>
					<option value="analyst">Analyst</option>
					<option value="viewer">Viewer</option>
				</select>
			</div>
			<button
				type="submit"
				disabled={creating}
				class="px-3 py-1.5 bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white text-xs rounded-lg transition-colors"
			>
				{creating ? 'Creating...' : 'Create User'}
			</button>
		</form>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading users...</p>
	{:else}
		<div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
			<table class="w-full text-sm">
				<thead>
					<tr class="text-left text-xs text-gray-500 border-b border-gray-800">
						<th class="px-4 py-2">Username</th>
						<th class="px-4 py-2">Role</th>
						<th class="px-4 py-2">Created</th>
						<th class="px-4 py-2">Last Login</th>
						<th class="px-4 py-2"></th>
					</tr>
				</thead>
				<tbody>
					{#each users as user (user.id)}
						<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
							<td class="px-4 py-2 text-gray-200">{user.username}</td>
							<td class="px-4 py-2">
								<span class="px-2 py-0.5 rounded text-xs {
									user.role === 'admin' ? 'bg-red-900/50 text-red-300' :
									user.role === 'analyst' ? 'bg-blue-900/50 text-blue-300' :
									'bg-gray-800 text-gray-400'
								}">
									{user.role}
								</span>
							</td>
							<td class="px-4 py-2 text-gray-500 text-xs">{new Date(user.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-2 text-gray-500 text-xs">{user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
							<td class="px-4 py-2">
								<button
									on:click={() => handleDelete(user)}
									class="text-red-400 hover:text-red-300 text-xs transition-colors"
								>
									Delete
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
