<script lang="ts">
	import { login } from '$lib/api/client';
	import { goto } from '$app/navigation';

	let username = '';
	let password = '';
	let error = '';
	let loading = false;

	async function handleLogin() {
		error = '';
		loading = true;
		try {
			await login(username, password);
			goto('/');
		} catch (e: any) {
			error = e.message || 'Login failed';
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-gray-950">
	<div class="bg-gray-900 border border-gray-800 rounded-lg p-8 w-full max-w-sm">
		<div class="text-center mb-6">
			<h1 class="text-kryon-500 font-bold text-2xl tracking-wider">KRYON</h1>
			<p class="text-gray-400 text-sm mt-1">Enterprise Security Platform</p>
		</div>

		<form on:submit|preventDefault={handleLogin} class="space-y-4">
			{#if error}
				<div class="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-3 py-2">
					{error}
				</div>
			{/if}

			<div>
				<label for="username" class="block text-sm text-gray-400 mb-1">Username</label>
				<input
					id="username"
					type="text"
					bind:value={username}
					class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 focus:outline-none focus:border-kryon-500"
					placeholder="admin"
					required
				/>
			</div>

			<div>
				<label for="password" class="block text-sm text-gray-400 mb-1">Password</label>
				<input
					id="password"
					type="password"
					bind:value={password}
					class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-100 focus:outline-none focus:border-kryon-500"
					required
				/>
			</div>

			<button
				type="submit"
				disabled={loading}
				class="w-full bg-kryon-600 hover:bg-kryon-500 disabled:opacity-50 text-white font-medium rounded px-4 py-2 transition-colors"
			>
				{loading ? 'Signing in...' : 'Sign In'}
			</button>
		</form>
	</div>
</div>
