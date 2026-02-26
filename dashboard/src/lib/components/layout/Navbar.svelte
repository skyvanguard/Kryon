<script lang="ts">
	import { page } from '$app/stores';
	import { currentUser, isAuthenticated } from '$lib/stores/auth';
	import { logout } from '$lib/api/client';
</script>

<nav class="bg-gray-900 border-b border-kryon-800 px-6 py-3 flex items-center justify-between">
	<div class="flex items-center gap-3">
		<span class="text-kryon-500 font-bold text-xl tracking-wider">KRYON</span>
		<span class="text-gray-500 text-sm">Dashboard</span>
	</div>
	<div class="flex gap-4 text-sm items-center">
		<a href="/" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/'}>
			Home
		</a>
		<a href="/usage" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/usage'}>
			Usage
		</a>
		<a href="/engagements" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname.startsWith('/engagements')}>
			Engagements
		</a>
		<a href="/scans" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/scans'}>
			Scans
		</a>
		<a href="/knowledge" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/knowledge'}>
			Knowledge
		</a>
		<a href="/sessions" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/sessions'}>
			Sessions
		</a>

		{#if $isAuthenticated && $currentUser}
			<span class="border-l border-gray-700 pl-4 text-gray-400">
				{$currentUser.username}
				<span class="text-xs text-gray-600 ml-1">({$currentUser.role})</span>
			</span>
			<button
				on:click={logout}
				class="text-gray-400 hover:text-red-400 transition-colors text-xs"
			>
				Logout
			</button>
		{/if}
	</div>
</nav>
