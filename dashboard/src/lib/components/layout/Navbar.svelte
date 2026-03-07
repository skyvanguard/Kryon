<script lang="ts">
	import { page } from '$app/stores';
	import { currentUser, isAuthenticated } from '$lib/stores/auth';
	import { logout } from '$lib/api/client';

	$: isAdmin = $currentUser?.role === 'admin';

	let moreOpen = false;

	function toggleMore() {
		moreOpen = !moreOpen;
	}

	function closeMore() {
		moreOpen = false;
	}
</script>

<svelte:window on:click={closeMore} />

<nav class="bg-gray-900 border-b border-kryon-800 px-6 py-3 flex items-center justify-between">
	<div class="flex items-center gap-6">
		<a href="/" class="text-kryon-500 font-bold text-xl tracking-wider">KRYON</a>

		<div class="flex gap-4 text-sm">
			<a
				href="/"
				class="hover:text-kryon-400 transition-colors"
				class:text-kryon-400={$page.url.pathname === '/'}
			>
				Chat
			</a>
			<a
				href="/agents"
				class="hover:text-kryon-400 transition-colors"
				class:text-kryon-400={$page.url.pathname.startsWith('/agents')}
			>
				Agents
			</a>
			<a
				href="/findings"
				class="hover:text-kryon-400 transition-colors"
				class:text-kryon-400={$page.url.pathname.startsWith('/findings')}
			>
				Findings
			</a>
			<a
				href="/scans"
				class="hover:text-kryon-400 transition-colors"
				class:text-kryon-400={$page.url.pathname === '/scans'}
			>
				Scans
			</a>
			<a
				href="/knowledge"
				class="hover:text-kryon-400 transition-colors"
				class:text-kryon-400={$page.url.pathname === '/knowledge'}
			>
				Knowledge
			</a>

			<!-- More dropdown -->
			<div class="relative">
				<button
					on:click|stopPropagation={toggleMore}
					class="hover:text-kryon-400 transition-colors flex items-center gap-1"
					class:text-kryon-400={moreOpen}
				>
					More
					<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
					</svg>
				</button>
				{#if moreOpen}
					<div
						class="absolute top-full left-0 mt-2 w-48 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 py-1"
					>
						<a href="/engagements" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Engagements</a>
						<a href="/clients" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Clients</a>
						<a href="/reports" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Reports</a>
						<a href="/assets" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Assets</a>
						<a href="/appsec" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">AppSec</a>
						<a href="/compliance" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Compliance</a>
						<a href="/remediation" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Remediation</a>
						<a href="/risk" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Risk</a>
						<a href="/attack-paths" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Attack Paths</a>
						<a href="/scope" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Scope</a>
						<a href="/onboarding" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Onboarding</a>
						{#if isAdmin}
							<div class="border-t border-gray-700 my-1"></div>
							<a href="/notifications" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Notifications</a>
							<a href="/billing" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Billing</a>
							<a href="/admin" class="block px-4 py-2 text-sm hover:bg-gray-800 hover:text-kryon-400 transition-colors">Admin</a>
						{/if}
					</div>
				{/if}
			</div>
		</div>
	</div>

	<div class="flex items-center gap-4 text-sm">
		{#if $isAuthenticated && $currentUser}
			<span class="text-gray-400">
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
