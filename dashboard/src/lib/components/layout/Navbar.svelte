<script lang="ts">
	import { page } from '$app/stores';
</script>

<nav class="bg-gray-900 border-b border-kryon-800 px-6 py-3 flex items-center justify-between">
	<div class="flex items-center gap-3">
		<span class="text-kryon-500 font-bold text-xl tracking-wider">KRYON</span>
		<span class="text-gray-500 text-sm">Dashboard</span>
	</div>
	<div class="flex gap-4 text-sm">
		<a href="/" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/'}>
			Home
		</a>
		<a href="/usage" class="hover:text-kryon-400 transition-colors" class:text-kryon-400={$page.url.pathname === '/usage'}>
			Usage
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
	</div>
</nav>
