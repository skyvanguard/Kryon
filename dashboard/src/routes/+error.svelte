<script lang="ts">
	import { page } from '$app/stores';
	import Navbar from '$lib/components/layout/Navbar.svelte';
	import Footer from '$lib/components/layout/Footer.svelte';
</script>

<div class="flex flex-col min-h-screen bg-gray-950 text-gray-100">
	<Navbar></Navbar>
	<main class="flex-1 flex items-center justify-center">
		<div class="text-center space-y-4 p-8">
			<h1 class="text-6xl font-bold text-kryon-400">{$page.status}</h1>
			<p class="text-xl text-gray-400">
				{$page.error?.message || 'Something went wrong'}
			</p>
			<a
				href="/"
				class="inline-block px-4 py-2 bg-kryon-600 hover:bg-kryon-500 text-white text-sm font-medium rounded-lg transition-colors"
			>
				Return Home
			</a>
		</div>
	</main>
	<Footer></Footer>
</div>
