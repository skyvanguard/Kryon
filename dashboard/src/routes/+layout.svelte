<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';
	import Navbar from '$lib/components/layout/Navbar.svelte';
	import Footer from '$lib/components/layout/Footer.svelte';
	import { isAuthenticated } from '$lib/stores/auth';

	// Login page doesn't need the navbar/footer chrome
	$: isLoginPage = $page.url.pathname === '/login';
</script>

{#if isLoginPage}
	<slot />
{:else}
	<div class="flex flex-col min-h-screen bg-gray-950 text-gray-100">
		<Navbar />
		<main class="flex-1 flex">
			<slot />
		</main>
		<Footer />
	</div>
{/if}
