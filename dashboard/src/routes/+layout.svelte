<script lang="ts">
	import '../app.css';
	import Navbar from '$lib/components/layout/Navbar.svelte';
	import Footer from '$lib/components/layout/Footer.svelte';
</script>

<div class="flex flex-col min-h-screen bg-gray-950 text-gray-100">
	<Navbar />
	<main class="flex-1 flex">
		<slot />
	</main>
	<Footer />
</div>
