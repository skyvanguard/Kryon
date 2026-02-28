<script lang="ts">
	import { onMount } from 'svelte';
	import { listScopeRules, createScopeRule, deleteScopeRule, type ScopeRule } from '$lib/api/scope';
	import ScopeRuleForm from '$lib/components/scope/ScopeRuleForm.svelte';
	import ScopeRuleList from '$lib/components/scope/ScopeRuleList.svelte';

	let rules: ScopeRule[] = [];
	let loading = true;
	let creating = false;
	let error = '';

	async function load() {
		loading = true;
		error = '';
		try {
			rules = await listScopeRules();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load scope rules';
		} finally {
			loading = false;
		}
	}

	async function handleCreate(e: CustomEvent<{ target: string; rule_type: string; action: string; notes: string }>) {
		creating = true;
		error = '';
		try {
			await createScopeRule(e.detail);
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to create rule';
		} finally {
			creating = false;
		}
	}

	async function handleDelete(e: CustomEvent<{ id: string }>) {
		try {
			await deleteScopeRule(e.detail.id);
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete rule';
		}
	}

	onMount(() => { load(); });
</script>

<div class="flex-1 p-8 max-w-5xl mx-auto w-full space-y-6">
	<div>
		<h1 class="text-2xl font-bold text-kryon-400">Scope Management</h1>
		<p class="text-gray-500 text-sm mt-1">Define allowed and denied targets for agent operations</p>
	</div>

	{#if error}
		<div class="bg-red-900/30 border border-red-800 rounded-lg p-4 text-red-300 text-sm">{error}</div>
	{/if}

	<ScopeRuleForm {creating} on:create={handleCreate} />

	{#if loading}
		<p class="text-gray-500 text-sm">Loading scope rules...</p>
	{:else}
		<ScopeRuleList {rules} on:delete={handleDelete} />
	{/if}
</div>
