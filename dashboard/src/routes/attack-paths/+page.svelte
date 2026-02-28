<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api/client';
  import {
    getClientAttackPaths,
    getClientChains,
    type AttackPath,
    type KillChain
  } from '$lib/api/attackPaths';
  import AttackPathGraph from '$lib/components/visualization/AttackPathGraph.svelte';
  import KillChainView from '$lib/components/visualization/KillChainView.svelte';

  interface Client {
    id: string;
    name: string;
  }

  let clients: Client[] = [];
  let selectedClientId = '';
  let attackPaths: AttackPath[] = [];
  let killChains: KillChain[] = [];
  let loading = false;
  let error = '';
  let activeView: 'graph' | 'chains' = 'graph';

  onMount(() => {
    loadClients();
  });

  async function loadClients() {
    try {
      clients = await apiFetch<Client[]>('/clients');
      if (clients.length > 0) {
        selectedClientId = clients[0].id;
        await loadData();
      }
    } catch (e) {
      error = 'Error al cargar clientes: ' + (e as Error).message;
    }
  }

  async function loadData() {
    if (!selectedClientId) return;

    try {
      loading = true;
      error = '';

      const [paths, chains] = await Promise.all([
        getClientAttackPaths(selectedClientId),
        getClientChains(selectedClientId)
      ]);

      attackPaths = paths;
      killChains = chains;
    } catch (e) {
      error = 'Error al cargar rutas de ataque: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function handleClientChange() {
    await loadData();
  }

  $: combinedPath = attackPaths.length > 0 ? attackPaths[0] : { nodes: [], edges: [] };
</script>

<div class="container mx-auto p-6">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold text-kryon-400">Rutas de Ataque</h1>

    <div class="flex gap-4">
      <select
        bind:value={selectedClientId}
        on:change={handleClientChange}
        class="px-4 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      >
        {#each clients as client}
          <option value={client.id}>{client.name}</option>
        {/each}
      </select>
    </div>
  </div>

  {#if error}
    <div class="bg-red-900/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-4">
      {error}
    </div>
  {/if}

  <div class="border-b border-gray-700 mb-6">
    <nav class="flex gap-4">
      <button
        on:click={() => (activeView = 'graph')}
        class="pb-2 px-1 border-b-2 transition-colors {activeView === 'graph'
          ? 'border-kryon-500 text-kryon-400'
          : 'border-transparent text-gray-400 hover:text-gray-300'}"
      >
        Vista de Grafo
      </button>
      <button
        on:click={() => (activeView = 'chains')}
        class="pb-2 px-1 border-b-2 transition-colors {activeView === 'chains'
          ? 'border-kryon-500 text-kryon-400'
          : 'border-transparent text-gray-400 hover:text-gray-300'}"
      >
        Kill Chains ({killChains.length})
      </button>
    </nav>
  </div>

  {#if loading}
    <div class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500"></div>
      <p class="text-gray-400 mt-4">Analizando rutas de ataque...</p>
    </div>
  {:else if activeView === 'graph'}
    <div class="space-y-6">
      {#if attackPaths.length > 0}
        <div class="grid grid-cols-3 gap-4 mb-4">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <p class="text-sm text-gray-500">Rutas Detectadas</p>
            <p class="text-2xl font-bold text-gray-300">{attackPaths.length}</p>
          </div>
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <p class="text-sm text-gray-500">Riesgo Promedio</p>
            <p class="text-2xl font-bold text-orange-400">
              {(attackPaths.reduce((sum, p) => sum + p.risk_score, 0) / attackPaths.length).toFixed(
                1
              )}
            </p>
          </div>
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <p class="text-sm text-gray-500">Longitud Promedio</p>
            <p class="text-2xl font-bold text-gray-300">
              {(attackPaths.reduce((sum, p) => sum + p.length, 0) / attackPaths.length).toFixed(1)}
              pasos
            </p>
          </div>
        </div>
      {/if}

      <AttackPathGraph nodes={combinedPath.nodes} edges={combinedPath.edges} />

      {#if attackPaths.length === 0}
        <div class="bg-gray-900 border border-gray-700 rounded-lg p-12 text-center">
          <p class="text-gray-500">No se encontraron rutas de ataque para este cliente.</p>
          <p class="text-sm text-gray-600 mt-2">
            Ejecuta un escaneo completo para generar el análisis de rutas.
          </p>
        </div>
      {/if}
    </div>
  {:else if activeView === 'chains'}
    <KillChainView chains={killChains} />
  {/if}
</div>
