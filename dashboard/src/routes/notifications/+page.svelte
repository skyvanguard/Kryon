<script lang="ts">
  import { onMount } from 'svelte';
  import {
    listChannels,
    createChannel,
    deleteChannel,
    testChannel,
    listRules,
    createRule,
    deleteRule,
    getNotificationLog,
    type NotificationChannel,
    type NotificationRule,
    type NotificationLogEntry
  } from '$lib/api/notifications';
  import { toast } from '$lib/stores/toast';
  import ChannelForm from '$lib/components/notifications/ChannelForm.svelte';
  import RuleEditor from '$lib/components/notifications/RuleEditor.svelte';

  let activeTab: 'channels' | 'rules' | 'log' = 'channels';
  let channels: NotificationChannel[] = [];
  let rules: NotificationRule[] = [];
  let logEntries: NotificationLogEntry[] = [];
  let loading = false;
  let error = '';
  let showChannelForm = false;
  let showRuleEditor = false;

  onMount(() => {
    loadChannels();
    loadRules();
    loadLog();
  });

  async function loadChannels() {
    try {
      loading = true;
      error = '';
      channels = await listChannels();
    } catch (e) {
      error = 'Error al cargar canales: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function loadRules() {
    try {
      rules = await listRules();
    } catch (e) {
      error = 'Error al cargar reglas: ' + (e as Error).message;
    }
  }

  async function loadLog() {
    try {
      logEntries = await getNotificationLog(100);
    } catch (e) {
      error = 'Error al cargar log: ' + (e as Error).message;
    }
  }

  async function handleCreateChannel(event: CustomEvent) {
    try {
      await createChannel(event.detail);
      showChannelForm = false;
      await loadChannels();
    } catch (e) {
      error = 'Error al crear canal: ' + (e as Error).message;
    }
  }

  async function handleDeleteChannel(id: number) {
    if (!confirm('¿Eliminar este canal?')) return;
    try {
      await deleteChannel(id);
      await loadChannels();
    } catch (e) {
      error = 'Error al eliminar canal: ' + (e as Error).message;
    }
  }

  async function handleTestChannel(id: number) {
    try {
      const result = await testChannel(id);
      if (result.success) {
        toast.success('Test exitoso: ' + result.message);
      } else {
        toast.warning('Test falló: ' + result.message);
      }
    } catch (e) {
      error = 'Error al probar canal: ' + (e as Error).message;
    }
  }

  async function handleCreateRule(event: CustomEvent) {
    try {
      await createRule(event.detail);
      showRuleEditor = false;
      await loadRules();
    } catch (e) {
      error = 'Error al crear regla: ' + (e as Error).message;
    }
  }

  async function handleDeleteRule(id: number) {
    if (!confirm('¿Eliminar esta regla?')) return;
    try {
      await deleteRule(id);
      await loadRules();
    } catch (e) {
      error = 'Error al eliminar regla: ' + (e as Error).message;
    }
  }
</script>

<div class="container mx-auto p-6">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold text-kryon-400">Notificaciones</h1>
  </div>

  {#if error}
    <div class="bg-red-900/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-4">
      {error}
    </div>
  {/if}

  <div class="border-b border-gray-700 mb-6">
    <nav class="flex gap-4">
      <button
        on:click={() => (activeTab = 'channels')}
        class="pb-2 px-1 border-b-2 transition-colors {activeTab === 'channels'
          ? 'border-kryon-500 text-kryon-400'
          : 'border-transparent text-gray-400 hover:text-gray-300'}"
      >
        Canales
      </button>
      <button
        on:click={() => (activeTab = 'rules')}
        class="pb-2 px-1 border-b-2 transition-colors {activeTab === 'rules'
          ? 'border-kryon-500 text-kryon-400'
          : 'border-transparent text-gray-400 hover:text-gray-300'}"
      >
        Reglas
      </button>
      <button
        on:click={() => (activeTab = 'log')}
        class="pb-2 px-1 border-b-2 transition-colors {activeTab === 'log'
          ? 'border-kryon-500 text-kryon-400'
          : 'border-transparent text-gray-400 hover:text-gray-300'}"
      >
        Log de Entrega
      </button>
    </nav>
  </div>

  {#if activeTab === 'channels'}
    <div class="space-y-4">
      <button
        on:click={() => (showChannelForm = !showChannelForm)}
        class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors"
      >
        {showChannelForm ? 'Cancelar' : 'Nuevo Canal'}
      </button>

      {#if showChannelForm}
        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <ChannelForm
            on:save={handleCreateChannel}
            on:cancel={() => (showChannelForm = false)}
          />
        </div>
      {/if}

      <div class="grid gap-4">
        {#each channels as channel}
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <div class="flex justify-between items-start">
              <div class="flex-1">
                <h3 class="text-lg font-semibold text-gray-300 mb-1">{channel.name}</h3>
                <p class="text-sm text-gray-500 mb-2">
                  Tipo: <span class="text-kryon-400">{channel.channel_type}</span>
                  {#if !channel.enabled}
                    <span class="ml-2 text-red-500">(Deshabilitado)</span>
                  {/if}
                </p>
                <pre
                  class="text-xs text-gray-400 bg-gray-950 p-2 rounded overflow-x-auto">{JSON.stringify(
                    channel.config,
                    null,
                    2
                  )}</pre>
              </div>
              <div class="flex gap-2 ml-4">
                <button
                  on:click={() => handleTestChannel(channel.id)}
                  class="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-500"
                >
                  Probar
                </button>
                <button
                  on:click={() => handleDeleteChannel(channel.id)}
                  class="px-3 py-1 bg-red-600 text-white text-sm rounded hover:bg-red-500"
                >
                  Eliminar
                </button>
              </div>
            </div>
          </div>
        {/each}

        {#if channels.length === 0 && !loading}
          <p class="text-gray-500 text-center py-8">No hay canales configurados.</p>
        {/if}
      </div>
    </div>
  {:else if activeTab === 'rules'}
    <div class="space-y-4">
      <button
        on:click={() => (showRuleEditor = !showRuleEditor)}
        class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors"
      >
        {showRuleEditor ? 'Cancelar' : 'Nueva Regla'}
      </button>

      {#if showRuleEditor}
        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <RuleEditor
            channels={channels.map((c) => ({ id: c.id, name: c.name }))}
            on:save={handleCreateRule}
            on:cancel={() => (showRuleEditor = false)}
          />
        </div>
      {/if}

      <div class="grid gap-4">
        {#each rules as rule}
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <div class="flex justify-between items-start">
              <div class="flex-1">
                <h3 class="text-lg font-semibold text-gray-300 mb-2">{rule.event_type}</h3>
                <div class="space-y-1 text-sm text-gray-400">
                  {#if rule.severity_filter.length > 0}
                    <p>Severidades: <span class="text-kryon-400">{rule.severity_filter.join(', ')}</span></p>
                  {/if}
                  {#if rule.client_filter}
                    <p>Cliente: <span class="text-kryon-400">{rule.client_filter}</span></p>
                  {/if}
                  <p>
                    Canales: <span class="text-kryon-400"
                      >{rule.channel_ids.length} configurado{rule.channel_ids.length !== 1
                        ? 's'
                        : ''}</span
                    >
                  </p>
                  {#if rule.digest_mode}
                    <p class="text-yellow-500">Modo resumen activado</p>
                  {/if}
                </div>
              </div>
              <button
                on:click={() => handleDeleteRule(rule.id)}
                class="px-3 py-1 bg-red-600 text-white text-sm rounded hover:bg-red-500"
              >
                Eliminar
              </button>
            </div>
          </div>
        {/each}

        {#if rules.length === 0 && !loading}
          <p class="text-gray-500 text-center py-8">No hay reglas configuradas.</p>
        {/if}
      </div>
    </div>
  {:else if activeTab === 'log'}
    <div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
      <table class="w-full">
        <thead class="bg-gray-950">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Fecha</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Canal</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Evento</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Estado</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Error</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {#each logEntries as entry}
            <tr class="hover:bg-gray-800/50">
              <td class="px-4 py-3 text-sm text-gray-300">
                {new Date(entry.timestamp).toLocaleString('es-ES')}
              </td>
              <td class="px-4 py-3 text-sm text-gray-300">{entry.channel_name}</td>
              <td class="px-4 py-3 text-sm text-gray-400">{entry.event_type}</td>
              <td class="px-4 py-3 text-sm">
                <span
                  class="px-2 py-1 rounded text-xs font-medium {entry.status === 'success'
                    ? 'bg-green-900/30 text-green-400'
                    : 'bg-red-900/30 text-red-400'}"
                >
                  {entry.status}
                </span>
              </td>
              <td class="px-4 py-3 text-sm text-red-400">{entry.error_message || '-'}</td>
            </tr>
          {/each}
        </tbody>
      </table>

      {#if logEntries.length === 0 && !loading}
        <p class="text-gray-500 text-center py-8">No hay registros de entrega.</p>
      {/if}
    </div>
  {/if}
</div>
