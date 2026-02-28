<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { NotificationRule } from '$lib/api/notifications';

  export let channels: Array<{ id: number; name: string }> = [];

  const dispatch = createEventDispatcher();

  let eventType = 'scan.completed';
  let severityFilter: string[] = [];
  let clientFilter = '';
  let channelIds: number[] = [];
  let digestMode = false;

  const eventTypes = [
    'scan.completed',
    'scan.failed',
    'finding.new',
    'finding.critical',
    'engagement.started',
    'engagement.completed',
    'retest.completed'
  ];

  const severities = ['critical', 'high', 'medium', 'low', 'info'];

  function toggleSeverity(severity: string) {
    if (severityFilter.includes(severity)) {
      severityFilter = severityFilter.filter((s) => s !== severity);
    } else {
      severityFilter = [...severityFilter, severity];
    }
  }

  function toggleChannel(id: number) {
    if (channelIds.includes(id)) {
      channelIds = channelIds.filter((cid) => cid !== id);
    } else {
      channelIds = [...channelIds, id];
    }
  }

  function handleSubmit() {
    const data: Omit<NotificationRule, 'id' | 'created_at'> = {
      event_type: eventType,
      severity_filter: severityFilter,
      client_filter: clientFilter || null,
      channel_ids: channelIds,
      digest_mode: digestMode
    };

    dispatch('save', data);
  }
</script>

<form on:submit|preventDefault={handleSubmit} class="space-y-4">
  <div>
    <label for="eventType" class="block text-sm font-medium text-gray-300 mb-1">
      Tipo de Evento
    </label>
    <select
      id="eventType"
      bind:value={eventType}
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
    >
      {#each eventTypes as type}
        <option value={type}>{type}</option>
      {/each}
    </select>
  </div>

  <div>
    <label class="block text-sm font-medium text-gray-300 mb-2">
      Severidades (opcional)
    </label>
    <div class="flex flex-wrap gap-2">
      {#each severities as severity}
        <button
          type="button"
          on:click={() => toggleSeverity(severity)}
          class="px-3 py-1 rounded text-sm font-medium transition-colors {severityFilter.includes(
            severity
          )
            ? 'bg-kryon-500 text-gray-950'
            : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}"
        >
          {severity}
        </button>
      {/each}
    </div>
  </div>

  <div>
    <label for="clientFilter" class="block text-sm font-medium text-gray-300 mb-1">
      Filtro de Cliente (opcional)
    </label>
    <input
      id="clientFilter"
      type="text"
      bind:value={clientFilter}
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="client_id o deja vacío para todos"
    />
  </div>

  <div>
    <label class="block text-sm font-medium text-gray-300 mb-2">
      Canales de Notificación
    </label>
    {#if channels.length === 0}
      <p class="text-gray-500 text-sm">No hay canales disponibles. Crea uno primero.</p>
    {:else}
      <div class="space-y-2 max-h-40 overflow-y-auto border border-gray-700 rounded p-2">
        {#each channels as channel}
          <label class="flex items-center gap-2 cursor-pointer hover:bg-gray-800 p-2 rounded">
            <input
              type="checkbox"
              checked={channelIds.includes(channel.id)}
              on:change={() => toggleChannel(channel.id)}
              class="w-4 h-4 bg-gray-900 border-gray-700 rounded focus:ring-2 focus:ring-kryon-500"
            />
            <span class="text-gray-300 text-sm">{channel.name}</span>
          </label>
        {/each}
      </div>
    {/if}
  </div>

  <div class="flex items-center">
    <input
      id="digestMode"
      type="checkbox"
      bind:checked={digestMode}
      class="w-4 h-4 bg-gray-900 border-gray-700 rounded focus:ring-2 focus:ring-kryon-500"
    />
    <label for="digestMode" class="ml-2 text-sm text-gray-300">
      Modo resumen (agrupar notificaciones)
    </label>
  </div>

  <div class="flex justify-end gap-3 pt-4">
    <button
      type="button"
      on:click={() => dispatch('cancel')}
      class="px-4 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition-colors"
    >
      Cancelar
    </button>
    <button
      type="submit"
      disabled={channelIds.length === 0}
      class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
    >
      Crear Regla
    </button>
  </div>
</form>
