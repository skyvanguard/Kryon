<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { NotificationChannel } from '$lib/api/notifications';

  export let channel: Partial<NotificationChannel> | null = null;

  const dispatch = createEventDispatcher();

  let name = channel?.name || '';
  let channelType: NotificationChannel['channel_type'] = channel?.channel_type || 'email';
  let configJson = JSON.stringify(channel?.config || {}, null, 2);
  let enabled = channel?.enabled ?? true;
  let configError = '';

  function validateConfig() {
    try {
      JSON.parse(configJson);
      configError = '';
      return true;
    } catch (e) {
      configError = 'JSON inválido';
      return false;
    }
  }

  function handleSubmit() {
    if (!validateConfig()) return;

    const data: Omit<NotificationChannel, 'id' | 'created_at'> = {
      name,
      channel_type: channelType,
      config: JSON.parse(configJson),
      enabled
    };

    dispatch('save', data);
  }
</script>

<form on:submit|preventDefault={handleSubmit} class="space-y-4">
  <div>
    <label for="name" class="block text-sm font-medium text-gray-300 mb-1">
      Nombre del Canal
    </label>
    <input
      id="name"
      type="text"
      bind:value={name}
      required
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="Mi Canal de Slack"
    />
  </div>

  <div>
    <label for="channelType" class="block text-sm font-medium text-gray-300 mb-1">
      Tipo de Canal
    </label>
    <select
      id="channelType"
      bind:value={channelType}
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
    >
      <option value="email">Email</option>
      <option value="slack">Slack</option>
      <option value="teams">Microsoft Teams</option>
      <option value="pagerduty">PagerDuty</option>
      <option value="webhook">Webhook</option>
    </select>
  </div>

  <div>
    <label for="config" class="block text-sm font-medium text-gray-300 mb-1">
      Configuración (JSON)
    </label>
    <textarea
      id="config"
      bind:value={configJson}
      on:blur={validateConfig}
      rows="8"
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="{`{\n  \"webhook_url\": \"https://...\"\n}`}"
    ></textarea>
    {#if configError}
      <p class="text-red-500 text-sm mt-1">{configError}</p>
    {/if}
  </div>

  <div class="flex items-center">
    <input
      id="enabled"
      type="checkbox"
      bind:checked={enabled}
      class="w-4 h-4 bg-gray-900 border-gray-700 rounded focus:ring-2 focus:ring-kryon-500"
    />
    <label for="enabled" class="ml-2 text-sm text-gray-300">
      Canal habilitado
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
      class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors"
    >
      {channel ? 'Actualizar' : 'Crear'} Canal
    </button>
  </div>
</form>
