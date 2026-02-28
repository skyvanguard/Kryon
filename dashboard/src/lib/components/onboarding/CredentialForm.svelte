<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { Credential } from '$lib/api/onboarding';

  const dispatch = createEventDispatcher();

  let credType: Credential['type'] = 'ssh';
  let label = '';
  let dataJson = JSON.stringify({ username: '', private_key: '' }, null, 2);
  let dataError = '';

  const typeTemplates = {
    ssh: { username: '', private_key: '', passphrase: '' },
    api_key: { key: '', secret: '' },
    password: { username: '', password: '' },
    certificate: { cert: '', key: '', ca: '' }
  };

  function handleTypeChange() {
    dataJson = JSON.stringify(typeTemplates[credType], null, 2);
  }

  function validateData() {
    try {
      JSON.parse(dataJson);
      dataError = '';
      return true;
    } catch (e) {
      dataError = 'JSON inválido';
      return false;
    }
  }

  function handleSubmit() {
    if (!validateData()) return;

    const credential: Omit<Credential, 'id' | 'created_at'> = {
      type: credType,
      label,
      data: JSON.parse(dataJson)
    };

    dispatch('save', credential);
  }
</script>

<form on:submit|preventDefault={handleSubmit} class="space-y-4">
  <div>
    <label for="credType" class="block text-sm font-medium text-gray-300 mb-1">
      Tipo de Credencial
    </label>
    <select
      id="credType"
      bind:value={credType}
      on:change={handleTypeChange}
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
    >
      <option value="ssh">SSH (Private Key)</option>
      <option value="api_key">API Key</option>
      <option value="password">Usuario/Contraseña</option>
      <option value="certificate">Certificado</option>
    </select>
  </div>

  <div>
    <label for="label" class="block text-sm font-medium text-gray-300 mb-1">
      Etiqueta Descriptiva
    </label>
    <input
      id="label"
      type="text"
      bind:value={label}
      required
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="SSH Production Server"
    />
  </div>

  <div>
    <label for="data" class="block text-sm font-medium text-gray-300 mb-1">
      Datos de Credencial (JSON)
    </label>
    <textarea
      id="data"
      bind:value={dataJson}
      on:blur={validateData}
      rows="10"
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-kryon-500"
    ></textarea>
    {#if dataError}
      <p class="text-red-500 text-sm mt-1">{dataError}</p>
    {/if}
    <p class="text-xs text-gray-500 mt-1">
      Estos datos se almacenan de forma segura y encriptada.
    </p>
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
      Guardar Credencial
    </button>
  </div>
</form>
