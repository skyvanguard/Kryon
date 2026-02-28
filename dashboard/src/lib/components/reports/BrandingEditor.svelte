<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let branding: {
    logo_url: string;
    primary_color: string;
    company_name: string;
    footer_text: string;
  } | null = null;

  const dispatch = createEventDispatcher();

  let logoUrl = branding?.logo_url || '';
  let primaryColor = branding?.primary_color || '#06b6d4';
  let companyName = branding?.company_name || '';
  let footerText = branding?.footer_text || '';

  function handleSubmit() {
    dispatch('save', {
      logo_url: logoUrl,
      primary_color: primaryColor,
      company_name: companyName,
      footer_text: footerText
    });
  }
</script>

<form on:submit|preventDefault={handleSubmit} class="space-y-4">
  <div>
    <label for="companyName" class="block text-sm font-medium text-gray-300 mb-1">
      Nombre de la Empresa
    </label>
    <input
      id="companyName"
      type="text"
      bind:value={companyName}
      required
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="Acme Security Corp"
    />
  </div>

  <div>
    <label for="logoUrl" class="block text-sm font-medium text-gray-300 mb-1">
      URL del Logo
    </label>
    <input
      id="logoUrl"
      type="url"
      bind:value={logoUrl}
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="https://example.com/logo.png"
    />
    {#if logoUrl}
      <div class="mt-2 p-2 bg-gray-950 rounded">
        <img src={logoUrl} alt="Logo preview" class="max-h-16 object-contain" />
      </div>
    {/if}
  </div>

  <div>
    <label for="primaryColor" class="block text-sm font-medium text-gray-300 mb-1">
      Color Principal
    </label>
    <div class="flex gap-2">
      <input
        id="primaryColor"
        type="color"
        bind:value={primaryColor}
        class="w-16 h-10 bg-gray-900 border border-gray-700 rounded cursor-pointer"
      />
      <input
        type="text"
        bind:value={primaryColor}
        class="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500 font-mono"
        placeholder="#06b6d4"
      />
    </div>
  </div>

  <div>
    <label for="footerText" class="block text-sm font-medium text-gray-300 mb-1">
      Texto del Pie de Página
    </label>
    <textarea
      id="footerText"
      bind:value={footerText}
      rows="3"
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder="Este informe es confidencial y solo para uso interno."
    />
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
      Guardar Branding
    </button>
  </div>
</form>
