<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { importAssets, type AssetImport } from '$lib/api/onboarding';

  const dispatch = createEventDispatcher();

  let fileInput: HTMLInputElement;
  let previewData: AssetImport[] = [];
  let importing = false;

  function handleFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string;

        if (file.name.endsWith('.json')) {
          previewData = JSON.parse(content);
        } else if (file.name.endsWith('.csv')) {
          previewData = parseCSV(content);
        } else {
          alert('Formato no soportado. Usa JSON o CSV.');
        }
      } catch (err) {
        alert('Error al parsear archivo: ' + (err as Error).message);
      }
    };
    reader.readAsText(file);
  }

  function parseCSV(content: string): AssetImport[] {
    const lines = content.split('\n').filter((l) => l.trim());
    const headers = lines[0].split(',').map((h) => h.trim());

    return lines.slice(1).map((line) => {
      const values = line.split(',').map((v) => v.trim());
      const asset: AssetImport = {
        identifier: values[0] || '',
        type: values[1] || 'server',
        criticality: values[2] || 'medium'
      };
      return asset;
    });
  }

  async function handleImport() {
    if (previewData.length === 0) return;

    try {
      importing = true;
      const result = await importAssets(previewData);
      dispatch('imported', result.imported);
    } catch (e) {
      alert('Error al importar activos: ' + (e as Error).message);
    } finally {
      importing = false;
    }
  }
</script>

<div class="space-y-4">
  <div>
    <label class="block text-sm font-medium text-gray-300 mb-2">
      Cargar Archivo de Activos (CSV o JSON)
    </label>
    <input
      bind:this={fileInput}
      type="file"
      accept=".csv,.json"
      on:change={handleFileSelect}
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-kryon-500 file:text-gray-950 hover:file:bg-kryon-400 file:cursor-pointer"
    />
    <p class="text-xs text-gray-500 mt-1">
      CSV: identifier, type, criticality (una fila por activo)
    </p>
  </div>

  {#if previewData.length > 0}
    <div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
      <div class="px-4 py-3 border-b border-gray-700 bg-gray-950">
        <h3 class="text-sm font-semibold text-gray-300">
          Vista Previa ({previewData.length} activos)
        </h3>
      </div>

      <div class="max-h-64 overflow-y-auto">
        <table class="w-full">
          <thead class="bg-gray-950 sticky top-0">
            <tr>
              <th class="px-4 py-2 text-left text-xs font-medium text-gray-400 uppercase"
                >Identificador</th
              >
              <th class="px-4 py-2 text-left text-xs font-medium text-gray-400 uppercase">Tipo</th>
              <th class="px-4 py-2 text-left text-xs font-medium text-gray-400 uppercase"
                >Criticidad</th
              >
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800">
            {#each previewData.slice(0, 10) as asset}
              <tr class="hover:bg-gray-800/50">
                <td class="px-4 py-2 text-sm text-gray-300 font-mono">{asset.identifier}</td>
                <td class="px-4 py-2 text-sm text-gray-400 capitalize">{asset.type}</td>
                <td class="px-4 py-2 text-sm text-gray-400 capitalize">{asset.criticality}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if previewData.length > 10}
          <p class="text-xs text-gray-500 text-center py-2">
            ... y {previewData.length - 10} más
          </p>
        {/if}
      </div>
    </div>

    <button
      type="button"
      on:click={handleImport}
      disabled={importing}
      class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {importing ? 'Importando...' : `Importar ${previewData.length} Activos`}
    </button>
  {/if}
</div>
