<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { validateScope, type ScopeValidation } from '$lib/api/onboarding';
  import { toast } from '$lib/stores/toast';

  const dispatch = createEventDispatcher();

  let targetsText = '';
  let validating = false;
  let results: ScopeValidation[] = [];

  async function handleValidate() {
    const targets = targetsText
      .split('\n')
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (targets.length === 0) return;

    try {
      validating = true;
      results = await validateScope(targets);
    } catch (e) {
      toast.error('Error al validar alcance: ' + (e as Error).message);
    } finally {
      validating = false;
    }
  }

  function handleConfirm() {
    const validTargets = results.filter((r) => r.reachable).map((r) => r.target);
    dispatch('confirm', validTargets);
  }
</script>

<div class="space-y-4">
  <div>
    <label for="targets" class="block text-sm font-medium text-gray-300 mb-1">
      Objetivos de Análisis (uno por línea)
    </label>
    <textarea
      id="targets"
      bind:value={targetsText}
      rows="8"
      class="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-300 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-kryon-500"
      placeholder={'192.168.1.0/24\nexample.com\n10.0.0.1'}
    />
  </div>

  <button
    type="button"
    on:click={handleValidate}
    disabled={validating || !targetsText.trim()}
    class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
  >
    {validating ? 'Validando...' : 'Validar Alcance'}
  </button>

  {#if results.length > 0}
    <div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
      <table class="w-full">
        <thead class="bg-gray-950">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Objetivo</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Estado</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase"
              >Tiempo (ms)</th
            >
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Error</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {#each results as result}
            <tr class="hover:bg-gray-800/50">
              <td class="px-4 py-3 text-sm text-gray-300 font-mono">{result.target}</td>
              <td class="px-4 py-3 text-sm">
                {#if result.reachable}
                  <span class="px-2 py-1 bg-green-900/30 text-green-400 rounded text-xs font-medium"
                    >Alcanzable</span
                  >
                {:else}
                  <span class="px-2 py-1 bg-red-900/30 text-red-400 rounded text-xs font-medium"
                    >No alcanzable</span
                  >
                {/if}
              </td>
              <td class="px-4 py-3 text-sm text-gray-400">
                {result.response_time_ms !== null ? result.response_time_ms : '-'}
              </td>
              <td class="px-4 py-3 text-sm text-red-400">{result.error || '-'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if results.some((r) => r.reachable)}
      <button
        type="button"
        on:click={handleConfirm}
        class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors"
      >
        Confirmar {results.filter((r) => r.reachable).length} Objetivos Válidos
      </button>
    {/if}
  {/if}
</div>
