<script lang="ts">
  import type { KillChain } from '$lib/api/attackPaths';
  import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';

  export let chains: KillChain[] = [];
</script>

<div class="space-y-4">
  <h3 class="text-lg font-semibold text-gray-300">Kill Chains Detectadas</h3>

  {#each chains as chain}
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <div class="flex justify-between items-start mb-4">
        <div>
          <h4 class="text-gray-300 font-medium mb-1">Objetivo: {chain.target}</h4>
          <p class="text-sm text-gray-500">
            Factibilidad: <span class="text-kryon-400">{(chain.feasibility * 100).toFixed(0)}%</span>
          </p>
        </div>
        <SeverityBadge severity={chain.severity} />
      </div>

      <div class="relative">
        <div class="flex items-center justify-between">
          {#each chain.steps as step, i}
            <div class="flex-1">
              <div class="flex items-center">
                {#if i > 0}
                  <div class="flex-1 h-0.5 bg-kryon-500 mr-2"></div>
                {/if}

                <div class="relative">
                  <div
                    class="w-10 h-10 rounded-full bg-kryon-500 text-gray-950 flex items-center justify-center font-bold"
                  >
                    {i + 1}
                  </div>

                  {#if i < chain.steps.length - 1}
                    <div class="absolute -right-2 top-1/2 -translate-y-1/2">
                      <svg
                        class="w-4 h-4 text-kryon-500"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fill-rule="evenodd"
                          d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z"
                          clip-rule="evenodd"
                        />
                      </svg>
                    </div>
                  {/if}
                </div>
              </div>

              <div class="mt-3 text-center px-2">
                <p class="text-xs font-semibold text-gray-300 mb-1">{step.phase}</p>
                <p class="text-xs text-gray-400 mb-1">{step.technique}</p>
                <p class="text-xs text-kryon-400">{step.mitre_id}</p>
              </div>
            </div>
          {/each}
        </div>
      </div>

      <div class="mt-4 pt-4 border-t border-gray-800">
        <details class="text-sm">
          <summary class="text-gray-400 cursor-pointer hover:text-gray-300">
            Ver detalles de pasos
          </summary>
          <div class="mt-3 space-y-2">
            {#each chain.steps as step, i}
              <div class="bg-gray-950 rounded p-2">
                <p class="text-gray-300 font-medium mb-1">
                  {i + 1}. {step.technique}
                </p>
                <p class="text-xs text-gray-500">{step.description}</p>
              </div>
            {/each}
          </div>
        </details>
      </div>
    </div>
  {/each}

  {#if chains.length === 0}
    <p class="text-gray-500 text-center py-8">No se detectaron kill chains.</p>
  {/if}
</div>
