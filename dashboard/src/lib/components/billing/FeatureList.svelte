<script lang="ts">
  import type { Feature } from '$lib/api/billing';

  export let features: Feature[] = [];

  function getTierBadgeColor(tier: string): string {
    switch (tier) {
      case 'community':
        return 'bg-gray-700 text-gray-300';
      case 'professional':
        return 'bg-blue-900/30 text-blue-400';
      case 'enterprise':
        return 'bg-purple-900/30 text-purple-400';
      case 'military':
        return 'bg-red-900/30 text-red-400';
      default:
        return 'bg-gray-700 text-gray-300';
    }
  }
</script>

<div class="space-y-4">
  <h3 class="text-lg font-semibold text-gray-300">Características Disponibles</h3>

  <div class="grid gap-3">
    {#each features as feature}
      <div
        class="bg-gray-900 border rounded-lg p-4 transition-all {feature.enabled
          ? 'border-kryon-500/30'
          : 'border-gray-700 opacity-60'}"
      >
        <div class="flex items-start justify-between">
          <div class="flex items-start gap-3 flex-1">
            {#if feature.enabled}
              <svg class="w-5 h-5 text-kryon-500 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path
                  fill-rule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                  clip-rule="evenodd"
                />
              </svg>
            {:else}
              <svg class="w-5 h-5 text-gray-600 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path
                  fill-rule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clip-rule="evenodd"
                />
              </svg>
            {/if}

            <div class="flex-1">
              <h4 class="text-gray-300 font-medium mb-1">{feature.name}</h4>
              <p class="text-sm text-gray-500">{feature.description}</p>
            </div>
          </div>

          <span
            class="px-2 py-1 rounded text-xs font-medium {getTierBadgeColor(
              feature.tier_required
            )} uppercase"
          >
            {feature.tier_required}
          </span>
        </div>
      </div>
    {/each}

    {#if features.length === 0}
      <p class="text-gray-500 text-center py-4">No hay características disponibles.</p>
    {/if}
  </div>
</div>
