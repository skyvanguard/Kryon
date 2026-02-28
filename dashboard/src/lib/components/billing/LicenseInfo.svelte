<script lang="ts">
  import type { License } from '$lib/api/billing';

  export let license: License;

  function getTierColor(tier: string): string {
    switch (tier) {
      case 'military':
        return 'bg-red-900/30 text-red-400 border-red-500';
      case 'enterprise':
        return 'bg-purple-900/30 text-purple-400 border-purple-500';
      case 'professional':
        return 'bg-blue-900/30 text-blue-400 border-blue-500';
      case 'community':
        return 'bg-gray-800 text-gray-300 border-gray-600';
      default:
        return 'bg-gray-800 text-gray-300 border-gray-600';
    }
  }

  function getTierIcon(tier: string): string {
    switch (tier) {
      case 'military':
        return '🎖️';
      case 'enterprise':
        return '🏢';
      case 'professional':
        return '💼';
      case 'community':
        return '🌐';
      default:
        return '📦';
    }
  }

  function formatDate(dateString: string | null): string {
    if (!dateString) return 'Ilimitado';
    const date = new Date(dateString);
    return date.toLocaleDateString('es-ES', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  function getDaysUntilExpiry(dateString: string | null): number | null {
    if (!dateString) return null;
    const expiry = new Date(dateString);
    const now = new Date();
    const diff = expiry.getTime() - now.getTime();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  $: daysLeft = getDaysUntilExpiry(license.valid_until);
  $: isExpiringSoon = daysLeft !== null && daysLeft <= 30;
</script>

<div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
  <div class="px-6 py-4 border-b border-gray-700">
    <h3 class="text-lg font-semibold text-gray-300">Información de Licencia</h3>
  </div>

  <div class="p-6">
    <div class="flex items-start gap-4 mb-6">
      <div class="text-4xl">{getTierIcon(license.tier)}</div>
      <div class="flex-1">
        <div
          class="inline-block px-4 py-2 rounded-lg border-2 {getTierColor(
            license.tier
          )} font-semibold text-lg mb-2 uppercase"
        >
          {license.tier}
        </div>
        <div class="space-y-1">
          <p class="text-sm text-gray-400">
            Estado:
            <span class="{license.active ? 'text-green-400' : 'text-red-400'} font-medium">
              {license.active ? 'Activa' : 'Inactiva'}
            </span>
          </p>
          <p class="text-sm text-gray-400">
            Vencimiento: <span class="text-gray-300">{formatDate(license.valid_until)}</span>
          </p>
          {#if daysLeft !== null}
            <p class="text-sm {isExpiringSoon ? 'text-orange-400' : 'text-gray-400'}">
              {daysLeft > 0 ? `${daysLeft} días restantes` : 'Expirada'}
            </p>
          {/if}
        </div>
      </div>
    </div>

    {#if isExpiringSoon && daysLeft && daysLeft > 0}
      <div class="bg-orange-900/20 border border-orange-500 rounded-lg p-4 mb-4">
        <div class="flex items-start">
          <svg
            class="w-5 h-5 text-orange-500 mt-0.5 mr-3 flex-shrink-0"
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path
              fill-rule="evenodd"
              d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
              clip-rule="evenodd"
            />
          </svg>
          <div>
            <h4 class="text-orange-300 font-semibold mb-1">Licencia por vencer</h4>
            <p class="text-orange-400 text-sm">
              Tu licencia expira en {daysLeft} días. Contacta con soporte para renovar.
            </p>
          </div>
        </div>
      </div>
    {/if}

    <div>
      <h4 class="text-sm font-medium text-gray-400 mb-3">Características Incluidas</h4>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
        {#each license.features as feature}
          <div class="flex items-center gap-2 text-sm text-gray-300">
            <svg class="w-4 h-4 text-kryon-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path
                fill-rule="evenodd"
                d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                clip-rule="evenodd"
              />
            </svg>
            <span>{feature}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>
