<script lang="ts">
  import type { UsageStats } from '$lib/api/billing';

  export let limits: UsageStats;

  function getPercentage(current: number, limit: number): number {
    if (limit === 0) return 0;
    return Math.min(100, (current / limit) * 100);
  }

  function getBarColor(percentage: number): string {
    if (percentage >= 90) return 'bg-red-500';
    if (percentage >= 75) return 'bg-orange-500';
    if (percentage >= 50) return 'bg-yellow-500';
    return 'bg-kryon-500';
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  $: scansPercentage = getPercentage(limits.scans_count, limits.scans_limit);
  $: findingsPercentage = getPercentage(limits.findings_count, limits.findings_limit);
  $: storagePercentage = getPercentage(limits.storage_bytes, limits.storage_limit_bytes);
  $: usersPercentage = getPercentage(limits.users_count, limits.users_limit);
</script>

<div class="space-y-6">
  <h3 class="text-lg font-semibold text-gray-300">Uso de Recursos</h3>

  <div class="space-y-4">
    <!-- Scans -->
    <div>
      <div class="flex justify-between items-center mb-2">
        <span class="text-sm text-gray-400">Escaneos (este mes)</span>
        <span class="text-sm font-semibold text-gray-300">
          {limits.scans_count} / {limits.scans_limit === 0 ? '∞' : limits.scans_limit}
        </span>
      </div>
      <div class="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
        <div
          class="{getBarColor(scansPercentage)} h-full rounded-full transition-all duration-500"
          style="width: {scansPercentage}%"
        />
      </div>
      {#if scansPercentage >= 90}
        <p class="text-xs text-red-400 mt-1">Acercándose al límite</p>
      {/if}
    </div>

    <!-- Findings -->
    <div>
      <div class="flex justify-between items-center mb-2">
        <span class="text-sm text-gray-400">Hallazgos Almacenados</span>
        <span class="text-sm font-semibold text-gray-300">
          {limits.findings_count} / {limits.findings_limit === 0 ? '∞' : limits.findings_limit}
        </span>
      </div>
      <div class="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
        <div
          class="{getBarColor(findingsPercentage)} h-full rounded-full transition-all duration-500"
          style="width: {findingsPercentage}%"
        />
      </div>
    </div>

    <!-- Storage -->
    <div>
      <div class="flex justify-between items-center mb-2">
        <span class="text-sm text-gray-400">Almacenamiento</span>
        <span class="text-sm font-semibold text-gray-300">
          {formatBytes(limits.storage_bytes)} / {limits.storage_limit_bytes === 0 ? '∞' : formatBytes(limits.storage_limit_bytes)}
        </span>
      </div>
      <div class="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
        <div
          class="{getBarColor(storagePercentage)} h-full rounded-full transition-all duration-500"
          style="width: {storagePercentage}%"
        />
      </div>
    </div>

    <!-- Users -->
    <div>
      <div class="flex justify-between items-center mb-2">
        <span class="text-sm text-gray-400">Usuarios</span>
        <span class="text-sm font-semibold text-gray-300">
          {limits.users_count} / {limits.users_limit === 0 ? '∞' : limits.users_limit}
        </span>
      </div>
      <div class="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
        <div
          class="{getBarColor(usersPercentage)} h-full rounded-full transition-all duration-500"
          style="width: {usersPercentage}%"
        />
      </div>
    </div>
  </div>

  <div class="mt-4 p-3 bg-gray-950 rounded-lg">
    <p class="text-xs text-gray-500">
      Los límites se renuevan mensualmente. Actualiza tu plan para aumentar capacidades.
    </p>
  </div>
</div>
