<script lang="ts">
  import type { RiskyAsset } from '$lib/api/risk';
  import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';

  export let assets: RiskyAsset[] = [];

  function getRiskColor(score: number): string {
    if (score >= 80) return 'text-red-500';
    if (score >= 60) return 'text-orange-500';
    if (score >= 40) return 'text-yellow-500';
    return 'text-green-500';
  }

  function getCriticalityBadgeColor(criticality: string): string {
    switch (criticality) {
      case 'critical': return 'bg-red-900/30 text-red-400';
      case 'high': return 'bg-orange-900/30 text-orange-400';
      case 'medium': return 'bg-yellow-900/30 text-yellow-400';
      default: return 'bg-green-900/30 text-green-400';
    }
  }
</script>

<div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
  <div class="px-6 py-4 border-b border-gray-700">
    <h3 class="text-lg font-semibold text-gray-300">Activos de Mayor Riesgo</h3>
    <p class="text-sm text-gray-500 mt-1">Top {assets.length} activos ordenados por puntuación de riesgo</p>
  </div>

  <div class="overflow-x-auto">
    <table class="w-full">
      <thead class="bg-gray-950">
        <tr>
          <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Activo</th>
          <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Tipo</th>
          <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Criticidad</th>
          <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Exposición</th>
          <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Riesgo</th>
          <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Hallazgos</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-800">
        {#each assets as asset}
          <tr class="hover:bg-gray-800/50 transition-colors">
            <td class="px-4 py-3 text-sm font-medium text-gray-300">
              {asset.identifier}
            </td>
            <td class="px-4 py-3 text-sm text-gray-400 capitalize">
              {asset.asset_type}
            </td>
            <td class="px-4 py-3 text-sm">
              <span class="px-2 py-1 rounded text-xs font-medium {getCriticalityBadgeColor(asset.criticality)}">
                {asset.criticality}
              </span>
            </td>
            <td class="px-4 py-3 text-sm">
              <div class="flex items-center gap-2">
                <div class="flex-1 bg-gray-800 rounded-full h-2 w-24">
                  <div
                    class="bg-kryon-500 h-full rounded-full transition-all"
                    style="width: {asset.exposure_score}%"
                  ></div>
                </div>
                <span class="text-gray-400 text-xs">{asset.exposure_score}%</span>
              </div>
            </td>
            <td class="px-4 py-3 text-sm">
              <span class="font-semibold {getRiskColor(asset.risk_score)}">
                {asset.risk_score}
              </span>
            </td>
            <td class="px-4 py-3 text-sm">
              <div class="flex items-center gap-2">
                <span class="text-gray-400">{asset.findings_count}</span>
                {#if asset.critical_findings > 0}
                  <span class="px-2 py-0.5 bg-red-900/30 text-red-400 rounded text-xs font-medium">
                    {asset.critical_findings} críticos
                  </span>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

    {#if assets.length === 0}
      <div class="text-center py-12">
        <p class="text-gray-500">No hay datos de activos disponibles.</p>
      </div>
    {/if}
  </div>
</div>
