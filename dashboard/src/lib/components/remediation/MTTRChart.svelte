<script lang="ts">
  import type { RemediationMetrics } from '$lib/api/remediation';

  export let metrics: RemediationMetrics;
</script>

<div class="grid grid-cols-3 gap-4">
  <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-medium text-gray-400">MTTR (Tiempo Medio de Resolución)</h3>
    </div>
    <p class="text-3xl font-bold text-kryon-400">
      {metrics.mttr_days.toFixed(1)}
      <span class="text-lg text-gray-500">días</span>
    </p>
  </div>

  <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-medium text-gray-400">Cumplimiento SLA</h3>
    </div>
    <p class="text-3xl font-bold {metrics.sla_compliance_pct >= 90 ? 'text-green-400' : metrics.sla_compliance_pct >= 70 ? 'text-yellow-400' : 'text-red-400'}">
      {metrics.sla_compliance_pct.toFixed(1)}
      <span class="text-lg text-gray-500">%</span>
    </p>
  </div>

  <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-medium text-gray-400">Hallazgos Vencidos</h3>
    </div>
    <p class="text-3xl font-bold {metrics.overdue_count === 0 ? 'text-green-400' : 'text-red-400'}">
      {metrics.overdue_count}
    </p>
  </div>
</div>

<div class="mt-4 bg-gray-900 border border-gray-700 rounded-lg p-4">
  <h3 class="text-sm font-medium text-gray-400 mb-3">Distribución por Estado</h3>
  <div class="grid grid-cols-5 gap-2">
    {#each Object.entries(metrics.by_status) as [status, count]}
      <div class="text-center">
        <p class="text-2xl font-bold text-gray-300">{count}</p>
        <p class="text-xs text-gray-500 capitalize">{status.replace('_', ' ')}</p>
      </div>
    {/each}
  </div>
</div>
