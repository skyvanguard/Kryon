<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getRiskOverview,
    getRiskyAssets,
    getRiskTrend,
    type RiskOverview,
    type RiskyAsset,
    type RiskTrend
  } from '$lib/api/risk';
  import RiskGauge from '$lib/components/risk/RiskGauge.svelte';
  import BusinessImpactChart from '$lib/components/risk/BusinessImpactChart.svelte';
  import RiskyAssetsTable from '$lib/components/risk/RiskyAssetsTable.svelte';

  let overview: RiskOverview | null = null;
  let assets: RiskyAsset[] = [];
  let trend: RiskTrend[] = [];
  let loading = false;
  let error = '';

  onMount(() => {
    loadData();
  });

  async function loadData() {
    try {
      loading = true;
      error = '';

      const [overviewData, assetsData, trendData] = await Promise.all([
        getRiskOverview(),
        getRiskyAssets(undefined, 20),
        getRiskTrend(undefined, 30)
      ]);

      overview = overviewData;
      assets = assetsData;
      trend = trendData;
    } catch (e) {
      error = 'Error al cargar datos de riesgo: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }

  function getTrendIcon(trend: number): string {
    if (trend > 0) return '↑';
    if (trend < 0) return '↓';
    return '→';
  }

  function getTrendColor(trend: number): string {
    if (trend > 0) return 'text-red-500';
    if (trend < 0) return 'text-green-500';
    return 'text-gray-500';
  }
</script>

<div class="container mx-auto p-6">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold text-kryon-400">Análisis de Riesgo</h1>
  </div>

  {#if error}
    <div class="bg-red-900/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-4">
      {error}
    </div>
  {/if}

  {#if loading}
    <div class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500"></div>
      <p class="text-gray-400 mt-4">Cargando análisis de riesgo...</p>
    </div>
  {:else if overview}
    <div class="space-y-6">
      <!-- Risk Overview -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <RiskGauge score={overview.overall_score} />

          {#if overview.trend_30d !== 0}
            <div class="mt-4 text-center">
              <p class="text-sm text-gray-500">Tendencia 30 días</p>
              <p class="text-lg font-semibold {getTrendColor(overview.trend_30d)}">
                {getTrendIcon(overview.trend_30d)}
                {Math.abs(overview.trend_30d).toFixed(1)} puntos
              </p>
            </div>
          {/if}
        </div>

        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <BusinessImpactChart impact={overview.business_impact} />
        </div>
      </div>

      <!-- Risk Level Alert -->
      {#if overview.risk_level === 'critical' || overview.risk_level === 'high'}
        <div class="bg-{overview.risk_level === 'critical' ? 'red' : 'orange'}-900/20 border border-{overview.risk_level === 'critical' ? 'red' : 'orange'}-500 rounded-lg p-4">
          <div class="flex items-start">
            <svg
              class="w-5 h-5 text-{overview.risk_level === 'critical' ? 'red' : 'orange'}-500 mt-0.5 mr-3 flex-shrink-0"
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
              <h3 class="text-{overview.risk_level === 'critical' ? 'red' : 'orange'}-300 font-semibold mb-1">
                Nivel de Riesgo {overview.risk_level === 'critical' ? 'Crítico' : 'Alto'}
              </h3>
              <p class="text-{overview.risk_level === 'critical' ? 'red' : 'orange'}-400 text-sm">
                Se requiere atención inmediata. Revisa los activos de mayor riesgo y prioriza la remediación.
              </p>
            </div>
          </div>
        </div>
      {/if}

      <!-- Risky Assets Table -->
      <RiskyAssetsTable {assets} />
    </div>
  {/if}
</div>
