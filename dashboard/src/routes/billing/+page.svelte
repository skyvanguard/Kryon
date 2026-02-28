<script lang="ts">
  import { onMount } from 'svelte';
  import {
    validateLicense,
    getUsage,
    getFeatures,
    getLimits,
    type License,
    type UsageStats,
    type Feature,
    type Limits
  } from '$lib/api/billing';
  import LicenseInfo from '$lib/components/billing/LicenseInfo.svelte';
  import UsageMeter from '$lib/components/billing/UsageMeter.svelte';
  import FeatureList from '$lib/components/billing/FeatureList.svelte';

  let license: License | null = null;
  let usage: UsageStats | null = null;
  let features: Feature[] = [];
  let limits: Limits | null = null;
  let loading = false;
  let error = '';

  onMount(() => {
    loadData();
  });

  async function loadData() {
    try {
      loading = true;
      error = '';

      const [licenseData, usageData, featuresData, limitsData] = await Promise.all([
        validateLicense(),
        getUsage(),
        getFeatures(),
        getLimits()
      ]);

      license = licenseData;
      usage = usageData;
      features = featuresData;
      limits = limitsData;
    } catch (e) {
      error = 'Error al cargar información de licencia: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }
</script>

<div class="container mx-auto p-6">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold text-kryon-400">Licencia y Facturación</h1>
  </div>

  {#if error}
    <div class="bg-red-900/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-4">
      {error}
    </div>
  {/if}

  {#if loading}
    <div class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500"></div>
      <p class="text-gray-400 mt-4">Cargando información de licencia...</p>
    </div>
  {:else if license && usage && limits}
    <div class="space-y-6">
      <!-- License Info -->
      <LicenseInfo {license} />

      <!-- Usage Stats -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <UsageMeter limits={usage} />
      </div>

      <!-- Features -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <FeatureList {features} />
      </div>

      <!-- Limits Info -->
      {#if limits}
        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <h3 class="text-lg font-semibold text-gray-300 mb-4">Límites del Plan</h3>
          <div class="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div class="bg-gray-950 rounded p-4">
              <p class="text-sm text-gray-500 mb-1">Escaneos/mes</p>
              <p class="text-2xl font-bold text-gray-300">
                {limits.scans_per_month === 0 ? '∞' : limits.scans_per_month}
              </p>
            </div>
            <div class="bg-gray-950 rounded p-4">
              <p class="text-sm text-gray-500 mb-1">Escaneos concurrentes</p>
              <p class="text-2xl font-bold text-gray-300">
                {limits.concurrent_scans === 0 ? '∞' : limits.concurrent_scans}
              </p>
            </div>
            <div class="bg-gray-950 rounded p-4">
              <p class="text-sm text-gray-500 mb-1">Usuarios máximos</p>
              <p class="text-2xl font-bold text-gray-300">
                {limits.max_users === 0 ? '∞' : limits.max_users}
              </p>
            </div>
            <div class="bg-gray-950 rounded p-4">
              <p class="text-sm text-gray-500 mb-1">Almacenamiento</p>
              <p class="text-2xl font-bold text-gray-300">
                {limits.storage_gb === 0 ? '∞' : `${limits.storage_gb} GB`}
              </p>
            </div>
            <div class="bg-gray-950 rounded p-4">
              <p class="text-sm text-gray-500 mb-1">API calls/día</p>
              <p class="text-2xl font-bold text-gray-300">
                {limits.api_calls_per_day === 0 ? '∞' : limits.api_calls_per_day.toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      {/if}

      <!-- Support Contact -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <h3 class="text-lg font-semibold text-gray-300 mb-2">¿Necesitas más capacidad?</h3>
        <p class="text-gray-400 text-sm mb-4">
          Contacta con nuestro equipo de ventas para actualizar tu plan o extender tu licencia.
        </p>
        <div class="flex gap-4">
          <a
            href="mailto:sales@kryon.io"
            class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors"
          >
            Contactar Ventas
          </a>
          <a
            href="mailto:support@kryon.io"
            class="px-4 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition-colors"
          >
            Soporte Técnico
          </a>
        </div>
      </div>
    </div>
  {/if}
</div>
