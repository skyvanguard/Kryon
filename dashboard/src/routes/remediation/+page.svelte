<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api/client';
  import {
    getMetrics,
    listOverdue,
    updateFindingStatus,
    assignFinding,
    type RemediationFinding,
    type RemediationMetrics
  } from '$lib/api/remediation';
  import RemediationBoard from '$lib/components/remediation/RemediationBoard.svelte';
  import MTTRChart from '$lib/components/remediation/MTTRChart.svelte';
  import AssignmentModal from '$lib/components/remediation/AssignmentModal.svelte';

  let findings: RemediationFinding[] = [];
  let metrics: RemediationMetrics | null = null;
  let overdueFindings: RemediationFinding[] = [];
  let loading = false;
  let error = '';
  let showAssignModal = false;
  let selectedFinding: RemediationFinding | null = null;

  onMount(() => {
    loadData();
  });

  async function loadData() {
    try {
      loading = true;
      error = '';

      const [metricsData, overdueData, findingsData] = await Promise.all([
        getMetrics(),
        listOverdue(),
        apiFetch<RemediationFinding[]>('/findings?limit=1000')
      ]);

      metrics = metricsData;
      overdueFindings = overdueData;
      findings = findingsData;
    } catch (e) {
      error = 'Error al cargar datos: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function handleStatusChange(findingId: number, newStatus: RemediationFinding['status']) {
    try {
      await updateFindingStatus(findingId, newStatus);
      await loadData();
    } catch (e) {
      error = 'Error al actualizar estado: ' + (e as Error).message;
    }
  }

  function handleAssignClick(finding: RemediationFinding) {
    selectedFinding = finding;
    showAssignModal = true;
  }

  async function handleAssign(event: CustomEvent) {
    if (!selectedFinding) return;

    try {
      await assignFinding(
        selectedFinding.id,
        event.detail.assigned_to,
        event.detail.priority
      );
      showAssignModal = false;
      selectedFinding = null;
      await loadData();
    } catch (e) {
      error = 'Error al asignar: ' + (e as Error).message;
    }
  }
</script>

<div class="container mx-auto p-6">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold text-kryon-400">Remediación</h1>
  </div>

  {#if error}
    <div class="bg-red-900/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-4">
      {error}
    </div>
  {/if}

  {#if overdueFindings.length > 0}
    <div class="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-6">
      <div class="flex items-start">
        <svg
          class="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0"
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
          <h3 class="text-red-300 font-semibold mb-1">
            {overdueFindings.length} hallazgo{overdueFindings.length !== 1 ? 's' : ''} vencido{overdueFindings.length !== 1 ? 's' : ''}
          </h3>
          <p class="text-red-400 text-sm">
            Se han excedido los SLAs. Revisa y actualiza el estado de estos hallazgos.
          </p>
        </div>
      </div>
    </div>
  {/if}

  {#if loading}
    <div class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500"></div>
      <p class="text-gray-400 mt-4">Cargando datos...</p>
    </div>
  {:else if metrics}
    <div class="space-y-6">
      <MTTRChart {metrics} />

      <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <h2 class="text-xl font-bold text-gray-300 mb-4">Tablero de Remediación</h2>
        <RemediationBoard {findings} onStatusChange={handleStatusChange} />
      </div>
    </div>
  {/if}
</div>

{#if showAssignModal && selectedFinding}
  <AssignmentModal
    findingTitle={selectedFinding.title}
    on:assign={handleAssign}
    on:close={() => {
      showAssignModal = false;
      selectedFinding = null;
    }}
  />
{/if}
