<script lang="ts">
  import type { RemediationFinding } from '$lib/api/remediation';
  import SeverityBadge from '$lib/components/common/SeverityBadge.svelte';

  export let findings: RemediationFinding[] = [];
  export let onStatusChange: (findingId: number, newStatus: RemediationFinding['status']) => void;

  const columns: Array<{ status: RemediationFinding['status']; label: string; color: string }> = [
    { status: 'open', label: 'Abierto', color: 'bg-gray-800' },
    { status: 'assigned', label: 'Asignado', color: 'bg-blue-900/30' },
    { status: 'in_progress', label: 'En Progreso', color: 'bg-yellow-900/30' },
    { status: 'remediated', label: 'Remediado', color: 'bg-purple-900/30' },
    { status: 'verified', label: 'Verificado', color: 'bg-green-900/30' }
  ];

  function getFindingsByStatus(status: RemediationFinding['status']) {
    return findings.filter((f) => f.status === status);
  }

  function getSLACountdown(deadline: string | null): { text: string; color: string } {
    if (!deadline) return { text: 'Sin SLA', color: 'text-gray-500' };

    const now = new Date();
    const target = new Date(deadline);
    const diff = target.getTime() - now.getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

    if (days < 0) return { text: `Vencido ${Math.abs(days)}d`, color: 'text-red-500' };
    if (days === 0) return { text: `${hours}h restantes`, color: 'text-orange-500' };
    if (days <= 2) return { text: `${days}d ${hours}h`, color: 'text-yellow-500' };
    return { text: `${days} días`, color: 'text-green-500' };
  }

  function handleDragStart(event: DragEvent, finding: RemediationFinding) {
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('findingId', finding.id.toString());
    }
  }

  function handleDragOver(event: DragEvent) {
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = 'move';
    }
  }

  function handleDrop(event: DragEvent, newStatus: RemediationFinding['status']) {
    event.preventDefault();
    if (event.dataTransfer) {
      const findingId = parseInt(event.dataTransfer.getData('findingId'));
      onStatusChange(findingId, newStatus);
    }
  }
</script>

<div class="grid grid-cols-5 gap-4">
  {#each columns as column}
    <div class="flex flex-col min-h-[500px]">
      <div class="bg-gray-900 border border-gray-700 rounded-t-lg px-4 py-3">
        <h3 class="font-semibold text-gray-300">{column.label}</h3>
        <p class="text-sm text-gray-500">{getFindingsByStatus(column.status).length} hallazgos</p>
      </div>

      <div
        class="flex-1 border-x border-b border-gray-700 rounded-b-lg p-2 space-y-2 overflow-y-auto {column.color}"
        on:dragover={handleDragOver}
        on:drop={(e) => handleDrop(e, column.status)}
      >
        {#each getFindingsByStatus(column.status) as finding}
          <div
            draggable="true"
            on:dragstart={(e) => handleDragStart(e, finding)}
            class="bg-gray-900 border border-gray-700 rounded-lg p-3 cursor-move hover:border-kryon-500 transition-colors"
          >
            <div class="flex justify-between items-start mb-2">
              <h4 class="text-sm font-medium text-gray-300 flex-1 pr-2">{finding.title}</h4>
              <SeverityBadge severity={finding.severity} />
            </div>

            {#if finding.assigned_to}
              <p class="text-xs text-gray-500 mb-1">
                Asignado a: <span class="text-kryon-400">{finding.assigned_to}</span>
              </p>
            {/if}

            <div class="flex justify-between items-center mt-2">
              <span class="text-xs text-gray-500">Prioridad: {finding.priority}</span>
              <span class="text-xs {getSLACountdown(finding.sla_deadline).color}">
                {getSLACountdown(finding.sla_deadline).text}
              </span>
            </div>
          </div>
        {/each}

        {#if getFindingsByStatus(column.status).length === 0}
          <p class="text-gray-600 text-sm text-center py-8">Sin hallazgos</p>
        {/if}
      </div>
    </div>
  {/each}
</div>
