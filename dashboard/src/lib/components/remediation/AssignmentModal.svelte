<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let findingTitle = '';

  const dispatch = createEventDispatcher();

  let assignedTo = '';
  let priority: 'critical' | 'high' | 'medium' | 'low' = 'medium';

  function handleSubmit() {
    if (!assignedTo.trim()) return;
    dispatch('assign', { assigned_to: assignedTo, priority });
  }

  function handleClose() {
    dispatch('close');
  }
</script>

<div class="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
  <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-md w-full mx-4">
    <h2 class="text-xl font-bold text-gray-300 mb-4">Asignar Hallazgo</h2>

    <p class="text-sm text-gray-400 mb-4">
      {findingTitle}
    </p>

    <form on:submit|preventDefault={handleSubmit} class="space-y-4">
      <div>
        <label for="assignedTo" class="block text-sm font-medium text-gray-300 mb-1">
          Asignar a (usuario)
        </label>
        <input
          id="assignedTo"
          type="text"
          bind:value={assignedTo}
          required
          class="w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
          placeholder="nombre.usuario"
        />
      </div>

      <div>
        <label for="priority" class="block text-sm font-medium text-gray-300 mb-1">
          Prioridad
        </label>
        <select
          id="priority"
          bind:value={priority}
          class="w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
        >
          <option value="critical">Crítica</option>
          <option value="high">Alta</option>
          <option value="medium">Media</option>
          <option value="low">Baja</option>
        </select>
      </div>

      <div class="flex justify-end gap-3 pt-4">
        <button
          type="button"
          on:click={handleClose}
          class="px-4 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition-colors"
        >
          Cancelar
        </button>
        <button
          type="submit"
          class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors"
        >
          Asignar
        </button>
      </div>
    </form>
  </div>
</div>
