<script lang="ts">
  export let currentStep: number;

  const steps = [
    { num: 1, label: 'Información de la Empresa' },
    { num: 2, label: 'Alcance del Análisis' },
    { num: 3, label: 'Importar Activos' },
    { num: 4, label: 'Credenciales' },
    { num: 5, label: 'Revisión y Confirmación' }
  ];

  function getStepStatus(stepNum: number): 'complete' | 'current' | 'upcoming' {
    if (stepNum < currentStep) return 'complete';
    if (stepNum === currentStep) return 'current';
    return 'upcoming';
  }
</script>

<nav aria-label="Progress">
  <ol class="flex items-center justify-between">
    {#each steps as step, i}
      <li class="flex items-center {i < steps.length - 1 ? 'flex-1' : ''}">
        <div class="flex flex-col items-center {i < steps.length - 1 ? 'w-full' : ''}">
          <div class="flex items-center {i < steps.length - 1 ? 'w-full' : ''}">
            <div
              class="relative flex items-center justify-center w-10 h-10 rounded-full {getStepStatus(
                step.num
              ) === 'complete'
                ? 'bg-kryon-500 text-gray-950'
                : getStepStatus(step.num) === 'current'
                  ? 'bg-kryon-500 text-gray-950 ring-4 ring-kryon-500/30'
                  : 'bg-gray-800 text-gray-500'}"
            >
              {#if getStepStatus(step.num) === 'complete'}
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fill-rule="evenodd"
                    d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                    clip-rule="evenodd"
                  />
                </svg>
              {:else}
                <span class="font-semibold">{step.num}</span>
              {/if}
            </div>

            {#if i < steps.length - 1}
              <div
                class="flex-1 h-0.5 mx-2 {getStepStatus(step.num) === 'complete'
                  ? 'bg-kryon-500'
                  : 'bg-gray-800'}"
              />
            {/if}
          </div>

          <span
            class="mt-2 text-xs text-center {getStepStatus(step.num) === 'current'
              ? 'text-kryon-400 font-semibold'
              : getStepStatus(step.num) === 'complete'
                ? 'text-gray-400'
                : 'text-gray-600'}"
          >
            {step.label}
          </span>
        </div>
      </li>
    {/each}
  </ol>
</nav>
