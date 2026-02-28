<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    startOnboarding,
    updateStep,
    completeOnboarding,
    saveCredential,
    listCredentials,
    deleteCredential,
    type OnboardingSession,
    type Credential
  } from '$lib/api/onboarding';
  import StepIndicator from '$lib/components/onboarding/StepIndicator.svelte';
  import ScopeValidator from '$lib/components/onboarding/ScopeValidator.svelte';
  import AssetImporter from '$lib/components/onboarding/AssetImporter.svelte';
  import CredentialForm from '$lib/components/onboarding/CredentialForm.svelte';

  let session: OnboardingSession | null = null;
  let currentStep = 1;
  let loading = false;
  let error = '';

  // Step 1: Company Info
  let companyName = '';
  let companyIndustry = '';
  let contactEmail = '';

  // Step 2: Scope
  let validatedTargets: string[] = [];

  // Step 3: Assets
  let importedAssets = 0;

  // Step 4: Credentials
  let credentials: Credential[] = [];
  let showCredentialForm = false;

  onMount(async () => {
    try {
      session = await startOnboarding();
      currentStep = session.current_step;

      if (session.data) {
        companyName = session.data.company_name as string || '';
        companyIndustry = session.data.company_industry as string || '';
        contactEmail = session.data.contact_email as string || '';
        validatedTargets = session.data.validated_targets as string[] || [];
        importedAssets = session.data.imported_assets as number || 0;
      }

      if (currentStep === 4) {
        await loadCredentials();
      }
    } catch (e) {
      error = 'Error al iniciar onboarding: ' + (e as Error).message;
    }
  });

  async function loadCredentials() {
    try {
      credentials = await listCredentials();
    } catch (e) {
      error = 'Error al cargar credenciales: ' + (e as Error).message;
    }
  }

  async function handleNext() {
    if (!session) return;

    try {
      loading = true;
      error = '';

      let stepData: Record<string, unknown> = {};

      switch (currentStep) {
        case 1:
          if (!companyName || !companyIndustry || !contactEmail) {
            error = 'Completa todos los campos';
            return;
          }
          stepData = { company_name: companyName, company_industry: companyIndustry, contact_email: contactEmail };
          break;
        case 2:
          if (validatedTargets.length === 0) {
            error = 'Valida al menos un objetivo';
            return;
          }
          stepData = { validated_targets: validatedTargets };
          break;
        case 3:
          stepData = { imported_assets: importedAssets };
          break;
        case 4:
          stepData = { credentials_count: credentials.length };
          break;
      }

      session = await updateStep(session.id, currentStep, stepData);
      currentStep++;

      if (currentStep === 4) {
        await loadCredentials();
      }
    } catch (e) {
      error = 'Error al avanzar: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function handleBack() {
    if (currentStep > 1) {
      currentStep--;
    }
  }

  async function handleComplete() {
    if (!session) return;

    try {
      loading = true;
      await completeOnboarding(session.id);
      goto('/dashboard');
    } catch (e) {
      error = 'Error al completar onboarding: ' + (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function handleSaveCredential(event: CustomEvent) {
    try {
      await saveCredential(event.detail);
      showCredentialForm = false;
      await loadCredentials();
    } catch (e) {
      error = 'Error al guardar credencial: ' + (e as Error).message;
    }
  }

  async function handleDeleteCredential(id: number) {
    if (!confirm('¿Eliminar esta credencial?')) return;

    try {
      await deleteCredential(id);
      await loadCredentials();
    } catch (e) {
      error = 'Error al eliminar credencial: ' + (e as Error).message;
    }
  }

  function handleScopeConfirm(event: CustomEvent) {
    validatedTargets = event.detail;
  }

  function handleAssetsImported(event: CustomEvent) {
    importedAssets = event.detail;
  }
</script>

<div class="min-h-screen bg-gray-950 py-12">
  <div class="container mx-auto px-6 max-w-4xl">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold text-kryon-400 mb-2">Configuración Inicial de Kryon</h1>
      <p class="text-gray-400">
        Completa estos pasos para comenzar a utilizar la plataforma.
      </p>
    </div>

    {#if session}
      <div class="mb-12">
        <StepIndicator {currentStep} />
      </div>

      {#if error}
        <div class="bg-red-900/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-6">
          {error}
        </div>
      {/if}

      <div class="bg-gray-900 border border-gray-700 rounded-lg p-8">
        {#if currentStep === 1}
          <h2 class="text-xl font-bold text-gray-300 mb-6">Información de la Empresa</h2>
          <div class="space-y-4">
            <div>
              <label for="companyName" class="block text-sm font-medium text-gray-300 mb-1">
                Nombre de la Empresa
              </label>
              <input
                id="companyName"
                type="text"
                bind:value={companyName}
                class="w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
                placeholder="Acme Corporation"
              />
            </div>

            <div>
              <label for="companyIndustry" class="block text-sm font-medium text-gray-300 mb-1">
                Industria
              </label>
              <select
                id="companyIndustry"
                bind:value={companyIndustry}
                class="w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
              >
                <option value="">Selecciona una industria</option>
                <option value="fintech">Fintech</option>
                <option value="healthcare">Salud</option>
                <option value="ecommerce">E-commerce</option>
                <option value="technology">Tecnología</option>
                <option value="government">Gobierno</option>
                <option value="other">Otra</option>
              </select>
            </div>

            <div>
              <label for="contactEmail" class="block text-sm font-medium text-gray-300 mb-1">
                Email de Contacto
              </label>
              <input
                id="contactEmail"
                type="email"
                bind:value={contactEmail}
                class="w-full px-3 py-2 bg-gray-950 border border-gray-700 rounded text-gray-300 focus:outline-none focus:ring-2 focus:ring-kryon-500"
                placeholder="security@acme.com"
              />
            </div>
          </div>
        {:else if currentStep === 2}
          <h2 class="text-xl font-bold text-gray-300 mb-6">Alcance del Análisis</h2>
          <ScopeValidator on:confirm={handleScopeConfirm} />
          {#if validatedTargets.length > 0}
            <div class="mt-4 p-3 bg-green-900/20 border border-green-500 rounded">
              <p class="text-green-300 text-sm">
                {validatedTargets.length} objetivo{validatedTargets.length !== 1 ? 's' : ''} validado{validatedTargets.length !== 1 ? 's' : ''}
              </p>
            </div>
          {/if}
        {:else if currentStep === 3}
          <h2 class="text-xl font-bold text-gray-300 mb-6">Importar Activos</h2>
          <p class="text-gray-400 text-sm mb-4">
            Importa tus activos existentes desde un archivo CSV o JSON.
          </p>
          <AssetImporter on:imported={handleAssetsImported} />
          {#if importedAssets > 0}
            <div class="mt-4 p-3 bg-green-900/20 border border-green-500 rounded">
              <p class="text-green-300 text-sm">
                {importedAssets} activo{importedAssets !== 1 ? 's' : ''} importado{importedAssets !== 1 ? 's' : ''}
              </p>
            </div>
          {/if}
        {:else if currentStep === 4}
          <h2 class="text-xl font-bold text-gray-300 mb-6">Credenciales de Acceso</h2>
          <p class="text-gray-400 text-sm mb-4">
            Configura credenciales para análisis autenticados (opcional pero recomendado).
          </p>

          {#if !showCredentialForm}
            <button
              on:click={() => (showCredentialForm = true)}
              class="px-4 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors mb-4"
            >
              Nueva Credencial
            </button>
          {/if}

          {#if showCredentialForm}
            <div class="mb-4">
              <CredentialForm
                on:save={handleSaveCredential}
                on:cancel={() => (showCredentialForm = false)}
              />
            </div>
          {/if}

          <div class="space-y-2">
            {#each credentials as cred}
              <div class="bg-gray-950 border border-gray-700 rounded p-3 flex justify-between items-center">
                <div>
                  <p class="text-gray-300 font-medium">{cred.label}</p>
                  <p class="text-sm text-gray-500">Tipo: {cred.type}</p>
                </div>
                <button
                  on:click={() => handleDeleteCredential(cred.id)}
                  class="px-3 py-1 bg-red-600 text-white text-sm rounded hover:bg-red-500"
                >
                  Eliminar
                </button>
              </div>
            {/each}
          </div>
        {:else if currentStep === 5}
          <h2 class="text-xl font-bold text-gray-300 mb-6">Revisión y Confirmación</h2>
          <div class="space-y-4">
            <div class="bg-gray-950 rounded p-4">
              <h3 class="text-kryon-400 font-semibold mb-2">Empresa</h3>
              <p class="text-gray-300">{companyName}</p>
              <p class="text-sm text-gray-500">{companyIndustry} - {contactEmail}</p>
            </div>

            <div class="bg-gray-950 rounded p-4">
              <h3 class="text-kryon-400 font-semibold mb-2">Alcance</h3>
              <p class="text-gray-300">{validatedTargets.length} objetivo{validatedTargets.length !== 1 ? 's' : ''} validado{validatedTargets.length !== 1 ? 's' : ''}</p>
            </div>

            <div class="bg-gray-950 rounded p-4">
              <h3 class="text-kryon-400 font-semibold mb-2">Activos</h3>
              <p class="text-gray-300">{importedAssets} activo{importedAssets !== 1 ? 's' : ''} importado{importedAssets !== 1 ? 's' : ''}</p>
            </div>

            <div class="bg-gray-950 rounded p-4">
              <h3 class="text-kryon-400 font-semibold mb-2">Credenciales</h3>
              <p class="text-gray-300">{credentials.length} credencial{credentials.length !== 1 ? 'es' : ''} configurada{credentials.length !== 1 ? 's' : ''}</p>
            </div>
          </div>
        {/if}

        <div class="flex justify-between mt-8 pt-6 border-t border-gray-700">
          {#if currentStep > 1}
            <button
              on:click={handleBack}
              disabled={loading}
              class="px-6 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition-colors disabled:opacity-50"
            >
              Anterior
            </button>
          {:else}
            <div></div>
          {/if}

          {#if currentStep < 5}
            <button
              on:click={handleNext}
              disabled={loading}
              class="px-6 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors disabled:opacity-50"
            >
              {loading ? 'Guardando...' : 'Siguiente'}
            </button>
          {:else}
            <button
              on:click={handleComplete}
              disabled={loading}
              class="px-6 py-2 bg-kryon-500 text-gray-950 font-semibold rounded hover:bg-kryon-400 transition-colors disabled:opacity-50"
            >
              {loading ? 'Completando...' : 'Completar Configuración'}
            </button>
          {/if}
        </div>
      </div>
    {:else}
      <div class="text-center py-12">
        <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-kryon-500"></div>
        <p class="text-gray-400 mt-4">Iniciando configuración...</p>
      </div>
    {/if}
  </div>
</div>
