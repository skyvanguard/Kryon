# Resumen de Archivos de Deployment Kubernetes

Fecha: 2026-02-28
Componente: Manifiestos de Kubernetes y Helm Chart para KRYON Security Platform

## Archivos Creados

### Manifiestos Kubernetes (`k8s/`)

1. **namespace.yaml** - Define el namespace `kryon-system`
2. **configmap.yaml** - ConfigMap con variables de entorno (debug, log format, rate limit)
3. **secret.yaml.example** - Template de secrets (JWT, API keys) con valores placeholder en base64
4. **deployment-server.yaml** - Deployment del servidor (2 réplicas, health probes, resource limits)
5. **service-server.yaml** - ClusterIP service para el servidor (puerto 8700)
6. **ingress.yaml** - Ingress con nginx, TLS, ruta /api→server
7. **hpa.yaml** - HorizontalPodAutoscaler (min=2, max=10, CPU 70%, Memory 80%)
8. **pvc.yaml** - PersistentVolumeClaim de 10Gi para datos persistentes
9. **README.md** - Documentación completa de deployment con Kubernetes
10. **.gitignore** - Ignora secret.yaml y archivos de configuración sensibles

### Helm Chart (`helm/kryon/`)

13. **Chart.yaml** - Metadata del chart (nombre, versión 1.0.0, descripción)
14. **values.yaml** - Valores por defecto (réplicas, imágenes, recursos, ingress, secrets)
15. **templates/deployment.yaml** - Deployment templado para server
16. **templates/service.yaml** - Service templado
17. **templates/ingress.yaml** - Ingress templado con condicional
18. **templates/hpa.yaml** - HPA templado con condicional
19. **templates/configmap.yaml** - ConfigMap templado
20. **templates/secret.yaml** - Secret templado con generación automática
21. **templates/pvc.yaml** - PVC templado con condicional de persistencia
22. **templates/serviceaccount.yaml** - ServiceAccount templado
23. **templates/namespace.yaml** - Namespace templado
24. **templates/_helpers.tpl** - Helper templates (labels, nombres, selectors)
25. **templates/NOTES.txt** - Notas post-instalación con instrucciones de acceso
26. **.helmignore** - Excluye archivos innecesarios del chart package
27. **README.md** (helm/) - Documentación completa del Helm chart

### Scripts de Deployment (`scripts/`)

28. **deploy-k8s.sh** - Script bash para deployment automático con manifiestos K8s
29. **deploy-helm.sh** - Script bash para deployment automático con Helm

### Documentación

30. **DEPLOYMENT.md** - Guía maestra de deployment (K8s, Helm, Docker, desarrollo local)
31. **K8S_DEPLOYMENT_SUMMARY.md** - Este archivo

## Características Principales

### Manifiestos Kubernetes

- **Namespace aislado:** `kryon-system`
- **ConfigMap:** Variables de configuración centralizadas
- **Secrets:** Template con valores base64 (NUNCA commitear el real)
- **Server Deployment:**
  - 2 réplicas por defecto
  - Resource requests: 256Mi/500m
  - Resource limits: 512Mi/1000m
  - ReadinessProbe: GET /api/v1/health (puerto 8700)
  - LivenessProbe: GET /api/v1/health (puerto 8700)
  - Volume mount: /data (PVC)
- **Services:**
  - ClusterIP para comunicación interna
  - Server: puerto 8700
- **Ingress:**
  - nginx-ingress-controller
  - TLS habilitado
  - Ruta: /api → server
  - Soporte SSE (Server-Sent Events)
  - cert-manager annotations
- **HPA:**
  - Escalado automático del servidor
  - Min: 2, Max: 10 réplicas
  - Targets: CPU 70%, Memory 80%
  - Políticas de scale-up/down optimizadas
- **PVC:**
  - 10Gi storage
  - ReadWriteMany access mode
  - Para SQLite, ChromaDB, archivos

### Helm Chart

- **Parametrizable:** Todos los valores en `values.yaml`
- **Environments:** Dev, staging, prod con diferentes defaults
- **Auto-generación:** Secrets aleatorios si no se proveen
- **Condicionales:**
  - Ingress habilitado/deshabilitado
  - Autoscaling habilitado/deshabilitado
  - Persistencia habilitada/deshabilitada
- **Templates:**
  - Labels consistentes con helpers
  - Checksums para forzar rolling updates
  - Security contexts configurables
  - Node selectors y affinity
- **NOTES.txt:** Instrucciones dinámicas post-instalación

### Scripts de Deployment

- **deploy-k8s.sh:**
  - Valida manifiestos antes de aplicar
  - Genera secrets automáticamente si no existen
  - Despliega en orden correcto
  - Espera a que deployments estén ready
  - Muestra instrucciones de acceso
  - Soporta ambientes: dev, staging, prod
- **deploy-helm.sh:**
  - Lint del chart
  - Dry-run antes de deployment
  - Genera values files por ambiente
  - Soporte para install y upgrade
  - Confirmación interactiva (excepto dev)
  - Muestra notas y comandos útiles

## Uso Rápido

### Opción 1: Manifiestos Kubernetes

```bash
cd k8s

# 1. Configurar secrets
cp secret.yaml.example secret.yaml
# Editar secret.yaml con valores reales

# 2. Desplegar
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment-server.yaml
kubectl apply -f service-server.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml

# 3. Verificar
kubectl get all -n kryon-system
```

O usar el script:
```bash
./scripts/deploy-k8s.sh dev
```

### Opción 2: Helm Chart

```bash
# Instalación básica
helm install kryon ./helm/kryon --namespace kryon-system --create-namespace

# Con valores personalizados
helm install kryon ./helm/kryon \
  --namespace kryon-system \
  --create-namespace \
  --set secrets.jwtSecret="<your-secret>" \
  --set ingress.hosts[0].host="kryon.tu-dominio.com"

# Con archivo de valores
helm install kryon ./helm/kryon -f my-values.yaml
```

O usar el script:
```bash
./scripts/deploy-helm.sh dev
```

## Configuración de Secrets

**IMPORTANTE:** Los secrets DEBEN ser configurados antes del deployment en producción.

### Generar secrets seguros:

```bash
# JWT Secret (base64)
echo -n "$(openssl rand -base64 48)" | base64

# API Key (base64)
echo -n "$(openssl rand -base64 32)" | base64

# Credential Key (base64)
echo -n "$(openssl rand -base64 32)" | base64
```

### Kubernetes Manifiestos:

Editar `k8s/secret.yaml`:
```yaml
data:
  JWT_SECRET: <tu-valor-base64>
  API_KEY: <tu-valor-base64>
  CREDENTIAL_KEY: <tu-valor-base64>
```

### Helm Chart:

Opción 1 - Vía CLI:
```bash
helm install kryon ./helm/kryon \
  --set secrets.jwtSecret="$(openssl rand -base64 48)" \
  --set secrets.apiKey="$(openssl rand -base64 32)" \
  --set secrets.credentialKey="$(openssl rand -base64 32)"
```

Opción 2 - Archivo de valores (NO COMMITEAR):
```yaml
# secrets.yaml
secrets:
  jwtSecret: "tu-jwt-secret-aqui"
  apiKey: "tu-api-key-aqui"
  credentialKey: "tu-credential-key-aqui"
```

```bash
helm install kryon ./helm/kryon -f values.yaml -f secrets.yaml
```

## Configuración de Ingress

### Cambiar el dominio:

**Kubernetes:**
Editar `k8s/ingress.yaml`:
```yaml
spec:
  tls:
  - hosts:
    - tu-dominio.com
  rules:
  - host: tu-dominio.com
```

**Helm:**
En `values.yaml`:
```yaml
ingress:
  hosts:
    - host: tu-dominio.com
      paths: [...]
  tls:
    - secretName: kryon-tls-cert
      hosts:
        - tu-dominio.com
```

### Certificados TLS:

Si usas cert-manager (automático):
```yaml
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
```

Si usas certificado manual:
```bash
kubectl create secret tls kryon-tls-cert \
  --cert=cert.pem \
  --key=key.pem \
  -n kryon-system
```

## Escalado

### Manual:
```bash
kubectl scale deployment kryon-server -n kryon-system --replicas=5
```

### Automático (HPA):
El HPA está configurado por defecto. Verificar:
```bash
kubectl get hpa -n kryon-system
kubectl describe hpa kryon-server-hpa -n kryon-system
```

Ajustar targets en `k8s/hpa.yaml` o `helm/values.yaml`:
```yaml
autoscaling:
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
  minReplicas: 2
  maxReplicas: 10
```

## Monitoreo

### Logs:
```bash
# Server
kubectl logs -f -n kryon-system -l app.kubernetes.io/component=server

# Pod específico
kubectl logs -f -n kryon-system <pod-name>
```

### Eventos:
```bash
kubectl get events -n kryon-system --sort-by='.lastTimestamp'
```

### Health checks:
```bash
# Desde dentro del cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://kryon-server.kryon-system.svc.cluster.local:8700/api/v1/health
```

### Recursos:
```bash
kubectl top pods -n kryon-system
kubectl top nodes
```

## Actualización

### Kubernetes Manifiestos:
```bash
# Aplicar cambios
kubectl apply -f k8s/deployment-server.yaml

# Ver estado del rollout
kubectl rollout status deployment/kryon-server -n kryon-system

# Rollback si es necesario
kubectl rollout undo deployment/kryon-server -n kryon-system
```

### Helm Chart:
```bash
# Actualizar valores
helm upgrade kryon ./helm/kryon -f my-values.yaml

# Actualizar solo imagen
helm upgrade kryon ./helm/kryon --set server.image.tag=v1.1.0

# Ver historial
helm history kryon -n kryon-system

# Rollback
helm rollback kryon -n kryon-system
```

## Troubleshooting

### Pods no inician:
```bash
kubectl describe pod <pod-name> -n kryon-system
kubectl logs <pod-name> -n kryon-system
kubectl get events -n kryon-system
```

### Storage issues:
```bash
kubectl get pvc -n kryon-system
kubectl describe pvc kryon-data-pvc -n kryon-system
```

### Ingress no funciona:
```bash
kubectl describe ingress kryon-ingress -n kryon-system
kubectl get ingress -n kryon-system
# Verificar nginx-ingress-controller instalado
kubectl get pods -n ingress-nginx
```

### HPA no escala:
```bash
# Verificar metrics-server
kubectl top nodes
kubectl top pods -n kryon-system

# Ver estado del HPA
kubectl describe hpa kryon-server-hpa -n kryon-system
```

## Limpieza

### Kubernetes Manifiestos:
```bash
# Eliminar recursos
kubectl delete -f k8s/

# O eliminar namespace completo
kubectl delete namespace kryon-system
```

### Helm Chart:
```bash
# Desinstalar release
helm uninstall kryon -n kryon-system

# Eliminar namespace
kubectl delete namespace kryon-system
```

## Seguridad

### Checklist Pre-Producción:

- [ ] Secrets configurados (no valores por defecto)
- [ ] TLS/SSL habilitado con certificados válidos
- [ ] Resource limits apropiados para la carga
- [ ] Autoscaling configurado y probado
- [ ] Persistent storage con backups
- [ ] Logs agregados (ELK, Loki, etc.)
- [ ] Métricas y alertas configuradas (Prometheus/Grafana)
- [ ] Network Policies implementadas
- [ ] RBAC con principio de menor privilegio
- [ ] Security contexts configurados (runAsNonRoot, etc.)
- [ ] Ingress rate limiting habilitado
- [ ] Pruebas de carga ejecutadas
- [ ] Plan de DR documentado y probado
- [ ] Runbook de operaciones actualizado
- [ ] Equipo entrenado en procedimientos

## Documentación Adicional

- **Deployment completo:** `DEPLOYMENT.md`
- **Kubernetes manifiestos:** `k8s/README.md`
- **Helm chart:** `helm/README.md`
- **Docker deployment:** `docker/README.md`
- **Arquitectura general:** `docs/architecture.md`

## Soporte

- GitHub Issues: https://github.com/skyvanguard/kryon/issues
- Documentación: https://github.com/skyvanguard/kryon/docs
- Email: admin@kryon.security

---

**Nota:** Este es un resumen técnico. Consulta la documentación completa en cada directorio para detalles específicos.
