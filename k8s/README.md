# KRYON Kubernetes Deployment

Este directorio contiene los manifiestos de Kubernetes para desplegar la plataforma KRYON Security.

## Requisitos Previos

- Kubernetes cluster 1.24+
- `kubectl` configurado
- nginx-ingress-controller instalado
- cert-manager instalado (opcional, para certificados TLS automáticos)
- Clase de almacenamiento configurada para PersistentVolumeClaims

## Despliegue Rápido

### 1. Crear Secrets

Primero, copia el archivo de ejemplo de secrets y configura tus valores:

```bash
cp secret.yaml.example secret.yaml
```

Genera valores base64 para tus secretos:

```bash
# Generar JWT Secret
echo -n "tu-jwt-secret-super-seguro-de-al-menos-32-caracteres" | base64

# Generar API Key
echo -n "tu-api-key-segura" | base64

# Generar Credential Key
echo -n "tu-credential-key-segura" | base64
```

Edita `secret.yaml` y reemplaza los valores placeholder con tus secrets generados.

### 2. Aplicar los Manifiestos

```bash
# Aplicar en orden
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment-server.yaml
kubectl apply -f deployment-dashboard.yaml
kubectl apply -f service-server.yaml
kubectl apply -f service-dashboard.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml
```

O aplicar todo de una vez:

```bash
kubectl apply -f .
```

### 3. Verificar el Despliegue

```bash
# Ver todos los recursos
kubectl get all -n kryon-system

# Ver los pods
kubectl get pods -n kryon-system

# Ver logs del servidor
kubectl logs -f -n kryon-system -l app.kubernetes.io/component=server

# Ver logs del dashboard
kubectl logs -f -n kryon-system -l app.kubernetes.io/component=dashboard
```

### 4. Acceder a la Aplicación

Si configuraste el Ingress correctamente:

```
https://kryon.example.com
```

Si estás en desarrollo local, puedes usar port-forward:

```bash
# Port-forward del servidor
kubectl port-forward -n kryon-system svc/kryon-server 8700:8700

# Port-forward del dashboard
kubectl port-forward -n kryon-system svc/kryon-dashboard 8080:80
```

Luego accede a:
- Dashboard: http://localhost:8080
- API: http://localhost:8700/api/v1/health

## Configuración del Ingress

### Actualizar el Host

Edita `ingress.yaml` y cambia `kryon.example.com` por tu dominio:

```yaml
spec:
  tls:
  - hosts:
    - tu-dominio.com
    secretName: kryon-tls-cert
  rules:
  - host: tu-dominio.com
```

### Certificados TLS

Si tienes cert-manager instalado, el certificado se generará automáticamente usando Let's Encrypt.

Si quieres usar un certificado manual:

```bash
kubectl create secret tls kryon-tls-cert \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem \
  -n kryon-system
```

## Escalado

### Manual

```bash
# Escalar el servidor
kubectl scale deployment kryon-server -n kryon-system --replicas=5

# Escalar el dashboard
kubectl scale deployment kryon-dashboard -n kryon-system --replicas=2
```

### Automático (HPA)

El HorizontalPodAutoscaler está configurado para el servidor:
- Mínimo: 2 réplicas
- Máximo: 10 réplicas
- Target CPU: 70%
- Target Memory: 80%

Verificar estado del HPA:

```bash
kubectl get hpa -n kryon-system
kubectl describe hpa kryon-server-hpa -n kryon-system
```

## Monitoreo

### Health Checks

```bash
# Desde dentro del cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://kryon-server.kryon-system.svc.cluster.local:8700/api/v1/health

# Health check extendido (requiere autenticación)
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://kryon-server.kryon-system.svc.cluster.local:8700/api/v1/admin/health
```

### Logs

```bash
# Logs del servidor (todas las réplicas)
kubectl logs -n kryon-system -l app.kubernetes.io/component=server --tail=100 -f

# Logs de un pod específico
kubectl logs -n kryon-system <pod-name> -f

# Logs anteriores (si el pod crasheó)
kubectl logs -n kryon-system <pod-name> --previous
```

### Eventos

```bash
kubectl get events -n kryon-system --sort-by='.lastTimestamp'
```

## Actualización

### Actualizar Imagen

```bash
# Actualizar servidor
kubectl set image deployment/kryon-server \
  server=kryon/server:v1.1.0 \
  -n kryon-system

# Actualizar dashboard
kubectl set image deployment/kryon-dashboard \
  dashboard=kryon/dashboard:v1.1.0 \
  -n kryon-system
```

### Rolling Update

Las actualizaciones se realizan automáticamente con rolling updates. Para ver el estado:

```bash
kubectl rollout status deployment/kryon-server -n kryon-system
```

### Rollback

Si algo sale mal:

```bash
# Ver historial
kubectl rollout history deployment/kryon-server -n kryon-system

# Rollback a la versión anterior
kubectl rollout undo deployment/kryon-server -n kryon-system

# Rollback a una revisión específica
kubectl rollout undo deployment/kryon-server -n kryon-system --to-revision=2
```

## Persistencia

El PVC `kryon-data-pvc` almacena:
- Base de datos SQLite
- ChromaDB embeddings
- Archivos de caché
- Reportes generados

Para verificar:

```bash
kubectl get pvc -n kryon-system
kubectl describe pvc kryon-data-pvc -n kryon-system
```

## Troubleshooting

### Pod no inicia

```bash
kubectl describe pod <pod-name> -n kryon-system
kubectl logs <pod-name> -n kryon-system
```

### Problemas de red

```bash
# Verificar servicios
kubectl get svc -n kryon-system

# Verificar endpoints
kubectl get endpoints -n kryon-system

# Test de conectividad interna
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- \
  curl http://kryon-server.kryon-system.svc.cluster.local:8700/api/v1/health
```

### Problemas de storage

```bash
# Verificar PV y PVC
kubectl get pv,pvc -n kryon-system

# Ver eventos del PVC
kubectl describe pvc kryon-data-pvc -n kryon-system
```

### HPA no escala

```bash
# Verificar metrics-server está instalado
kubectl top nodes
kubectl top pods -n kryon-system

# Ver estado del HPA
kubectl describe hpa kryon-server-hpa -n kryon-system
```

## Limpieza

Para eliminar todo:

```bash
kubectl delete namespace kryon-system
```

O eliminar recursos individuales:

```bash
kubectl delete -f .
```

## Notas de Seguridad

1. **Nunca** commitees `secret.yaml` al repositorio
2. Usa un secret management tool en producción (Vault, Sealed Secrets, etc.)
3. Configura Network Policies para restringir tráfico
4. Habilita RBAC apropiado
5. Usa TLS/SSL para todas las comunicaciones
6. Revisa los SecurityContext configurados
7. Considera usar Pod Security Standards (PSS)

## Configuración Avanzada

### Usar StorageClass Específica

Edita `pvc.yaml`:

```yaml
spec:
  storageClassName: fast-ssd  # tu storage class
```

### Configurar Node Affinity

Edita los deployments y añade:

```yaml
spec:
  template:
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-role.kubernetes.io/worker
                operator: In
                values:
                - "true"
```

### Configurar Resource Quotas

```bash
kubectl create quota kryon-quota -n kryon-system \
  --hard=requests.cpu=4,requests.memory=4Gi,limits.cpu=8,limits.memory=8Gi
```
