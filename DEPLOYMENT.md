# Guía de Despliegue de KRYON Security Platform

Esta guía cubre las diferentes opciones de despliegue para la plataforma KRYON.

## Tabla de Contenidos

- [Kubernetes (Manifiestos)](#kubernetes-manifiestos)
- [Helm Chart](#helm-chart)
- [Docker Compose](#docker-compose)
- [Desarrollo Local](#desarrollo-local)
- [Consideraciones de Producción](#consideraciones-de-producción)

## Kubernetes (Manifiestos)

### Requisitos

- Kubernetes 1.24+
- kubectl configurado
- nginx-ingress-controller
- cert-manager (opcional)
- Storage class configurada

### Despliegue Rápido

```bash
# 1. Crear y configurar secrets
cd k8s
cp secret.yaml.example secret.yaml

# Generar secrets seguros
echo -n "$(openssl rand -base64 48)" | base64  # JWT_SECRET
echo -n "$(openssl rand -base64 32)" | base64  # API_KEY
echo -n "$(openssl rand -base64 32)" | base64  # CREDENTIAL_KEY

# Editar secret.yaml con los valores generados
vim secret.yaml

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
kubectl get pods -n kryon-system -w
```

### Acceso

Si usas Ingress:
```
https://kryon.example.com
```

Si usas port-forward (desarrollo):
```bash
kubectl port-forward -n kryon-system svc/kryon-server 8700:8700
```

Ver documentación completa: [k8s/README.md](k8s/README.md)

## Helm Chart

### Requisitos

- Kubernetes 1.24+
- Helm 3.0+

### Instalación Básica

```bash
cd helm

# Instalación simple
helm install kryon ./kryon --namespace kryon-system --create-namespace

# Con valores personalizados
helm install kryon ./kryon \
  --namespace kryon-system \
  --create-namespace \
  --set secrets.jwtSecret="$(openssl rand -base64 48)" \
  --set secrets.apiKey="$(openssl rand -base64 32)" \
  --set secrets.credentialKey="$(openssl rand -base64 32)" \
  --set ingress.hosts[0].host="kryon.tu-dominio.com"
```

### Instalación con Archivo de Valores

```bash
# Crear archivo de valores
cat > my-values.yaml << EOF
server:
  replicaCount: 3
  resources:
    requests:
      memory: "512Mi"
      cpu: "1000m"

ingress:
  enabled: true
  hosts:
    - host: kryon.tu-dominio.com

persistence:
  enabled: true
  size: 20Gi

secrets:
  jwtSecret: "$(openssl rand -base64 48)"
  apiKey: "$(openssl rand -base64 32)"
  credentialKey: "$(openssl rand -base64 32)"
EOF

# Instalar
helm install kryon ./kryon -f my-values.yaml
```

### Verificación

```bash
# Ver status
helm status kryon -n kryon-system

# Ver valores aplicados
helm get values kryon -n kryon-system

# Ver pods
kubectl get pods -n kryon-system
```

Ver documentación completa: [helm/README.md](helm/README.md)

## Docker Compose

### Requisitos

- Docker 20.10+
- Docker Compose 2.0+

### Despliegue

```bash
# Stack estándar
docker-compose up -d

# Stack con Kali Linux (pentesting)
docker-compose -f docker/docker-compose.kali.yml up -d

# Ver logs
docker-compose logs -f

# Ver servicios
docker-compose ps
```

### Acceso

- API: http://localhost:8700
- API Docs: http://localhost:8700/docs

### Configuración

Edita `.env`:
```env
KRYON_DEBUG=false
KRYON_LOG_FORMAT=json
JWT_SECRET=<genera-un-secret-seguro>
API_KEY=<genera-una-api-key>
```

## Desarrollo Local

### Requisitos

- Python 3.11+
- uv (Python package manager)

### Backend

```bash
# Instalar dependencias
uv sync

# Ejecutar migraciones
python -c "from kryon.server.db import get_store; from kryon.server.migrations import run_migrations; run_migrations()"

# Iniciar servidor
python -m kryon.server.app
```

### Acceso Local

- API: http://localhost:8700
- API Docs: http://localhost:8700/docs

## Consideraciones de Producción

### Seguridad

1. **Secrets Management**
   - Nunca uses valores por defecto en producción
   - Usa un secret manager (Vault, AWS Secrets Manager, etc.)
   - Rota secrets regularmente

2. **TLS/SSL**
   - Siempre usa HTTPS en producción
   - Configura cert-manager para certificados automáticos
   - O usa certificados firmados por CA

3. **Network Policies**
   - Implementa Network Policies de Kubernetes
   - Restringe tráfico entre pods
   - Limita acceso egress

4. **RBAC**
   - Configura roles mínimos necesarios
   - Usa ServiceAccounts específicos
   - Audita accesos regularmente

### Escalabilidad

1. **Recursos**
   ```yaml
   server:
     resources:
       requests:
         memory: "1Gi"
         cpu: "2000m"
       limits:
         memory: "2Gi"
         cpu: "4000m"
   ```

2. **Autoscaling**
   ```yaml
   autoscaling:
     enabled: true
     minReplicas: 4
     maxReplicas: 20
     targetCPUUtilizationPercentage: 60
   ```

3. **Base de Datos**
   - Considera migrar a PostgreSQL para alta concurrencia
   - Implementa connection pooling
   - Configura backups automáticos

### Monitoreo

1. **Logs**
   - Configura agregación de logs (ELK, Loki)
   - Usa formato JSON para parsing
   - Implementa log rotation

2. **Métricas**
   - Integra Prometheus + Grafana
   - Configura alertas críticas
   - Monitorea uso de recursos

3. **Tracing**
   - Considera OpenTelemetry
   - Implementa distributed tracing
   - Monitorea latencias

### Alta Disponibilidad

1. **Multi-Zona**
   ```yaml
   affinity:
     podAntiAffinity:
       preferredDuringSchedulingIgnoredDuringExecution:
       - weight: 100
         podAffinityTerm:
           labelSelector:
             matchExpressions:
             - key: app.kubernetes.io/component
               operator: In
               values:
               - server
           topologyKey: topology.kubernetes.io/zone
   ```

2. **Persistencia**
   - Usa storage redundante
   - Implementa backups automáticos
   - Prueba restauración regularmente

3. **Disaster Recovery**
   - Documenta procedimientos
   - Automatiza backups
   - Prueba DR plan trimestralmente

### Configuración Recomendada Producción

```yaml
# prod-values.yaml
namespace: kryon-production

config:
  debug: false
  logFormat: json
  rateLimit: 200

server:
  replicaCount: 4
  image:
    repository: kryon/server
    tag: "1.0.0"  # Versión específica, no latest
  resources:
    requests:
      memory: "1Gi"
      cpu: "2000m"
    limits:
      memory: "2Gi"
      cpu: "4000m"

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: kryon.empresa.com
      paths:
        - path: /api
          pathType: Prefix
          backend: server
  tls:
    - secretName: kryon-tls-cert
      hosts:
        - kryon.empresa.com

autoscaling:
  enabled: true
  minReplicas: 4
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 75

persistence:
  enabled: true
  accessMode: ReadWriteMany
  size: 100Gi
  storageClass: fast-ssd

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/component
            operator: In
            values:
            - server
        topologyKey: kubernetes.io/hostname

nodeSelector:
  node-role.kubernetes.io/worker: "true"

tolerations:
- key: "workload"
  operator: "Equal"
  value: "security"
  effect: "NoSchedule"
```

### Deployment Checklist

Antes de desplegar a producción, verifica:

- [ ] Secrets configurados correctamente (no valores por defecto)
- [ ] TLS/SSL habilitado con certificados válidos
- [ ] Resource limits configurados apropiadamente
- [ ] Autoscaling habilitado y probado
- [ ] Persistent storage configurado con backups
- [ ] Logs agregados y almacenados
- [ ] Métricas y alertas configuradas
- [ ] Network Policies implementadas
- [ ] RBAC configurado con principio de menor privilegio
- [ ] Pruebas de carga ejecutadas
- [ ] Plan de DR documentado y probado
- [ ] Runbook de operaciones documentado
- [ ] Equipo entrenado en procedimientos
- [ ] Monitoring configurado
- [ ] Alertas de capacidad configuradas

## Migración

### De Docker Compose a Kubernetes

1. Exporta datos de SQLite:
   ```bash
   docker-compose exec server sqlite3 /data/kryon.db .dump > backup.sql
   ```

2. Despliega en Kubernetes

3. Importa datos:
   ```bash
   kubectl exec -it -n kryon-system <pod-name> -- sqlite3 /data/kryon.db < backup.sql
   ```

### Entre Ambientes Kubernetes

```bash
# Backup del PVC
kubectl exec -n kryon-system <pod-name> -- tar czf /tmp/backup.tar.gz /data
kubectl cp kryon-system/<pod-name>:/tmp/backup.tar.gz ./backup.tar.gz

# Restaurar en nuevo ambiente
kubectl cp ./backup.tar.gz kryon-production/<pod-name>:/tmp/backup.tar.gz
kubectl exec -n kryon-production <pod-name> -- tar xzf /tmp/backup.tar.gz -C /
```

## Troubleshooting

### Pods no inician

```bash
kubectl describe pod <pod-name> -n kryon-system
kubectl logs <pod-name> -n kryon-system
```

### Problemas de conectividad

```bash
# Test desde otro pod
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://kryon-server.kryon-system.svc.cluster.local:8700/api/v1/health
```

### Storage issues

```bash
kubectl describe pvc kryon-data-pvc -n kryon-system
kubectl get pv
```

### Performance issues

```bash
kubectl top pods -n kryon-system
kubectl top nodes
kubectl describe hpa -n kryon-system
```

## Soporte

- GitHub Issues: https://github.com/skyvanguard/kryon/issues
- Documentación: https://github.com/skyvanguard/kryon/docs
- Email: admin@kryon.security
