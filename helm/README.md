# KRYON Helm Chart

Chart de Helm para desplegar la plataforma KRYON Security en Kubernetes.

## Requisitos Previos

- Kubernetes 1.24+
- Helm 3.0+
- nginx-ingress-controller (opcional, si usas Ingress)
- cert-manager (opcional, para certificados TLS automáticos)

## Instalación

### Instalación Básica

```bash
# Desde el directorio helm/
helm install kryon ./kryon --namespace kryon-system --create-namespace
```

### Instalación con Valores Personalizados

```bash
helm install kryon ./kryon \
  --namespace kryon-system \
  --create-namespace \
  --set secrets.jwtSecret="tu-jwt-secret-super-seguro" \
  --set secrets.apiKey="tu-api-key-segura" \
  --set secrets.credentialKey="tu-credential-key-segura" \
  --set ingress.hosts[0].host="kryon.tu-dominio.com"
```

### Instalación con Archivo de Valores

Crea un archivo `my-values.yaml`:

```yaml
namespace: kryon-system

server:
  replicaCount: 3
  resources:
    requests:
      memory: "512Mi"
      cpu: "1000m"
    limits:
      memory: "1Gi"
      cpu: "2000m"

ingress:
  enabled: true
  hosts:
    - host: kryon.tu-dominio.com
      paths:
        - path: /api
          pathType: Prefix
          backend: server
        - path: /
          pathType: Prefix
          backend: dashboard
  tls:
    - secretName: kryon-tls-cert
      hosts:
        - kryon.tu-dominio.com

persistence:
  enabled: true
  size: 20Gi
  storageClass: fast-ssd

secrets:
  jwtSecret: "tu-jwt-secret-aqui"
  apiKey: "tu-api-key-aqui"
  credentialKey: "tu-credential-key-aqui"
```

Luego instala:

```bash
helm install kryon ./kryon -f my-values.yaml
```

## Configuración

### Parámetros Principales

| Parámetro | Descripción | Valor por Defecto |
|-----------|-------------|-------------------|
| `namespace` | Namespace de Kubernetes | `kryon-system` |
| `server.replicaCount` | Número de réplicas del servidor | `2` |
| `server.image.repository` | Repositorio de imagen del servidor | `kryon/server` |
| `server.image.tag` | Tag de imagen del servidor | `latest` |
| `server.resources.requests.memory` | Memoria solicitada | `256Mi` |
| `server.resources.requests.cpu` | CPU solicitada | `500m` |
| `server.resources.limits.memory` | Límite de memoria | `512Mi` |
| `server.resources.limits.cpu` | Límite de CPU | `1000m` |
| `dashboard.replicaCount` | Número de réplicas del dashboard | `1` |
| `dashboard.image.repository` | Repositorio de imagen del dashboard | `kryon/dashboard` |
| `dashboard.image.tag` | Tag de imagen del dashboard | `latest` |
| `ingress.enabled` | Habilitar Ingress | `true` |
| `ingress.className` | Clase de Ingress | `nginx` |
| `ingress.hosts[0].host` | Hostname | `kryon.example.com` |
| `autoscaling.enabled` | Habilitar HPA | `true` |
| `autoscaling.minReplicas` | Mínimo de réplicas | `2` |
| `autoscaling.maxReplicas` | Máximo de réplicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target de CPU | `70` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target de memoria | `80` |
| `persistence.enabled` | Habilitar persistencia | `true` |
| `persistence.size` | Tamaño del PVC | `10Gi` |
| `persistence.storageClass` | Storage class | `""` (default) |
| `config.debug` | Modo debug | `false` |
| `config.logFormat` | Formato de logs | `json` |
| `config.rateLimit` | Límite de rate | `120` |
| `secrets.jwtSecret` | JWT secret | `""` (auto-generado) |
| `secrets.apiKey` | API key | `""` (auto-generado) |
| `secrets.credentialKey` | Credential key | `""` (auto-generado) |

### Configuración de Secrets

**IMPORTANTE**: En producción, SIEMPRE proporciona tus propios secrets:

```bash
helm install kryon ./kryon \
  --set secrets.jwtSecret="$(openssl rand -base64 48)" \
  --set secrets.apiKey="$(openssl rand -base64 32)" \
  --set secrets.credentialKey="$(openssl rand -base64 32)"
```

O mejor aún, usa un values file que NO se commitee:

```bash
# Crear archivo de secrets (NO COMMITEAR)
cat > secrets.yaml << EOF
secrets:
  jwtSecret: "$(openssl rand -base64 48)"
  apiKey: "$(openssl rand -base64 32)"
  credentialKey: "$(openssl rand -base64 32)"
EOF

# Instalar con secrets
helm install kryon ./kryon -f values.yaml -f secrets.yaml
```

### Configuración de Ingress

Para usar un dominio personalizado:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: kryon.tu-dominio.com
      paths:
        - path: /api
          pathType: Prefix
          backend: server
        - path: /
          pathType: Prefix
          backend: dashboard
  tls:
    - secretName: kryon-tls-cert
      hosts:
        - kryon.tu-dominio.com
```

### Configuración de Recursos

Para ajustar recursos según tu carga:

```yaml
server:
  resources:
    requests:
      memory: "512Mi"
      cpu: "1000m"
    limits:
      memory: "1Gi"
      cpu: "2000m"

dashboard:
  resources:
    requests:
      memory: "128Mi"
      cpu: "200m"
    limits:
      memory: "256Mi"
      cpu: "400m"
```

### Configuración de Autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 75
```

### Configuración de Persistencia

```yaml
persistence:
  enabled: true
  accessMode: ReadWriteMany
  size: 50Gi
  storageClass: "fast-ssd"
```

## Actualización

### Actualizar con Nuevos Valores

```bash
helm upgrade kryon ./kryon -f my-values.yaml
```

### Actualizar Solo la Imagen

```bash
helm upgrade kryon ./kryon \
  --set server.image.tag=v1.1.0 \
  --set dashboard.image.tag=v1.1.0
```

### Actualizar Configuración

```bash
helm upgrade kryon ./kryon \
  --set config.rateLimit=200 \
  --set config.debug=true
```

## Verificación

### Ver Release Instalado

```bash
helm list -n kryon-system
```

### Ver Valores Aplicados

```bash
helm get values kryon -n kryon-system
```

### Ver Manifiestos Generados

```bash
helm get manifest kryon -n kryon-system
```

### Ver Estado

```bash
helm status kryon -n kryon-system
```

## Rollback

```bash
# Ver historial
helm history kryon -n kryon-system

# Rollback a revisión anterior
helm rollback kryon -n kryon-system

# Rollback a revisión específica
helm rollback kryon 2 -n kryon-system
```

## Desinstalación

```bash
# Desinstalar release
helm uninstall kryon -n kryon-system

# Eliminar namespace (si no hay otros recursos)
kubectl delete namespace kryon-system
```

## Testing

### Validar Chart

```bash
# Validar sintaxis
helm lint ./kryon

# Ver template renderizado
helm template kryon ./kryon

# Validar con valores específicos
helm template kryon ./kryon -f my-values.yaml

# Dry-run de instalación
helm install kryon ./kryon --dry-run --debug
```

### Test Post-Instalación

```bash
# Ver notas post-instalación
helm get notes kryon -n kryon-system

# Ejecutar tests (si existen)
helm test kryon -n kryon-system
```

## Ejemplos de Uso

### Desarrollo Local

```yaml
# dev-values.yaml
config:
  debug: true
  logFormat: text

server:
  replicaCount: 1

dashboard:
  replicaCount: 1

ingress:
  enabled: false

autoscaling:
  enabled: false

persistence:
  enabled: false
```

```bash
helm install kryon ./kryon -f dev-values.yaml
kubectl port-forward -n kryon-system svc/kryon-server 8700:8700
kubectl port-forward -n kryon-system svc/kryon-dashboard 8080:80
```

### Staging

```yaml
# staging-values.yaml
namespace: kryon-staging

config:
  debug: true

server:
  replicaCount: 2

ingress:
  hosts:
    - host: kryon-staging.tu-dominio.com

persistence:
  size: 10Gi
```

```bash
helm install kryon-staging ./kryon -f staging-values.yaml
```

### Producción

```yaml
# prod-values.yaml
namespace: kryon-production

config:
  debug: false
  logFormat: json
  rateLimit: 200

server:
  replicaCount: 4
  resources:
    requests:
      memory: "1Gi"
      cpu: "2000m"
    limits:
      memory: "2Gi"
      cpu: "4000m"

dashboard:
  replicaCount: 2

ingress:
  hosts:
    - host: kryon.tu-dominio.com
  annotations:
    nginx.ingress.kubernetes.io/rate-limit: "100"

autoscaling:
  enabled: true
  minReplicas: 4
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60

persistence:
  enabled: true
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
```

```bash
helm install kryon-prod ./kryon \
  -f prod-values.yaml \
  -f prod-secrets.yaml \
  --namespace kryon-production \
  --create-namespace
```

## Troubleshooting

### Chart no se instala

```bash
# Ver output completo
helm install kryon ./kryon --debug

# Validar manifiestos
helm template kryon ./kryon --debug
```

### Valores no se aplican

```bash
# Ver valores finales
helm get values kryon -n kryon-system --all

# Comparar con defaults
helm show values ./kryon
```

### Problemas con Secrets

```bash
# Ver secret generado (valores en base64)
kubectl get secret -n kryon-system kryon-secrets -o yaml

# Decodificar un valor
kubectl get secret -n kryon-system kryon-secrets -o jsonpath='{.data.JWT_SECRET}' | base64 -d
```

## Mejores Prácticas

1. **Nunca commitees valores sensibles** - Usa archivos separados para secrets
2. **Usa versiones específicas** de imágenes en producción (no `latest`)
3. **Configura resource limits** apropiados para tu carga
4. **Habilita autoscaling** en producción
5. **Usa persistent storage** en producción
6. **Configura monitoring y alerting**
7. **Implementa backups** regulares del PVC
8. **Usa RBAC** apropiado
9. **Configura Network Policies**
10. **Revisa logs** regularmente

## Soporte

Para issues y preguntas:
- GitHub Issues: https://github.com/skyvanguard/kryon/issues
- Documentación: https://github.com/skyvanguard/kryon/docs
