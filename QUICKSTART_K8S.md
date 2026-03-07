# KRYON Kubernetes Quick Start

Guía rápida para desplegar KRYON Security Platform en Kubernetes.

## Opción 1: Script Automático (Recomendado)

### Desarrollo

```bash
./scripts/deploy-k8s.sh dev
```

### Staging/Producción

```bash
./scripts/deploy-helm.sh staging
```

## Opción 2: Manual con Manifiestos

```bash
# 1. Configurar secrets
cd k8s
cp secret.yaml.example secret.yaml

# Generar valores seguros
echo -n "$(openssl rand -base64 48)" | base64
echo -n "$(openssl rand -base64 32)" | base64
echo -n "$(openssl rand -base64 32)" | base64

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
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=kryon -n kryon-system
```

## Opción 3: Manual con Helm

```bash
# 1. Instalación básica
helm install kryon ./helm/kryon --namespace kryon-system --create-namespace

# 2. Con configuración personalizada
helm install kryon ./helm/kryon \
  --namespace kryon-system \
  --create-namespace \
  --set secrets.jwtSecret="$(openssl rand -base64 48)" \
  --set secrets.apiKey="$(openssl rand -base64 32)" \
  --set secrets.credentialKey="$(openssl rand -base64 32)" \
  --set ingress.hosts[0].host="kryon.tu-dominio.com"

# 3. Verificar
helm status kryon -n kryon-system
kubectl get pods -n kryon-system
```

## Acceso a la Aplicación

### Desarrollo (sin Ingress)

```bash
kubectl port-forward -n kryon-system svc/kryon-server 8700:8700
```

Acceder a:
- API: http://localhost:8700
- Health: http://localhost:8700/api/v1/health

### Producción (con Ingress)

Configurar DNS apuntando a la IP del Ingress:

```bash
# Obtener IP del Ingress
kubectl get ingress -n kryon-system

# Configurar DNS o /etc/hosts
echo "<INGRESS_IP> kryon.tu-dominio.com" | sudo tee -a /etc/hosts
```

Acceder a: https://kryon.tu-dominio.com

## Verificación Rápida

```bash
# Pods corriendo
kubectl get pods -n kryon-system

# Logs del servidor
kubectl logs -f -n kryon-system -l app.kubernetes.io/component=server

# Health check
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://kryon-server.kryon-system.svc.cluster.local:8700/api/v1/health
```

## Troubleshooting Rápido

### Pods no inician

```bash
kubectl describe pod <pod-name> -n kryon-system
kubectl logs <pod-name> -n kryon-system
```

### Storage issues

```bash
kubectl get pvc -n kryon-system
kubectl describe pvc kryon-data-pvc -n kryon-system
```

### Ingress no funciona

```bash
kubectl describe ingress kryon-ingress -n kryon-system
kubectl get pods -n ingress-nginx  # Verificar nginx-ingress
```

## Limpieza

```bash
# Kubernetes manifiestos
kubectl delete namespace kryon-system

# Helm
helm uninstall kryon -n kryon-system
kubectl delete namespace kryon-system
```

## Documentación Completa

- **Deployment completo:** [DEPLOYMENT.md](DEPLOYMENT.md)
- **Manifiestos K8s:** [k8s/README.md](k8s/README.md)
- **Helm Chart:** [helm/README.md](helm/README.md)
- **Verificación:** [K8S_VERIFICATION.md](K8S_VERIFICATION.md)

## Soporte

GitHub Issues: https://github.com/skyvanguard/kryon/issues
