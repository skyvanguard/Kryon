#!/bin/bash
set -e

# KRYON Helm Deployment Script
# Usage: ./deploy-helm.sh [environment] [release-name]
# Environments: dev, staging, prod

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
HELM_DIR="$PROJECT_DIR/helm"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Arguments
ENV="${1:-dev}"
RELEASE_NAME="${2:-kryon}"
NAMESPACE="kryon-${ENV}"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   KRYON Helm Deployment                ║${NC}"
echo -e "${BLUE}║   Environment: ${ENV}                     ║${NC}"
echo -e "${BLUE}║   Release: ${RELEASE_NAME}                    ║${NC}"
echo -e "${BLUE}║   Namespace: ${NAMESPACE}                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check helm
if ! command -v helm &> /dev/null; then
    echo -e "${RED}❌ helm not found. Please install Helm 3+.${NC}"
    exit 1
fi

# Check kubectl
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl not found. Please install kubectl.${NC}"
    exit 1
fi

# Check connection to cluster
echo -e "${BLUE}Checking connection to Kubernetes cluster...${NC}"
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}❌ Cannot connect to Kubernetes cluster. Check your kubeconfig.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Connected to cluster${NC}"
echo ""

# Validate chart
echo -e "${BLUE}Validating Helm chart...${NC}"
if ! helm lint "$HELM_DIR/kryon"; then
    echo -e "${RED}❌ Chart validation failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Chart is valid${NC}"
echo ""

# Check if values file exists
VALUES_FILE="$HELM_DIR/${ENV}-values.yaml"
if [ ! -f "$VALUES_FILE" ]; then
    echo -e "${YELLOW}⚠️  ${ENV}-values.yaml not found. Creating from template...${NC}"

    # Create values file based on environment
    if [ "$ENV" = "dev" ]; then
        cat > "$VALUES_FILE" << EOF
namespace: kryon-dev

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

secrets:
  jwtSecret: "$(openssl rand -base64 48)"
  apiKey: "$(openssl rand -base64 32)"
  credentialKey: "$(openssl rand -base64 32)"
EOF
    elif [ "$ENV" = "staging" ]; then
        cat > "$VALUES_FILE" << EOF
namespace: kryon-staging

config:
  debug: true
  logFormat: json
  rateLimit: 120

server:
  replicaCount: 2

dashboard:
  replicaCount: 1

ingress:
  enabled: true
  hosts:
    - host: kryon-staging.example.com
      paths:
        - path: /api
          pathType: Prefix
          backend: server
        - path: /
          pathType: Prefix
          backend: dashboard
  tls:
    - secretName: kryon-staging-tls
      hosts:
        - kryon-staging.example.com

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5

persistence:
  enabled: true
  size: 10Gi

secrets:
  jwtSecret: "$(openssl rand -base64 48)"
  apiKey: "$(openssl rand -base64 32)"
  credentialKey: "$(openssl rand -base64 32)"
EOF
    elif [ "$ENV" = "prod" ]; then
        cat > "$VALUES_FILE" << EOF
namespace: kryon-production

config:
  debug: false
  logFormat: json
  rateLimit: 200

server:
  replicaCount: 4
  image:
    tag: "1.0.0"  # Use specific version in prod
  resources:
    requests:
      memory: "1Gi"
      cpu: "2000m"
    limits:
      memory: "2Gi"
      cpu: "4000m"

dashboard:
  replicaCount: 2
  image:
    tag: "1.0.0"

ingress:
  enabled: true
  annotations:
    nginx.ingress.kubernetes.io/rate-limit: "100"
  hosts:
    - host: kryon.example.com
      paths:
        - path: /api
          pathType: Prefix
          backend: server
        - path: /
          pathType: Prefix
          backend: dashboard
  tls:
    - secretName: kryon-prod-tls
      hosts:
        - kryon.example.com

autoscaling:
  enabled: true
  minReplicas: 4
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 75

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

secrets:
  jwtSecret: "$(openssl rand -base64 48)"
  apiKey: "$(openssl rand -base64 32)"
  credentialKey: "$(openssl rand -base64 32)"
EOF
    fi

    echo -e "${GREEN}✓ Created ${VALUES_FILE}${NC}"
    echo -e "${YELLOW}⚠️  IMPORTANT: Review and update values, especially secrets!${NC}"
    echo ""
fi

# Check if release already exists
if helm list -n "$NAMESPACE" | grep -q "^${RELEASE_NAME}\s"; then
    echo -e "${YELLOW}Release ${RELEASE_NAME} already exists. Upgrading...${NC}"
    HELM_CMD="upgrade"
else
    echo -e "${YELLOW}Installing new release ${RELEASE_NAME}...${NC}"
    HELM_CMD="install"
fi
echo ""

# Dry run first
echo -e "${BLUE}Running dry-run...${NC}"
if ! helm $HELM_CMD "$RELEASE_NAME" "$HELM_DIR/kryon" \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f "$VALUES_FILE" \
    --dry-run --debug > /tmp/helm-dry-run.log 2>&1; then
    echo -e "${RED}❌ Dry-run failed. Check /tmp/helm-dry-run.log${NC}"
    cat /tmp/helm-dry-run.log
    exit 1
fi
echo -e "${GREEN}✓ Dry-run successful${NC}"
echo ""

# Confirm deployment (skip in dev)
if [ "$ENV" != "dev" ]; then
    echo -e "${YELLOW}Ready to deploy to ${ENV}. Continue? (y/N)${NC}"
    read -r CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo -e "${YELLOW}Deployment cancelled${NC}"
        exit 0
    fi
    echo ""
fi

# Deploy
echo -e "${BLUE}Deploying with Helm...${NC}"
helm $HELM_CMD "$RELEASE_NAME" "$HELM_DIR/kryon" \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f "$VALUES_FILE" \
    --wait \
    --timeout 10m

echo -e "${GREEN}✓ Helm deployment completed${NC}"
echo ""

# Show status
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Deployment Status                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Release Status:${NC}"
helm status "$RELEASE_NAME" -n "$NAMESPACE"
echo ""

echo -e "${YELLOW}Pods:${NC}"
kubectl get pods -n "$NAMESPACE"
echo ""

echo -e "${YELLOW}Services:${NC}"
kubectl get svc -n "$NAMESPACE"
echo ""

# Check if ingress is enabled
INGRESS_ENABLED=$(helm get values "$RELEASE_NAME" -n "$NAMESPACE" -o json | grep -o '"enabled": *true' | head -1 || echo "")
if [ -n "$INGRESS_ENABLED" ]; then
    echo -e "${YELLOW}Ingress:${NC}"
    kubectl get ingress -n "$NAMESPACE"
    echo ""
fi

# Show HPA if enabled
if kubectl get hpa -n "$NAMESPACE" &> /dev/null; then
    echo -e "${YELLOW}HPA:${NC}"
    kubectl get hpa -n "$NAMESPACE"
    echo ""
fi

# Show notes
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Post-Install Notes                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

helm get notes "$RELEASE_NAME" -n "$NAMESPACE"
echo ""

# Show useful commands
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Useful Commands                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}View logs:${NC}"
echo -e "  ${GREEN}kubectl logs -f -n $NAMESPACE -l app.kubernetes.io/component=server${NC}"
echo ""

echo -e "${YELLOW}View values:${NC}"
echo -e "  ${GREEN}helm get values $RELEASE_NAME -n $NAMESPACE${NC}"
echo ""

echo -e "${YELLOW}Upgrade:${NC}"
echo -e "  ${GREEN}helm upgrade $RELEASE_NAME $HELM_DIR/kryon -f $VALUES_FILE -n $NAMESPACE${NC}"
echo ""

echo -e "${YELLOW}Rollback:${NC}"
echo -e "  ${GREEN}helm rollback $RELEASE_NAME -n $NAMESPACE${NC}"
echo ""

echo -e "${YELLOW}Uninstall:${NC}"
echo -e "  ${GREEN}helm uninstall $RELEASE_NAME -n $NAMESPACE${NC}"
echo ""

echo -e "${GREEN}✅ Deployment completed successfully!${NC}"
echo ""

# Production warning
if [ "$ENV" = "prod" ]; then
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   PRODUCTION DEPLOYMENT                ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Post-deployment checklist:${NC}"
    echo -e "  ☐ Verify all pods are running"
    echo -e "  ☐ Check application health endpoints"
    echo -e "  ☐ Verify TLS certificates"
    echo -e "  ☐ Test authentication"
    echo -e "  ☐ Configure monitoring alerts"
    echo -e "  ☐ Verify backup schedule"
    echo -e "  ☐ Update documentation"
    echo -e "  ☐ Notify team"
    echo ""
fi
