#!/bin/bash
set -e

# KRYON Kubernetes Deployment Script
# Usage: ./deploy-k8s.sh [environment]
# Environments: dev, staging, prod

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$PROJECT_DIR/k8s"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Environment (default: dev)
ENV="${1:-dev}"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   KRYON Kubernetes Deployment         ║${NC}"
echo -e "${BLUE}║   Environment: ${ENV}                     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

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

# Check if secret.yaml exists
if [ ! -f "$K8S_DIR/secret.yaml" ]; then
    echo -e "${YELLOW}⚠️  secret.yaml not found. Creating from example...${NC}"

    if [ ! -f "$K8S_DIR/secret.yaml.example" ]; then
        echo -e "${RED}❌ secret.yaml.example not found!${NC}"
        exit 1
    fi

    cp "$K8S_DIR/secret.yaml.example" "$K8S_DIR/secret.yaml"

    # Generate random secrets
    JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n' | base64 | tr -d '\n')
    API_KEY=$(openssl rand -base64 32 | tr -d '\n' | base64 | tr -d '\n')
    CREDENTIAL_KEY=$(openssl rand -base64 32 | tr -d '\n' | base64 | tr -d '\n')

    # Replace placeholders
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|cGxlYXNlLWNoYW5nZS10aGlzLWp3dC1zZWNyZXQtdG8tc29tZXRoaW5nLXNlY3VyZQ==|$JWT_SECRET|g" "$K8S_DIR/secret.yaml"
        sed -i '' "s|cGxlYXNlLWNoYW5nZS10aGlzLWFwaS1rZXktdG8tc29tZXRoaW5nLXNlY3VyZQ==|$API_KEY|g" "$K8S_DIR/secret.yaml"
        sed -i '' "s|cGxlYXNlLWNoYW5nZS10aGlzLWNyZWRlbnRpYWwta2V5LXRvLXNvbWV0aGluZy1zZWN1cmU=|$CREDENTIAL_KEY|g" "$K8S_DIR/secret.yaml"
    else
        # Linux
        sed -i "s|cGxlYXNlLWNoYW5nZS10aGlzLWp3dC1zZWNyZXQtdG8tc29tZXRoaW5nLXNlY3VyZQ==|$JWT_SECRET|g" "$K8S_DIR/secret.yaml"
        sed -i "s|cGxlYXNlLWNoYW5nZS10aGlzLWFwaS1rZXktdG8tc29tZXRoaW5nLXNlY3VyZQ==|$API_KEY|g" "$K8S_DIR/secret.yaml"
        sed -i "s|cGxlYXNlLWNoYW5nZS10aGlzLWNyZWRlbnRpYWwta2V5LXRvLXNvbWV0aGluZy1zZWN1cmU=|$CREDENTIAL_KEY|g" "$K8S_DIR/secret.yaml"
    fi

    echo -e "${GREEN}✓ Generated secret.yaml with random values${NC}"
    echo -e "${YELLOW}⚠️  IMPORTANT: Review and update secret.yaml if needed!${NC}"
    echo ""
fi

# Validate manifests
echo -e "${BLUE}Validating Kubernetes manifests...${NC}"
VALIDATION_FAILED=0

for file in "$K8S_DIR"/*.yaml; do
    if [ "$(basename "$file")" != "secret.yaml.example" ]; then
        if ! kubectl apply --dry-run=client -f "$file" &> /dev/null; then
            echo -e "${RED}❌ Validation failed: $(basename "$file")${NC}"
            VALIDATION_FAILED=1
        else
            echo -e "${GREEN}✓ $(basename "$file")${NC}"
        fi
    fi
done

if [ $VALIDATION_FAILED -eq 1 ]; then
    echo -e "${RED}❌ Manifest validation failed. Please fix errors.${NC}"
    exit 1
fi
echo ""

# Deploy
echo -e "${BLUE}Deploying to Kubernetes...${NC}"

# 1. Namespace
echo -e "${YELLOW}Creating namespace...${NC}"
kubectl apply -f "$K8S_DIR/namespace.yaml"
echo ""

# 2. ConfigMap
echo -e "${YELLOW}Creating ConfigMap...${NC}"
kubectl apply -f "$K8S_DIR/configmap.yaml"
echo ""

# 3. Secret
echo -e "${YELLOW}Creating Secret...${NC}"
kubectl apply -f "$K8S_DIR/secret.yaml"
echo ""

# 4. PVC
echo -e "${YELLOW}Creating PersistentVolumeClaim...${NC}"
kubectl apply -f "$K8S_DIR/pvc.yaml"
echo ""

# Wait for PVC to be bound (timeout 60s)
echo -e "${YELLOW}Waiting for PVC to be bound...${NC}"
TIMEOUT=60
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    STATUS=$(kubectl get pvc kryon-data-pvc -n kryon-system -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    if [ "$STATUS" = "Bound" ]; then
        echo -e "${GREEN}✓ PVC bound${NC}"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo ""

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "${YELLOW}⚠️  PVC not bound yet. Continuing anyway...${NC}"
fi
echo ""

# 5. Deployments
echo -e "${YELLOW}Creating Deployments...${NC}"
kubectl apply -f "$K8S_DIR/deployment-server.yaml"
kubectl apply -f "$K8S_DIR/deployment-dashboard.yaml"
echo ""

# 6. Services
echo -e "${YELLOW}Creating Services...${NC}"
kubectl apply -f "$K8S_DIR/service-server.yaml"
kubectl apply -f "$K8S_DIR/service-dashboard.yaml"
echo ""

# 7. Ingress (if not dev)
if [ "$ENV" != "dev" ]; then
    echo -e "${YELLOW}Creating Ingress...${NC}"
    kubectl apply -f "$K8S_DIR/ingress.yaml"
    echo ""
fi

# 8. HPA
echo -e "${YELLOW}Creating HorizontalPodAutoscaler...${NC}"
kubectl apply -f "$K8S_DIR/hpa.yaml"
echo ""

# Wait for deployments
echo -e "${BLUE}Waiting for deployments to be ready...${NC}"
kubectl wait --for=condition=available --timeout=300s \
    deployment/kryon-server -n kryon-system

kubectl wait --for=condition=available --timeout=300s \
    deployment/kryon-dashboard -n kryon-system

echo -e "${GREEN}✓ Deployments ready${NC}"
echo ""

# Show status
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Deployment Status                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Pods:${NC}"
kubectl get pods -n kryon-system
echo ""

echo -e "${YELLOW}Services:${NC}"
kubectl get svc -n kryon-system
echo ""

if [ "$ENV" != "dev" ]; then
    echo -e "${YELLOW}Ingress:${NC}"
    kubectl get ingress -n kryon-system
    echo ""
fi

echo -e "${YELLOW}HPA:${NC}"
kubectl get hpa -n kryon-system
echo ""

# Show access instructions
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Access Instructions                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

if [ "$ENV" = "dev" ]; then
    echo -e "${YELLOW}Development mode - use port-forward:${NC}"
    echo ""
    echo -e "Server API:"
    echo -e "  ${GREEN}kubectl port-forward -n kryon-system svc/kryon-server 8700:8700${NC}"
    echo -e "  Access at: ${BLUE}http://localhost:8700${NC}"
    echo ""
    echo -e "Dashboard:"
    echo -e "  ${GREEN}kubectl port-forward -n kryon-system svc/kryon-dashboard 8080:80${NC}"
    echo -e "  Access at: ${BLUE}http://localhost:8080${NC}"
else
    echo -e "${YELLOW}Access via Ingress:${NC}"
    echo -e "  ${BLUE}https://kryon.example.com${NC}"
    echo ""
    echo -e "${YELLOW}Update your DNS or /etc/hosts to point to the ingress IP:${NC}"
    kubectl get ingress kryon-ingress -n kryon-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
    echo ""
fi

echo ""
echo -e "${YELLOW}View logs:${NC}"
echo -e "  Server:    ${GREEN}kubectl logs -f -n kryon-system -l app.kubernetes.io/component=server${NC}"
echo -e "  Dashboard: ${GREEN}kubectl logs -f -n kryon-system -l app.kubernetes.io/component=dashboard${NC}"
echo ""

echo -e "${GREEN}✅ Deployment completed successfully!${NC}"
echo ""

# Show warning for production
if [ "$ENV" = "prod" ]; then
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   PRODUCTION DEPLOYMENT WARNING        ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Please verify:${NC}"
    echo -e "  • Secrets are properly configured"
    echo -e "  • TLS certificates are valid"
    echo -e "  • Resource limits are appropriate"
    echo -e "  • Monitoring is configured"
    echo -e "  • Backups are scheduled"
    echo ""
fi
