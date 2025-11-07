#!/bin/bash

# Build and Push Script for MCP Query Builder Docker Image to ECR with AWS SSO Support
# This script builds the Docker image and pushes it to Amazon ECR using AWS SSO profiles

set -e

# Configuration
AWS_ACCOUNT_ID="340047602715"
AWS_REGION="us-east-2"
ECR_REPOSITORY="mcp-query-builder"
IMAGE_TAG="latest"
AWS_PROFILE="${AWS_PROFILE:-}"  # Use environment variable or can be overridden

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}MCP Query Builder - ECR Build & Push Script${NC}"
echo -e "${GREEN}       (AWS SSO Profile Support)${NC}"
echo -e "${GREEN}============================================${NC}"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    echo "Visit: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed. Please install it first.${NC}"
    exit 1
fi

# Handle AWS Profile
if [ -z "$AWS_PROFILE" ]; then
    echo -e "${YELLOW}No AWS_PROFILE set. Available profiles:${NC}"
    aws configure list-profiles
    echo ""
    echo -e "${BLUE}Usage: AWS_PROFILE=admin_yac ./build-and-push-sso.sh${NC}"
    echo -e "${BLUE}   or: export AWS_PROFILE=admin_yac${NC}"
    echo -e "${BLUE}       ./build-and-push-sso.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}Using AWS Profile: ${GREEN}$AWS_PROFILE${NC}"

# Check if SSO session is active
echo -e "${YELLOW}Checking AWS SSO authentication...${NC}"
if ! aws sts get-caller-identity --profile $AWS_PROFILE >/dev/null 2>&1; then
    echo -e "${YELLOW}SSO session expired or not authenticated. Logging in...${NC}"
    aws sso login --profile $AWS_PROFILE
fi

# Verify account ID
ACTUAL_ACCOUNT_ID=$(aws sts get-caller-identity --profile $AWS_PROFILE --query Account --output text)
if [ "$ACTUAL_ACCOUNT_ID" != "$AWS_ACCOUNT_ID" ]; then
    echo -e "${RED}Error: Account mismatch!${NC}"
    echo -e "Expected: $AWS_ACCOUNT_ID"
    echo -e "Actual: $ACTUAL_ACCOUNT_ID"
    echo -e "${YELLOW}Please update AWS_ACCOUNT_ID in this script or use the correct profile.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Authenticated to AWS Account: $ACTUAL_ACCOUNT_ID${NC}"
echo ""

echo -e "${YELLOW}Configuration:${NC}"
echo "  AWS Account ID: $AWS_ACCOUNT_ID"
echo "  AWS Region: $AWS_REGION"
echo "  ECR Repository: $ECR_REPOSITORY"
echo "  Image Tag: $IMAGE_TAG"
echo "  AWS Profile: $AWS_PROFILE"
echo ""

# Step 1: Authenticate Docker to ECR
echo -e "${YELLOW}Step 1: Authenticating Docker to Amazon ECR...${NC}"
aws ecr get-login-password --region $AWS_REGION --profile $AWS_PROFILE | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully authenticated to ECR${NC}"
else
    echo -e "${RED}✗ Failed to authenticate to ECR${NC}"
    exit 1
fi

# Step 2: Create ECR repository if it doesn't exist
echo -e "${YELLOW}Step 2: Checking/Creating ECR repository...${NC}"

# Check if repository exists
if aws ecr describe-repositories --repository-names $ECR_REPOSITORY --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1; then
    echo -e "${GREEN}✓ ECR repository already exists${NC}"
else
    echo "Repository doesn't exist. Creating..."
    aws ecr create-repository \
        --repository-name $ECR_REPOSITORY \
        --region $AWS_REGION \
        --profile $AWS_PROFILE \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Successfully created ECR repository${NC}"
    else
        echo -e "${RED}✗ Failed to create ECR repository${NC}"
        exit 1
    fi
fi

# Step 3: Build the Docker image
echo -e "${YELLOW}Step 3: Building Docker image...${NC}"

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building from project root: $PROJECT_ROOT"
cd "$PROJECT_ROOT"

# Check if Dockerfile.ecs exists
if [ ! -f "Dockerfile.ecs" ]; then
    echo -e "${RED}Error: Dockerfile.ecs not found in project root${NC}"
    exit 1
fi

# Build with proper context
docker build -f Dockerfile.ecs -t $ECR_REPOSITORY:$IMAGE_TAG .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully built Docker image${NC}"
else
    echo -e "${RED}✗ Failed to build Docker image${NC}"
    exit 1
fi

# Step 4: Tag the image for ECR
echo -e "${YELLOW}Step 4: Tagging image for ECR...${NC}"
docker tag $ECR_REPOSITORY:$IMAGE_TAG $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully tagged image${NC}"
else
    echo -e "${RED}✗ Failed to tag image${NC}"
    exit 1
fi

# Step 5: Push the image to ECR
echo -e "${YELLOW}Step 5: Pushing image to ECR...${NC}"
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully pushed image to ECR${NC}"
else
    echo -e "${RED}✗ Failed to push image to ECR${NC}"
    exit 1
fi

# Step 6: Verify the image was pushed
echo -e "${YELLOW}Step 6: Verifying image in ECR...${NC}"
aws ecr list-images --repository-name $ECR_REPOSITORY --region $AWS_REGION --profile $AWS_PROFILE

# Display the image URI
IMAGE_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG"
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Build and push completed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${YELLOW}Image URI:${NC} $IMAGE_URI"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Verify your task-definition.json has this image URI"
echo "2. Force a new deployment of your ECS service:"
echo ""
echo -e "${BLUE}aws ecs update-service \\
  --cluster mcp-query-builder-cluster \\
  --service mcp-query-builder-service \\
  --force-new-deployment \\
  --region $AWS_REGION \\
  --profile $AWS_PROFILE${NC}"
echo ""
