#!/bin/bash

# Exit on any error
set -e

# Get the short commit hash
COMMIT_HASH=$(git rev-parse --short HEAD)

# Build the Docker image with the commit hash tag
IMAGE_NAME="ghoul"

echo "Building Docker image: ${IMAGE_NAME}"

# Build the Docker image
docker build -t archbungle/${IMAGE_NAME}:${COMMIT_HASH} .
docker push archbungle/${IMAGE_NAME}:${COMMIT_HASH}

echo "Build complete!"
echo "To run the container, use:"
echo "docker run -d \\"
echo "  -p 8887:8887 \\"
echo "  -v \$(pwd)/database.db:/app/database.db \\"
echo "  -v \$(pwd)/static/uploads:/app/static/uploads \\"
echo "  archbungle/${IMAGE_NAME}:${COMMIT_HASH}" 
