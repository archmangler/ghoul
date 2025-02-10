#!/bin/bash

# Exit on any error
set -e

# Run the container
docker run -d \
  -p 8887:8887 \
  -v $(pwd)/database.db:/app/database.db \
  -v $(pwd)/static/uploads:/app/static/uploads \
  ghoul-$(git rev-parse --short HEAD)

echo "Container started! Application is available at http://localhost:8887"
