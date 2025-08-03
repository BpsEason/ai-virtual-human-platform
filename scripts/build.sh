#!/bin/bash
echo "Building Vue frontend..."
docker-compose exec php npm run build

echo "Building Chat Service..."
docker-compose exec chat-service npm run build

# Note: Python services typically don't require a separate build step,
# as they are interpreted languages. The Docker build handles dependencies.

echo "All services built successfully."
