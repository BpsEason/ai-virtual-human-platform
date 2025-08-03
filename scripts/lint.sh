#!/bin/bash

# PHP Linting
echo "Running PHP CS Fixer..."
# Assumes php-cs-fixer is installed and configured.
# You might need to install it globally or via composer.
# composer require friendsofphp/php-cs-fixer --dev
# docker-compose exec php vendor/bin/php-cs-fixer fix --dry-run --verbose --diff
# or if it's not installed in the container, you can run a temporary container
docker run --rm -v $(pwd):/app -w /app composer:2.4 sh -c "composer require --dev friendsofphp/php-cs-fixer && vendor/bin/php-cs-fixer fix --dry-run --verbose" || true
echo "PHP linting finished."

# TypeScript Linting
echo "Running ESLint for Chat Service..."
docker-compose exec chat-service npm run lint || true
echo "TypeScript linting finished."

# Python Linting
echo "Running Flake8 for Vectorization Service..."
docker-compose exec vectorization-service python3 -m flake8 --config microservices/vectorization-service/.flake8 || true
echo "Python linting finished."

echo "All linting tasks completed."
