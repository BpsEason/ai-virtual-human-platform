#!/bin/bash
echo "執行 Laravel 後端測試..."
docker-compose exec php vendor/bin/phpunit
echo "執行 Chat Service 測試..."
docker-compose exec chat-service npm run test
echo "執行 Vectorization Service 測試..."
docker-compose exec vectorization-service pytest
