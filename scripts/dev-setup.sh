#!/bin/bash
echo "正在啟動 Docker 容器..."
docker-compose up -d --build
echo "正在安裝 PHP 依賴..."
docker-compose exec php composer install
echo "正在產生 Laravel APP_KEY..."
docker-compose exec php php artisan key:generate
echo "正在產生 JWT_SECRET..."
docker-compose exec php php artisan jwt:secret --force
echo "正在執行資料庫遷移..."
docker-compose exec php php artisan migrate --seed
echo "開發環境設定完成！"
