FROM php:8.2-fpm-alpine

RUN apk add --no-cache \
    curl \
    git \
    nginx \
    swoole-dev \
    gcc \
    make \
    pcre-dev \
    autoconf \
    libtool \
    openssl-dev \
    linux-headers \
    zlib-dev \
    libmemcached-dev \
    onig-dev \
    sqlite-dev \
    mysql-client \
    rabbitmq-c-dev

RUN docker-php-ext-install pdo pdo_mysql opcache bcmath exif pcntl sockets

# 安裝 Swoole
RUN pecl install swoole
RUN docker-php-ext-enable swoole

# 安裝 RabbitMQ
RUN pecl install amqp
RUN docker-php-ext-enable amqp

# 安裝 Composer
COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

WORKDIR /var/www/html
