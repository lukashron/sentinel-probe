FROM php:8.3.36-fpm-bookworm

LABEL maintainer="info@lukashron.cz"

WORKDIR /var/www/html

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

RUN chown -R www-data:1000 /var/www && usermod -u 1000 www-data

USER www-data:1000