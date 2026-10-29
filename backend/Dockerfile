FROM php:8.4-apache-bookworm

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

RUN apt-get update \
    && apt-get install -y --no-install-recommends libonig-dev libpq-dev libxml2-dev libzip-dev libonig5 libpq5 libxml2 libzip4 unzip \
    && docker-php-ext-install -j"$(nproc)" mbstring opcache pdo_pgsql xml zip \
    && apt-mark manual libonig5 libpq5 libxml2 libzip4 unzip \
    && apt-get purge -y --auto-remove libonig-dev libpq-dev libxml2-dev libzip-dev \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

WORKDIR /var/www/html

COPY . /var/www/html
COPY docker/apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY docker/ports.conf.template /etc/apache2/ports.conf.template
COPY docker/entrypoint.sh /usr/local/bin/mergeguard-entrypoint

ENV APP_ENV=production \
    APP_DEBUG=false \
    DB_CONNECTION=pgsql

RUN mkdir -p \
        bootstrap/cache \
        storage/framework/cache/data \
        storage/framework/sessions \
        storage/framework/testing \
        storage/framework/views \
        storage/logs \
    && composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader \
    && chown -R www-data:www-data bootstrap/cache storage \
    && chmod -R ug+rwX bootstrap/cache storage \
    && chmod 0755 /usr/local/bin/mergeguard-entrypoint

EXPOSE 10000

ENTRYPOINT ["/usr/local/bin/mergeguard-entrypoint"]
