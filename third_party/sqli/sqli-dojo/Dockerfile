FROM php:8.4-apache@sha256:3550aedd1c7bdfe26283c7b1550ef76509e6c2b1284aef814e6f2e325b7c9688

RUN docker-php-ext-install pdo_mysql

COPY src/ /var/www/html/
COPY db-init-scripts/init.sql /var/upstream/init.sql
COPY init-scripts/init.php /var/upstream/init.php
