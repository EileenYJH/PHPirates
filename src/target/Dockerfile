# Deliberately vulnerable toy PHP site. Fictional bugs, sandbox only.
FROM php:8.2-apache

ENV APACHE_DOCUMENT_ROOT=/var/www/site/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' \
      /etc/apache2/sites-available/*.conf /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Agents rewrite PHP files and immediately verify them. OPcache would keep serving
# the old script for up to revalidate_freq seconds (and can miss a same-second
# revert), making verification lie. A toy site doesn't need it.
RUN echo "opcache.enable=0" > /usr/local/etc/php/conf.d/zz-no-opcache.ini

# Whole site (code, manifest, exploit scripts, sqlite data) lives under /var/www/site.
# Compose mounts a named volume there; Docker seeds it from this image on first start,
# and agents mount the same volume to read/patch files.
COPY site/ /var/www/site/
RUN mkdir -p /var/www/site/public/uploads /var/www/site/data \
 && chown -R www-data:www-data /var/www/site
