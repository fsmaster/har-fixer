#!/usr/bin/env bash
# Publish the static site to /var/www/harfixer and reload nginx.
# Run on the server from the repo checkout: sudo ./deploy/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
WEB=/var/www/harfixer
mkdir -p "$WEB"
rsync -a --delete \
  index.html app.js fixer.js favicon.svg favicon-32.png apple-touch-icon.png og.png robots.txt sitemap.xml \
  "$WEB/"
chown -R www-data:www-data "$WEB"
if [ ! -e /etc/nginx/sites-enabled/harfixer ]; then
  cp deploy/harfixer.nginx /etc/nginx/sites-available/harfixer
  ln -sf /etc/nginx/sites-available/harfixer /etc/nginx/sites-enabled/harfixer
fi
nginx -t
systemctl reload nginx
echo "deployed $(git rev-parse --short HEAD) to $WEB"
