#!/bin/sh
# Remove default symlinks that point to /dev/stdout and /dev/stderr
# so nginx writes to real files in the shared volume
rm -f /var/log/nginx/access.log /var/log/nginx/error.log
touch /var/log/nginx/access.log /var/log/nginx/error.log
chmod 644 /var/log/nginx/access.log /var/log/nginx/error.log

exec nginx -g 'daemon off;'
