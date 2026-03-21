#!/bin/sh
mkdir -p /app/data /tmp/nginx-client-body /tmp/nginx-proxy

export DB_PATH=${DB_PATH:-/app/data/kubecommit.db}

./kubecommit-api &
PORT=3000 HOSTNAME=0.0.0.0 node server.js &

sleep 2

exec nginx -g 'daemon off;'
