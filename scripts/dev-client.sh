#! /usr/bin/env bash

(trap 'kill 0' SIGINT; \
python -m http.server --directory src/client/assets & \
npm run build:client:css -- --watch & \
wait)
