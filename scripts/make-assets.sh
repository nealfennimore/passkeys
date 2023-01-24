#! /usr/bin/env bash

cp src/assets/* build/

HASH=$(sha256sum build/index.js | awk '{print $1}')
mv build/index.js build/$HASH.bundle.js

sed -i "s/{{bundle.js}}/\/$HASH.bundle.js/g" build/index.html