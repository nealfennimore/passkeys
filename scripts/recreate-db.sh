#! /usr/bin/env bash

npx wrangler d1 execute passkeys_db --command='DELETE FROM public_keys; DELETE FROM users;'
npx wrangler d1 execute passkeys_db --file=./src/server/db/schema/schema.sql
