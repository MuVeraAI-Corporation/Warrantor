#!/usr/bin/env bash
# Load the Trillian schema and create the log tree Rekor needs.
#
# Run once after `docker compose up -d`, then restart rekor with the printed
# tree id in REKOR_TLOG_ID.
set -euo pipefail

DB=warrantor-trillian-db
SCHEMA_URL=https://raw.githubusercontent.com/google/trillian/master/storage/mysql/schema/storage.sql

echo "==> waiting for MySQL"
for _ in $(seq 1 40); do
  if docker exec "$DB" mysqladmin ping -h localhost -uroot -pzaphod >/dev/null 2>&1; then break; fi
  sleep 2
done

echo "==> loading the Trillian schema"
tmp=$(mktemp)
curl -sL --max-time 60 -o "$tmp" "$SCHEMA_URL"
docker cp "$tmp" "$DB":/tmp/storage.sql
docker exec "$DB" sh -c 'mysql -uroot -pzaphod test < /tmp/storage.sql' 2>&1 | grep -v "Using a password" || true
rm -f "$tmp"

echo "==> creating the log tree"
# WHY THIS IS AN INSERT AND NOT `createtree`:
#
# Trillian's createtree is a separate binary with no published image --
# gcr.io/trillian-opensource-ci/createtree and ghcr.io/google/trillian/createtree
# both 404 -- and the log_server image is distroless, so there is no shell to run
# it in. Inserting the row is the remaining option without building a Go binary.
#
# CAVEAT: PrivateKey and PublicKey are NOT NULL in the schema but are written
# empty here. Trillian moved key handling out of storage, so current versions do
# not read them. If you upgrade Trillian and tree creation starts failing, this
# is the first thing to suspect.
TREE_ID=$(( (RANDOM << 45) | (RANDOM << 30) | (RANDOM << 15) | RANDOM ))
NOW=$(date +%s000)

docker exec "$DB" mysql -uroot -pzaphod -e "USE test;
INSERT INTO Trees
  (TreeId, TreeState, TreeType, HashStrategy, HashAlgorithm, SignatureAlgorithm,
   DisplayName, Description, CreateTimeMillis, UpdateTimeMillis,
   MaxRootDurationMillis, PrivateKey, PublicKey, Deleted)
VALUES
  ($TREE_ID, 'ACTIVE', 'LOG', 'RFC6962_SHA256', 'SHA256', 'ECDSA',
   'warrantor', 'warrantor evidence log', $NOW, $NOW, 3600000, '', '', 0);
INSERT INTO TreeControl (TreeId, SigningEnabled, SequencingEnabled, SequenceIntervalSeconds)
VALUES ($TREE_ID, 1, 1, 1);" 2>&1 | grep -v "Using a password" || true

echo
echo "tree id: $TREE_ID"
echo
echo "Now restart rekor with it:"
echo "  REKOR_TLOG_ID=$TREE_ID docker compose -f deploy/local-sigstore/docker-compose.yml up -d rekor"
echo
echo "Then verify:"
echo "  curl -s http://127.0.0.1:3000/api/v1/log"
echo "  # an empty tree has rootHash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
echo "  # which is SHA-256 of the empty string -- that is correct, not a failure"
