# build.sh

echo "=== AuthService Deploy ==="

# Backup
echo "Backup keys and database..."
mkdir -p ./backup/$(date +%Y%m%d)
cp -r ./keys ./data ./backup/$(date +%Y%m%d)/ 2>/dev/null

# Git pull
git pull

# Alten Container löschen
docker stop authservice 2>/dev/null
docker rm authservice 2>/dev/null

# Verzeichnisse erstellen
mkdir -p ./keys ./data

# Neues Image bauen (ohne Cache)
docker build --no-cache -t authservice .

# Neuen Container starten
docker run -d \
  --name authservice \
  -p 8001:8000 \
  --env-file .env \
  -v $(pwd)/keys:/app/keys \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  authservice


# Logs zeigen
docker logs --tail 50 authservice

echo "Done!"