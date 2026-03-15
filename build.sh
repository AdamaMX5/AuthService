# build.sh

echo "=== AuthService Deploy ==="

# Backup JWT keys
echo "Backup keys..."
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

if [ -f "./keys/jwt_private.pem" ]; then
    cp ./keys/*.pem $BACKUP_DIR/
    echo "  ✅ Keys backed up to $BACKUP_DIR/"
else
    echo "  ⚠️ No keys found to backup"
fi

# Git pull
git pull

# Rebuild and restart only the authservice (MongoDB bleibt laufen)
docker compose stop authservice
docker compose rm -f authservice
docker compose build --no-cache authservice
docker compose up -d

echo ""
echo "=== Deploy completed at $(date) ==="
