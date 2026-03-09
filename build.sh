# build.sh

echo "=== AuthService Deploy ==="

# Backup
echo "Backup keys and database..."
BACKUP_DIR="./backups/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

if [ -f "./data/app.db" ]; then
    cp ./data/app.db $BACKUP_DIR/app.db
    echo "  ✅ Database backed up to $BACKUP_DIR/app.db"
else
    echo "  ⚠️ No database found to backup"
fi

if [ -f "./keys/jwt_private.pem" ]; then
    cp ./keys/*.pem $BACKUP_DIR/
    echo "  ✅ Keys backed up to $BACKUP_DIR/"
fi

# Git pull
git pull

# Alten Container löschen
docker stop authservice 2>/dev/null
docker rm authservice 2>/dev/null

# Neues Image bauen (ohne Cache)
docker build --no-cache -t authservice .

# Verzeichnisse erstellen
mkdir -p ./keys ./data

# Wenn es ein Backup gibt, das NEUESTE verwenden
LATEST_BACKUP=$(ls -td ./backups/*/ 2>/dev/null | head -1)
if [ -n "$LATEST_BACKUP" ]; then
    echo "  Latest backup found: $LATEST_BACKUP"

    # Datenbank wiederherstellen
    if [ -f "${LATEST_BACKUP}app.db" ]; then
        cp ${LATEST_BACKUP}app.db ./data/app.db
        echo "  ✅ Database restored from backup"
    fi

    # Keys wiederherstellen
    if [ -f "${LATEST_BACKUP}jwt_private.pem" ]; then
        cp ${LATEST_BACKUP}*.pem ./keys/ 2>/dev/null
        echo "  ✅ Keys restored from backup"
    fi
else
    echo "  ⚠️ No backup found, starting fresh"
fi

# Neuen Container starten
docker run -d \
  --name authservice \
  -p 8001:8000 \
  --env-file .env \
  -v $(pwd)/keys:/app/keys \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  authservice

docker exec authservice python -c "
import asyncio
import logging
from database import engine
from models import Base
logging.basicConfig(level=logging.INFO)

async def init_db():
    try:
        # Prüfen ob Tabellen existieren
        async with engine.connect() as conn:
            # SQLite spezifisch: Tabellen auflisten
            result = await conn.execute('SELECT name FROM sqlite_master WHERE type=\"table\" AND name=\"users\"')
            table_exists = result.fetchone()

            if not table_exists:
                print('📝 Creating tables...')
                await conn.run_sync(Base.metadata.create_all)
                print('✅ Tables created')
            else:
                print('✅ Tables already exist')

    except Exception as e:
        print(f'❌ Error: {e}')

asyncio.run(init_db())
"

echo ""
echo "=== Deploy completed at $(date) ==="