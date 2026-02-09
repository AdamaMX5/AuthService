#main.py
from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import text
from user_router import router as UserRouter
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Include routers
app.include_router(UserRouter)


@app.get("/")
def read_root():
    """Root endpoint."""
    return "hello Welt"


@app.get("/db_health")
async def check_database_health(db: AsyncSession = Depends(get_db)):
    """Check database health."""
    try:
        # Test connection
        await db.exec(text("SELECT 1"))

        # Get list of tables
        result = await db.exec(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        )
        tables = result.all()

        # Count users if users table exists
        user_count = 0
        if any(table[0] == 'users' for table in tables):
            result = await db.exec(text("SELECT COUNT(*) FROM users"))
            count_result = result.first()
            user_count = count_result[0] if count_result else 0

        return {
            "status": "healthy",
            "database": "connected",
            "tables": [table[0] for table in tables],
            "user_count": user_count
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "tables": [],
            "user_count": 0
        }


@app.get("/create_tables")
async def create_tables_endpoint(db: AsyncSession = Depends(get_db)):
    """Create database tables."""
    from database import init_db
    try:
        success = await init_db()
        if success:
            return {"status": "success", "message": "Tables created successfully"}
        else:
            return {"status": "error", "message": "Failed to create tables"}
    except Exception as e:
        logger.error(f"Manual table creation failed: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/drop_tables")
async def drop_tables_endpoint(db: AsyncSession = Depends(get_db)):
    """Drop all tables (DANGEROUS - for development only!)."""
    try:
        # Get all tables
        result = await db.exec(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        )
        tables = result.all()

        # Drop each table
        dropped_tables = []
        for table in tables:
            table_name = table[0]
            if table_name != 'sqlite_sequence':  # Skip SQLite sequence table
                await db.exec(text(f"DROP TABLE IF EXISTS {table_name}"))
                dropped_tables.append(table_name)

        await db.commit()

        logger.warning(f"Dropped tables: {dropped_tables}")
        return {
            "status": "success",
            "message": f"Dropped {len(dropped_tables)} tables",
            "dropped_tables": dropped_tables
        }
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to drop tables: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/tables_info")
async def get_tables_info(db: AsyncSession = Depends(get_db)):
    """Get detailed information about all tables."""
    try:
        # Get all tables
        result = await db.exec(
            text("""
                SELECT name, sql 
                FROM sqlite_master 
                WHERE type='table' 
                ORDER BY name
            """)
        )
        tables = result.all()

        table_info = []
        for table_name, table_sql in tables:
            # Get row count for each table
            if table_name != 'sqlite_sequence':
                count_result = await db.exec(
                    text(f"SELECT COUNT(*) FROM {table_name}")
                )
                count_row = count_result.first()
                row_count = count_row[0] if count_row else 0

                # Get column info
                columns_result = await db.exec(
                    text(f"PRAGMA table_info({table_name})")
                )
                columns = columns_result.all()

                table_info.append({
                    "name": table_name,
                    "row_count": row_count,
                    "sql": table_sql,
                    "columns": [
                        {
                            "name": col[1],
                            "type": col[2],
                            "not_null": bool(col[3]),
                            "primary_key": bool(col[5])
                        }
                        for col in columns
                    ]
                })

        return {
            "status": "success",
            "tables": table_info,
            "total_tables": len(table_info)
        }

    except Exception as e:
        logger.error(f"Failed to get table info: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/simple_tables_html", response_class=HTMLResponse)
async def get_simple_tables_html(db: AsyncSession = Depends(get_db)):
    """Simple HTML version of all tables."""
    try:
        result = await db.exec(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        )
        tables = result.all()

        html = "<html><body><h1>Database Tables</h1>"

        for table in tables:
            table_name = table[0]
            html += f"<h2>Table: {table_name}</h2>"

            # Get data
            data_result = await db.exec(text(f"SELECT * FROM {table_name}"))
            data = data_result.all()

            if data:
                html += "<table border='1'>"
                # Header
                html += "<tr>"
                for column in data[0]._fields:
                    html += f"<th>{column}</th>"
                html += "</tr>"

                # Rows
                for row in data:
                    html += "<tr>"
                    for cell in row:
                        html += f"<td>{cell}</td>"
                    html += "</tr>"
                html += "</table>"
            else:
                html += "<p>Empty table</p>"

            html += "<hr>"

        html += "</body></html>"
        return HTMLResponse(content=html)

    except Exception as e:
        return HTMLResponse(content=f"<h1>Error: {str(e)}</h1>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)