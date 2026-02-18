# MicroService Template

Leeres Grundgerüst für neue Services (z. B. EmailService), abgeleitet vom UserService und auf das Nötigste reduziert.

## Inhalt
- FastAPI-App mit Health-Endpoint
- Router-Struktur (`app/routers`)
- Einfaches Test-Setup mit `pytest`

## Start
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8010
```

## Test
```bash
pytest -q
```
