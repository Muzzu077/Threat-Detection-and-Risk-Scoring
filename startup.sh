#!/bin/bash
# Promote user to admin if ADMIN_EMAIL set, then start server
if [ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ]; then
    python -m src.bootstrap_admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" --force
fi
exec uvicorn api.main:app --host 0.0.0.0 --port 8000
