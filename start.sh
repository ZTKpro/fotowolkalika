#!/bin/bash
# Skrypt startowy dla aplikacji PowerWise na platformie Render

# Sprawdź i utwórz katalogi jeśli nie istnieją
mkdir -p templates static

# Instaluj pozostałe zależności
pip install -r requirements.txt

# Uruchomienie aplikacji z poprawnym adresem hosta (nowa struktura modułowa)
python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}