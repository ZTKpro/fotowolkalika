#!/bin/bash
# Skrypt startowy dla aplikacji PGB2 Report Sender na platformie Render

# Sprawdź i utwórz katalogi jeśli nie istnieją
mkdir -p templates

# Instaluj pozostałe zależności
pip install -r requirements.txt

# Uruchomienie aplikacji z poprawnym adresem hosta
python -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}