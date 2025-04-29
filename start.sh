#!/bin/bash
# Skrypt startowy dla aplikacji PGB2 Report Sender na platformie Render

# Instalacja zależności
pip install -r requirements.txt

# Utworzenie katalogów jeśli nie istnieją
mkdir -p templates

# Uruchomienie aplikacji bezpośrednio
python main.py