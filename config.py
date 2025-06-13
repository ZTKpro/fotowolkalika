import os
import secrets
from dotenv import load_dotenv

# Ładowanie zmiennych środowiskowych
load_dotenv()

# Konfiguracja aplikacji
class Config:
    # Podstawowa konfiguracja aplikacji
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    
    # Konfiguracja sesji
    SESSION_COOKIE_NAME = "pgb2_session"
    SESSION_EXPIRE_DAYS = 30
    
    # Ścieżki plików
    EXCEL_PATH = os.getenv("EXCEL_PATH", "SOGLbazaraportTAURON.xlsx")
    PROCESSED_DATA_PATH = "processed_data.json"
    DATABASE_PATH = "pgb2_database.db"
    LOG_FILE_PATH = "pgb2_report_sender.log"
    
    # Konfiguracja PGB2 API
    PGB2_BASE_URL = os.getenv("PGB2_BASE_URL", "https://pgb2.tauron-dystrybucja.pl")
    PGB2_CLIENT_ID = os.getenv("PGB2_CLIENT_ID")
    PGB2_CLIENT_SECRET = os.getenv("PGB2_CLIENT_SECRET")
    PGB2_USERNAME = os.getenv("PGB2_USERNAME")
    PGB2_PASSWORD = os.getenv("PGB2_PASSWORD")
    MWE_ID = os.getenv("MWE_ID", "_d4bf64e9-ae21-4825-bc9a-2cced1ae6560")
    
    # Konfiguracja limitów mocy
    PMAXLIM_VALUE = float(os.getenv("PMAXLIM_VALUE", "0.4670"))  # MW
    PMINLIM_VALUE = float(os.getenv("PMINLIM_VALUE", "0.0"))     # MW
    
    # Konfiguracja harmonogramu
    DAILY_REPORT_HOUR = int(os.getenv("DAILY_REPORT_HOUR", "6"))
    DAILY_REPORT_MINUTE = int(os.getenv("DAILY_REPORT_MINUTE", "0"))
    
    # Konfiguracja serwera
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8000"))

# Instancja konfiguracji
config = Config()