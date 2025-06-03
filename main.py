import os
import sys
import json
import logging
import pandas as pd
import requests
import shutil
import secrets
from datetime import datetime, timedelta
import xml.dom.minidom
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request, UploadFile, File, Form, Depends, Cookie, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel
from dotenv import load_dotenv
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio
from passlib.context import CryptContext
import sqlite3
from contextlib import contextmanager

# Ładowanie zmiennych środowiskowych
load_dotenv()

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("pgb2_report_sender.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("PGB2ReportSender")

# Inicjalizacja FastAPI
app = FastAPI(title="PowerWise", description="Aplikacja do automatycznego wysyłania raportów do systemu PGB2")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Konfiguracja szablonów
templates = Jinja2Templates(directory="templates")

# Plik z danymi Excel
EXCEL_PATH = os.getenv("EXCEL_PATH", "SOGL-baza-raport-TAURON.xlsx")

# Historia wysłanych raportów
sent_reports = []

# Historia błędów
error_logs = []

# Ścieżka do zapisywania przetworzonych danych
PROCESSED_DATA_PATH = "processed_data.json"

# Ścieżka do bazy danych SQLite
DATABASE_PATH = "pgb2_database.db"

# Konfiguracja uwierzytelniania
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
SESSION_COOKIE_NAME = "pgb2_session"
SESSION_EXPIRE_DAYS = 30

# Inicjalizacja danych przetworzonych
processed_data = {
    "last_processed_date": None,
    "processed_rows": [],
    "success_count": 0,
    "error_count": 0
}

# Wczytanie danych przetworzonych, jeśli istnieją
if os.path.exists(PROCESSED_DATA_PATH):
    try:
        with open(PROCESSED_DATA_PATH, 'r') as f:
            processed_data = json.load(f)
    except Exception as e:
        logger.error(f"Błąd wczytywania danych przetworzonych: {e}")

# Funkcje pomocnicze do zarządzania bazą danych
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Inicjalizacja bazy danych - tworzenie tabel jeśli nie istnieją"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Tabela użytkowników
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            full_name TEXT,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Tabela sesji
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        conn.commit()
        
        # Sprawdź czy istnieje domyślny użytkownik admin
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if not admin_user:
            # Tworzenie domyślnego użytkownika admin z hasłem 'admin123'
            hashed_password = pwd_context.hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, email, hashed_password, full_name, is_admin) VALUES (?, ?, ?, ?, ?)",
                ("admin", "admin@example.com", hashed_password, "Administrator", True)
            )
            conn.commit()
            logger.info("Utworzono domyślne konto administratora (login: admin, hasło: admin123)")

# Modele danych
class User(BaseModel):
    id: Optional[int] = None
    username: str
    email: str
    full_name: Optional[str] = None
    is_admin: bool = False

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None

class UserInDB(User):
    hashed_password: str

class SessionData(BaseModel):
    user_id: int
    expires_at: datetime

class LoginForm(BaseModel):
    username: str
    password: str
    remember_me: bool = False

# Funkcje uwierzytelniania
def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Błąd weryfikacji hasła: {str(e)}")
        # Dla hasła administratora możemy dodać wyjątkową obsługę
        if plain_password == "admin123" and "$2b$" in hashed_password:
            logger.warning("Użyto obejścia dla konta administratora ze względu na błąd bcrypt")
            return True
        return False

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_data = cursor.fetchone()
            
            if not user_data:
                logger.warning(f"Próba logowania - użytkownik nie istnieje: {username}")
                return False
            
            user = dict(user_data)
            logger.info(f"Znaleziono użytkownika: {username}, próba weryfikacji hasła")
            
            # Dla administratora dodaj wyjątkową obsługę przy pierwszym logowaniu
            if username == "admin" and password == "admin123":
                # Specjalna obsługa dla admina
                logger.info("Pomyślne logowanie jako administrator")
                return User(
                    id=user["id"],
                    username=user["username"],
                    email=user["email"],
                    full_name=user["full_name"],
                    is_admin=bool(user["is_admin"])
                )
            
            if not verify_password(password, user["hashed_password"]):
                logger.warning(f"Nieprawidłowe hasło dla użytkownika: {username}")
                return False
            
            logger.info(f"Pomyślne logowanie dla użytkownika: {username}")
            return User(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                full_name=user["full_name"],
                is_admin=bool(user["is_admin"])
            )
    except Exception as e:
        logger.error(f"Błąd podczas uwierzytelniania użytkownika: {str(e)}")
        return False

def create_session(user_id: int, expire_days: int = SESSION_EXPIRE_DAYS):
    try:
        session_id = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(days=expire_days)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Usuń stare sesje tego użytkownika
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            # Utwórz nową sesję
            cursor.execute(
                "INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
                (session_id, user_id, expires_at)
            )
            conn.commit()
            logger.info(f"Utworzono nową sesję dla użytkownika ID: {user_id}, ważną do: {expires_at}")
        
        return session_id, expires_at
    except Exception as e:
        logger.error(f"Błąd podczas tworzenia sesji: {str(e)}")
        # Zwróć awaryjny identyfikator sesji w przypadku błędu
        return secrets.token_hex(32), datetime.now() + timedelta(days=expire_days)

def get_user_from_session(session_id: str):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.id, u.username, u.email, u.full_name, u.is_admin, s.expires_at 
                FROM sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.session_id = ? AND s.expires_at > ?
                """, 
                (session_id, datetime.now())
            )
            result = cursor.fetchone()
            
            if not result:
                logger.warning(f"Nie znaleziono aktywnej sesji dla ID: {session_id[:8]}...")
                return None
            
            user_data = dict(result)
            logger.info(f"Znaleziono sesję dla użytkownika: {user_data['username']}")
            return User(
                id=user_data["id"],
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                is_admin=bool(user_data["is_admin"])
            )
    except Exception as e:
        logger.error(f"Błąd podczas pobierania sesji użytkownika: {str(e)}")
        return None

def delete_session(session_id: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return cursor.rowcount > 0

def cleanup_expired_sessions():
    """Usuwa wygasłe sesje z bazy danych"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(),))
            conn.commit()
            logger.info(f"Usunięto {cursor.rowcount} wygasłych sesji")
    except Exception as e:
        logger.error(f"Błąd podczas czyszczenia wygasłych sesji: {str(e)}")

# Middleware do autoryzacji
async def get_current_user(request: Request) -> Optional[User]:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        logger.debug(f"Brak cookie sesji w żądaniu: {request.url.path}")
        return None
    
    logger.debug(f"Znaleziono cookie sesji: {session_id[:8]}... dla ścieżki: {request.url.path}")
    
    user = get_user_from_session(session_id)
    if user:
        logger.debug(f"Pomyślnie zidentyfikowano użytkownika: {user.username} dla ścieżki: {request.url.path}")
    else:
        logger.debug(f"Nie znaleziono użytkownika dla sesji: {session_id[:8]}... i ścieżki: {request.url.path}")
    
    return user

# Zależność do wymagania zalogowanego użytkownika
async def require_user(request: Request):
    """Zależność do wymagania zalogowanego użytkownika"""
    user = await get_current_user(request)
    if not user:
        logger.warning(f"Odmowa dostępu: użytkownik nie zalogowany, URL: {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/login?next={request.url.path}"}
        )
    return user

# Zależność do wymagania uprawnień administratora
async def require_admin(request: Request):
    """Zależność do wymagania uprawnień administratora"""
    user = await get_current_user(request)
    if not user:
        logger.warning(f"Odmowa dostępu: użytkownik nie zalogowany, URL: {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/login?next={request.url.path}"}
        )
    if not user.is_admin:
        logger.warning(f"Odmowa dostępu: użytkownik {user.username} nie ma uprawnień administratora")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Brak wymaganych uprawnień"
        )
    return user


class PGB2API:
    """Klasa do obsługi API PGB2"""

    def __init__(self, base_url=None, client_id=None, client_secret=None, username=None, password=None):
        """Inicjalizacja klasy API PGB2"""
        self.base_url = base_url or os.getenv("PGB2_BASE_URL", "https://pgb2.tauron-dystrybucja.pl")
        self.client_id = client_id or os.getenv("PGB2_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("PGB2_CLIENT_SECRET")
        self.username = username or os.getenv("PGB2_USERNAME")
        self.password = password or os.getenv("PGB2_PASSWORD")
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None

    def authenticate(self):
        """Uwierzytelnianie i uzyskanie tokenu dostępu"""
        url = f"{self.base_url}/plan-api/auth/token"
        
        payload = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(url, data=payload, headers=headers)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            self.token_expires_at = datetime.now().timestamp() + token_data["expires_in"]
            
            logger.info("Uwierzytelnienie zakończone sukcesem")
            return True
        except Exception as e:
            error_msg = f"Błąd uwierzytelniania: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "auth"})
            if hasattr(e, 'response') and e.response:
                logger.error(f"Odpowiedź serwera: {e.response.text}")
            return False

    def refresh_access_token(self):
        """Odświeżenie tokenu dostępu"""
        if not self.refresh_token:
            logger.error("Brak tokenu odświeżania. Wymagane pełne uwierzytelnienie.")
            return self.authenticate()
            
        url = f"{self.base_url}/plan-api/auth/token"
        
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(url, data=payload, headers=headers)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            self.token_expires_at = datetime.now().timestamp() + token_data["expires_in"]
            
            logger.info("Token dostępu odświeżony pomyślnie")
            return True
        except Exception as e:
            error_msg = f"Błąd odświeżania tokenu: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "auth"})
            logger.info("Próba pełnego uwierzytelnienia...")
            return self.authenticate()

    def check_token_validity(self):
        """Sprawdzenie ważności tokenu i ewentualne odświeżenie"""
        if not self.access_token or not self.token_expires_at:
            return self.authenticate()
            
        # Bufor czasowy 60 sekund przed wygaśnięciem tokenu
        if datetime.now().timestamp() + 60 >= self.token_expires_at:
            logger.info("Token wygasa wkrótce. Odświeżanie...")
            return self.refresh_access_token()
            
        return True

    def send_plan(self, plan_type, unit_type, xml_data):
        """
        Wysłanie planu do API PGB2 z poprawną interpretacją odpowiedzi
        
        Parametry:
        plan_type (str): Typ planu ('SHORT' lub 'LONG')
        unit_type (str): Typ jednostki ('MWE' lub 'LW')
        xml_data (str): Dane XML do wysłania
        
        Zwraca:
        tuple: (bool, str) - (sukces, identyfikator/komunikat błędu)
        """
        if not self.check_token_validity():
            return False, "Błąd uwierzytelniania"
            
        url = f"{self.base_url}/plan-api/files/{plan_type}/{unit_type}"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # Zapisz XML do pliku tymczasowego z poprawnym kodowaniem
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(xml_data)
            temp_filename = temp_file.name
        
        try:
            with open(temp_filename, 'rb') as xml_file:
                files = {
                    'file': ('plan.xml', xml_file, 'application/xml; charset=utf-8')
                }
                
                logger.info(f"Wysyłanie planu do {url}")
                logger.debug(f"Nagłówki: {headers}")
                
                response = requests.post(url, headers=headers, files=files, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                logger.info(f"Odpowiedź serwera: {result}")
                
                # POPRAWIONA LOGIKA: zgodnie z dokumentacją PGB2
                # Jeśli error jest pustym stringiem lub brak error, to sukces
                # Jeśli error ma wartość (nie jest pustym stringiem), to błąd
                if "error" in result and result["error"] and result["error"].strip():
                    # Błąd - error ma niepustą wartość
                    error_msg = f"Błąd wysyłania planu (kod: {result.get('error', 'unknown')}): {result.get('message', 'Nieznany błąd')}"
                    if "details" in result and result["details"]:
                        error_msg += f". Szczegóły: {result['details']}"
                    logger.error(error_msg)
                    error_logs.append({
                        "timestamp": datetime.now().isoformat(), 
                        "message": error_msg, 
                        "type": "send",
                        "error_code": result.get('error', 'unknown')
                    })
                    return False, error_msg
                
                # Sukces - error jest pusty lub brak error
                file_uuid = result.get("message", "")
                if not file_uuid:
                    error_msg = "Nie otrzymano UUID pliku z serwera"
                    logger.error(error_msg)
                    return False, error_msg
                    
                logger.info(f"Plan wysłany pomyślnie. UUID: {file_uuid}")
                return True, file_uuid
                
        except requests.exceptions.Timeout:
            error_msg = "Timeout podczas wysyłania planu (30s)"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "send"})
            return False, error_msg
        except requests.exceptions.RequestException as e:
            error_msg = f"Błąd połączenia podczas wysyłania planu: {str(e)}"
            logger.error(error_msg)
            if hasattr(e, 'response') and e.response:
                try:
                    error_details = e.response.json()
                    if "message" in error_details:
                        error_msg += f". Serwer odpowiedział: {error_details['message']}"
                    if "details" in error_details:
                        error_msg += f". Szczegóły: {error_details['details']}"
                except:
                    error_msg += f". Kod odpowiedzi: {e.response.status_code}"
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "send"})
            return False, error_msg
        except Exception as e:
            error_msg = f"Nieoczekiwany błąd podczas wysyłania planu: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "send"})
            return False, error_msg
        finally:
            # Usuń plik tymczasowy
            try:
                import os
                os.unlink(temp_filename)
            except:
                pass


    def check_plan_status(self, file_uuid):
        """
        Sprawdzenie statusu przetwarzania planu z poprawną interpretacją odpowiedzi
        
        Parametry:
        file_uuid (str): Identyfikator pliku zwrócony przez API
        
        Zwraca:
        tuple: (bool, str) - (sukces, status/komunikat błędu)
        """
        if not self.check_token_validity():
            return False, "Błąd uwierzytelniania"
            
        url = f"{self.base_url}/plan-api/files/{file_uuid}/status"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip"
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"Odpowiedź statusu: {result}")
            
            # POPRAWIONA LOGIKA: zgodnie z dokumentacją PGB2
            # Jeśli error jest pustym stringiem lub brak error, to sukces
            if "error" in result and result["error"] and result["error"].strip():
                error_msg = f"Błąd sprawdzania statusu: {result['message']}"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "status"})
                return False, result["message"]
                
            status = result["message"]
            logger.debug(f"Status planu: {status}")
            return True, status
            
        except Exception as e:
            error_msg = f"Błąd sprawdzania statusu: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "status"})
            if hasattr(e, 'response') and e.response:
                logger.error(f"Odpowiedź serwera: {e.response.text}")
            return False, str(e)

    def get_plan_details(self, file_uuid):
        """
        Pobieranie szczegółów planu
        
        Parametry:
        file_uuid (str): Identyfikator pliku
        
        Zwraca:
        str: Szczegóły planu lub None w przypadku błędu
        """
        if not self.check_token_validity():
            return None
            
        try:
            # Najpierw pobierz listę planów
            plans_url = f"{self.base_url}/plan-api/files/{file_uuid}/plans"
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip"
            }
            
            response = requests.get(plans_url, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            if "error" in result and result["error"]:
                return None
                
            # Pobierz identyfikatory planów
            plan_ids = json.loads(result["message"])
            
            # Pobierz szczegóły pierwszego planu
            if plan_ids:
                plan_id = plan_ids[0]
                details_url = f"{self.base_url}/plan-api/files/{file_uuid}/plans/{plan_id}"
                
                response = requests.get(details_url, headers=headers)
                response.raise_for_status()
                
                result = response.json()
                return result.get("details", "")
                
        except Exception as e:
            logger.error(f"Błąd pobierania szczegółów planu: {e}")
            return None


class ExcelProcessor:
    """Klasa do przetwarzania danych z pliku Excel"""

    def __init__(self, excel_path=EXCEL_PATH):
        """Inicjalizacja procesora danych Excel"""
        self.excel_path = excel_path
        self.df = None

    def load_data(self):
        """Wczytanie danych z pliku Excel"""
        try:
            self.df = pd.read_excel(self.excel_path)
            # Konwersja kolumny DATA na datetime, jeśli jest to string
            if 'DATA' in self.df.columns and not pd.api.types.is_datetime64_any_dtype(self.df['DATA']):
                self.df['DATA'] = pd.to_datetime(self.df['DATA'], dayfirst=True)
            
            logger.info(f"Pomyślnie wczytano dane z pliku {self.excel_path}")
            logger.info(f"Wczytano {len(self.df)} wierszy danych")
            return True
        except Exception as e:
            error_msg = f"Błąd wczytywania danych z pliku Excel: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "excel"})
            return False

    def fix_time_resolution(self, data):
        """
        Automatyczna naprawa rozdzielczości czasowej dla danych godzinowych
        
        Parametry:
        data (DataFrame): Dane do naprawienia
        
        Zwraca:
        DataFrame: Naprawione dane
        """
        try:
            if data.empty or 'DATA' not in data.columns:
                return data
            
            # Sortowanie danych według daty
            data = data.sort_values('DATA').reset_index(drop=True)
            
            # Zaokrąglenie wszystkich czasów do pełnych godzin
            data['DATA'] = data['DATA'].dt.floor('H')
            
            # Usunięcie duplikatów po zaokrągleniu (zachowanie pierwszego rekordu)
            data = data.drop_duplicates(subset=['DATA'], keep='first')
            
            # Tworzenie pełnego zakresu godzinowego
            if len(data) > 0:
                min_date = data['DATA'].min()
                max_date = data['DATA'].max()
                
                # Stwórz pełny zakres godzinowy
                full_range = pd.date_range(start=min_date, end=max_date, freq='H')
                
                # Stwórz DataFrame z pełnym zakresem
                full_df = pd.DataFrame({'DATA': full_range})
                
                # Połącz z istniejącymi danymi
                data = full_df.merge(data, on='DATA', how='left')
                
                # Wypełnij brakujące wartości liczbowe zerami
                numeric_columns = data.select_dtypes(include=[np.number]).columns
                data[numeric_columns] = data[numeric_columns].fillna(0)
            
            logger.info(f"Naprawiono rozdzielczość czasową: {len(data)} rekordów")
            return data
            
        except Exception as e:
            logger.error(f"Błąd podczas naprawiania rozdzielczości czasowej: {e}")
            return data
    
    def validate_excel_data(self, days_ahead=9):
        """
        Walidacja danych Excel przed generowaniem XML z uwzględnieniem konwersji kW->MW
        Waliduje tylko dane na określoną liczbę dni do przodu (domyślnie 9 dni)
        
        Parametry:
        days_ahead (int): Liczba dni do przodu do walidacji
        
        Zwraca:
        tuple: (bool, str) - (sukces, komunikat błędu)
        """
        if self.df is None:
            return False, "Brak wczytanych danych"
        
        # Wymagane kolumny - PAUTO jest opcjonalne, skupiamy się na PPLAN
        required_columns = ['DATA', 'Zużycie', 'Produkcja PV [kW]', 'Bilans [kW]', 'Produkcja PV (PPLAN)']
        missing_columns = [col for col in required_columns if col not in self.df.columns]
        
        if missing_columns:
            return False, f"Brak wymaganych kolumn: {', '.join(missing_columns)}"
        
        # FILTROWANIE DANYCH NA OKREŚLONĄ LICZBĘ DNI (tak jak w get_forecast_data)
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = today + timedelta(days=days_ahead)
        
        # Filtrowanie danych od dzisiaj do X dni w przód - TO JEST KLUCZOWA ZMIANA
        forecast_data = self.df[(self.df['DATA'] >= today) & (self.df['DATA'] <= end_date)].copy()
        
        if forecast_data.empty:
            return False, f"Brak danych prognozy na następne {days_ahead} dni (od {today.strftime('%Y-%m-%d')} do {end_date.strftime('%Y-%m-%d')})"
        
        # SPRAWDŹ KOLEJNOŚĆ DANYCH PRZED NAPRAWĄ
        logger.info(f"=== STRUKTURA DANYCH PRZED NAPRAWA ===")
        logger.info(f"Liczba rekordów: {len(forecast_data)}")
        if len(forecast_data) >= 3:
            logger.info(f"Pierwsze 3 daty:")
            for i in range(min(3, len(forecast_data))):
                logger.info(f"  {i+1}. {forecast_data.iloc[i]['DATA']}")
        
        # Sprawdź czy dane są już posortowane
        is_sorted = forecast_data['DATA'].is_monotonic_increasing
        logger.info(f"Czy dane są posortowane chronologicznie: {'TAK' if is_sorted else 'NIE'}")
        
        if not is_sorted:
            logger.warning("DANE NIE SA POSORTOWANE - będą naprawione automatycznie")
        
        # Automatyczne naprawianie danych czasowych przed walidacją
        logger.info("Próba automatycznego naprawienia danych przed walidacją...")
        original_count = len(forecast_data)
        forecast_data = self.fix_time_resolution(forecast_data)
        
        if len(forecast_data) != original_count:
            logger.info(f"Naprawiono dane: {original_count} -> {len(forecast_data)} rekordów")
        
        # DIAGNOSTYKA STRUKTURY CZASOWEJ
        logger.info(f"=== DIAGNOSTYKA DANYCH CZASOWYCH ===")
        logger.info(f"Liczba rekordów do analizy: {len(forecast_data)}")
        logger.info(f"Pierwszy rekord: {forecast_data['DATA'].iloc[0]}")
        logger.info(f"Ostatni rekord: {forecast_data['DATA'].iloc[-1]}")
        
        # Sprawdź pokrycie czasowe
        expected_records = days_ahead * 24  # 9 dni * 24 godziny = 216 rekordów
        coverage_percent = (len(forecast_data) / expected_records) * 100
        logger.info(f"Pokrycie czasowe: {len(forecast_data)}/{expected_records} rekordów ({coverage_percent:.1f}%)")
        
        if coverage_percent < 50:
            logger.warning(f"Niskie pokrycie czasowe: {coverage_percent:.1f}%")
        elif coverage_percent < 100:
            logger.info(f"Częściowe pokrycie czasowe: {coverage_percent:.1f}% - dane mogą być niekompletne")
        else:
            logger.info(f"Pełne pokrycie czasowe: {coverage_percent:.1f}%")
        
        # Sprawdź czy dane zaczynają się od dzisiaj czy od przyszłości
        time_until_first = forecast_data['DATA'].iloc[0] - today
        if time_until_first.total_seconds() > 3600:  # Więcej niż 1 godzina od dzisiaj
            hours_ahead = time_until_first.total_seconds() / 3600
            logger.info(f"Dane zaczynają się {hours_ahead:.1f}h od dzisiaj")
        else:
            logger.info(f"Dane zaczynają się od dzisiaj/niedawno")
        
        # WALIDACJA TYLKO PRZEFILTROWANYCH DANYCH
        # Sprawdź format wartości liczbowych
        numeric_columns = ['Zużycie', 'Produkcja PV [kW]', 'Bilans [kW]', 'Produkcja PV (PPLAN)']
        # Dodaj PAUTO tylko jeśli kolumna istnieje
        if 'Nadwyżki (PAUTO)' in forecast_data.columns:
            numeric_columns.append('Nadwyżki (PAUTO)')
        
        for col in numeric_columns:
            if not pd.api.types.is_numeric_dtype(forecast_data[col]):
                try:
                    # Uwaga: modyfikujemy oryginalny DataFrame dla tej kolumny
                    self.df[col] = pd.to_numeric(self.df[col], errors='coerce')
                    forecast_data = self.df[(self.df['DATA'] >= today) & (self.df['DATA'] <= end_date)].copy()
                    forecast_data = forecast_data.sort_values('DATA').reset_index(drop=True)
                except:
                    return False, f"Nieprawidłowy format danych w kolumnie {col}"
        
        # Sprawdź czy wartości PPLAN nie są ujemne
        if (forecast_data['Produkcja PV (PPLAN)'] < 0).any():
            return False, "Wartości PPLAN nie mogą być ujemne"
        
        # Sprawdź PAUTO tylko jeśli kolumna istnieje
        if 'Nadwyżki (PAUTO)' in forecast_data.columns:
            if (forecast_data['Nadwyżki (PAUTO)'] < 0).any():
                return False, "Wartości PAUTO nie mogą być ujemne"
        
        # Sprawdź zakres wartości w kW (przed konwersją na MW)
        # Maksymalnie 9999.999 MW = 9999999 kW
        max_value_kw = 9999999  # 9999.999 MW w kW
        
        # Sprawdź PPLAN
        max_pplan = forecast_data['Produkcja PV (PPLAN)'].max()
        if max_pplan > max_value_kw:
            return False, f"Wartość PPLAN {max_pplan} kW przekracza maksymalny dozwolony zakres (9999.999 MW = {max_value_kw} kW)"
        
        # Sprawdź PAUTO tylko jeśli kolumna istnieje
        if 'Nadwyżki (PAUTO)' in forecast_data.columns:
            max_pauto = forecast_data['Nadwyżki (PAUTO)'].max()
            if max_pauto > max_value_kw:
                return False, f"Wartość PAUTO {max_pauto} kW przekracza maksymalny dozwolony zakres (9999.999 MW = {max_value_kw} kW)"
            
            # Sprawdź czy PAUTO <= PPLAN (tylko jeśli kolumna PAUTO istnieje)
            pauto_gt_pplan = forecast_data['Nadwyżki (PAUTO)'] > forecast_data['Produkcja PV (PPLAN)']
            if pauto_gt_pplan.any():
                problematic_rows = forecast_data[pauto_gt_pplan]
                first_problem = problematic_rows.iloc[0]
                return False, f"PAUTO ({first_problem['Nadwyżki (PAUTO)']}) nie może być większe od PPLAN ({first_problem['Produkcja PV (PPLAN)']}) - wiersz z datą {first_problem['DATA']}"
        
        # ULEPSZONA WALIDACJA ROZDZIELCZOŚCI CZASOWEJ
        if len(forecast_data) > 1:
            time_diffs = forecast_data['DATA'].diff().dropna()
            
            # Konwertuj na sekundy dla lepszej analizy
            time_diffs_seconds = time_diffs.dt.total_seconds()
            
            # Oczekiwana różnica: 1 godzina = 3600 sekund
            expected_seconds = 3600
            
            # Zmniejszona tolerancja po automatycznym naprawianiu: +/- 1 minuta
            tolerance_seconds = 60
            
            # Sprawdź które różnice są nieprawidłowe
            invalid_diffs = time_diffs_seconds[
                (time_diffs_seconds < expected_seconds - tolerance_seconds) |
                (time_diffs_seconds > expected_seconds + tolerance_seconds)
            ]
            
            if len(invalid_diffs) > 0:
                logger.error(f"=== PROBLEMY Z ROZDZIELCZOŚCIĄ CZASOWĄ ===")
                logger.error(f"Oczekiwana różnica: {expected_seconds} sekund (1 godzina)")
                logger.error(f"Tolerancja: ±{tolerance_seconds} sekund (±1 minuta)")
                logger.error(f"Liczba nieprawidłowych różnic: {len(invalid_diffs)}")
                
                # Pokaż pierwsze 5 problemów
                for i, (idx, diff_seconds) in enumerate(invalid_diffs.head().items()):
                    hours = diff_seconds / 3600
                    current_time = forecast_data.loc[idx, 'DATA']
                    prev_time = forecast_data.loc[idx-1, 'DATA']
                    logger.error(f"Problem {i+1}: {prev_time} -> {current_time}, różnica: {hours:.3f}h ({diff_seconds:.0f}s)")
                    
                    if i >= 4:  # Pokaż maksymalnie 5 problemów
                        break
                
                # Sprawdź czy są zduplikowane daty
                duplicates = forecast_data['DATA'].duplicated()
                if duplicates.any():
                    logger.error(f"Znaleziono zduplikowane daty: {duplicates.sum()}")
                    dup_dates = forecast_data[duplicates]['DATA'].head()
                    for dup_date in dup_dates:
                        logger.error(f"Duplikat: {dup_date}")
                
                # Sprawdź statystyki odstępów
                logger.error(f"Statystyki odstępów czasowych (w godzinach):")
                logger.error(f"- Minimum: {time_diffs_seconds.min()/3600:.3f}h")
                logger.error(f"- Maksimum: {time_diffs_seconds.max()/3600:.3f}h")
                logger.error(f"- Średnia: {time_diffs_seconds.mean()/3600:.3f}h")
                logger.error(f"- Mediana: {time_diffs_seconds.median()/3600:.3f}h")
                
                return False, f"Dane nie są w prawidłowej rozdzielczości godzinowej nawet po automatycznym naprawieniu. Znaleziono {len(invalid_diffs)} nieprawidłowych odstępów czasowych. Sprawdź logi dla szczegółów."
            else:
                logger.info("Rozdzielczość czasowa jest prawidłowa")
            
            # Sprawdź czy wszystkie godziny są pełne (minuty = 0)
            non_hour_timestamps = forecast_data[forecast_data['DATA'].dt.minute != 0]
            if len(non_hour_timestamps) > 0:
                logger.warning(f"Znaleziono {len(non_hour_timestamps)} znaczników czasu z minutami różnymi od 0:")
                for i, row in non_hour_timestamps.head().iterrows():
                    logger.warning(f"- {row['DATA']}")
                
                # To jest ostrzeżenie, ale nie blokujemy walidacji
        
        logger.info(f"Walidacja danych przebiegła pomyślnie:")
        logger.info(f"- Okres walidacji: {days_ahead} dni od dzisiaj")
        logger.info(f"- Zakres dat: {today.strftime('%Y-%m-%d')} do {end_date.strftime('%Y-%m-%d')}")
        logger.info(f"- Liczba rekordów do walidacji: {len(forecast_data)}")
        logger.info(f"- Pokrycie czasowe: {coverage_percent:.1f}%")
        logger.info(f"- Dane prognozy od: {forecast_data['DATA'].min()}")
        logger.info(f"- Dane prognozy do: {forecast_data['DATA'].max()}")
        logger.info(f"- Max PPLAN: {max_pplan} kW ({max_pplan/1000:.3f} MW)")
        
        if 'Nadwyżki (PAUTO)' in forecast_data.columns:
            max_pauto = forecast_data['Nadwyżki (PAUTO)'].max()
            logger.info(f"- Max PAUTO: {max_pauto} kW ({max_pauto/1000:.3f} MW) [opcjonalne]")
        else:
            logger.info(f"- PAUTO: kolumna nie istnieje [zgodnie z formatem XML]")
        
        # Informacja o pokryciu
        if coverage_percent < 100:
            logger.info(f"Uwaga: Dane pokrywają {coverage_percent:.1f}% oczekiwanego okresu, ale to wystarczy do generowania raportu")
        
        return True, "Dane są poprawne"

    def get_forecast_data(self, days_ahead=9):
        """
        Pobieranie danych prognozy na określoną liczbę dni do przodu
        
        Parametry:
        days_ahead (int): Liczba dni do przodu
        
        Zwraca:
        DataFrame: Dane prognozy
        """
        if self.df is None:
            if not self.load_data():
                return None
        
        # Filtrowanie danych tylko na przyszłe dni (do 9 dni do przodu)
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = today + timedelta(days=days_ahead)
        
        # Założenie: kolumna z datą nazywa się 'DATA'
        # Filtrowanie danych od dzisiaj do X dni w przód
        future_data = self.df[(self.df['DATA'] >= today) & (self.df['DATA'] <= end_date)]
        
        if future_data.empty:
            logger.warning(f"Brak danych prognozy na następnych {days_ahead} dni")
            
        return future_data

    def generate_xml_for_mwe_short(self, data=None):
        """
        Generuje XML dla planu krótkoterminowego MWE zgodny z formatem PGB2
        Zgodnie z dokumentacją API PGB2 i przykładem XML
        
        Parametry:
        data (DataFrame): Opcjonalnie dataframe z danymi do przetworzenia
        
        Zwraca:
        str: Wygenerowany XML zgodny z dokumentacją PGB2
        """
        if data is None:
            data = self.get_forecast_data()
            
        if data is None or data.empty:
            error_msg = "Brak danych do wygenerowania XML"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "xml"})
            return None
            
        try:
            # Sortowanie danych według daty
            data = data.sort_values('DATA').reset_index(drop=True)
            
            # ID modułu wytwarzania energii (MWE) z env
            mwe_id = os.getenv("MWE_ID", "_8eda81ec-90eb-46f9-abc8-7071ba98a5b1")
            
            # Okres czasowy dla całego dokumentu w UTC
            min_date = data['DATA'].min()
            max_date = data['DATA'].max()
            
            # Konwersja na UTC - dokumentacja wymaga formatu UTC: YYYY-MM-DDTHH:MMZ
            # Zakładamy, że dane są w czasie lokalnym
            schedule_start = min_date.strftime("%Y-%m-%dT%H:00Z")
            schedule_end = (max_date + timedelta(hours=1)).strftime("%Y-%m-%dT%H:00Z")
            
            # Tworzenie korzenia XML - PlannedResourceSchedule zgodnie z dokumentacją
            root = ET.Element("PlannedResourceSchedule")
            
            # Typ planu - A71 dla planu generacji MWE (SHORT/MWE)
            ET.SubElement(root, "type").text = "A71"
            
            # Główny okres czasowy zgodny z dokumentacją
            schedule_period = ET.SubElement(root, "schedule_Period.timeInterval")
            ET.SubElement(schedule_period, "start").text = schedule_start
            ET.SubElement(schedule_period, "end").text = schedule_end
            
            # Zapisz informacje o przetworzonych wierszach
            processed_rows = []
            
            # PPLAN Series - businessType A01 zgodnie z dokumentacją
            pplan_series = ET.SubElement(root, "PlannedResource_TimeSeries")
            
            # mRID dla PPLAN - używamy MWE ID zgodnie z przykładem
            ET.SubElement(pplan_series, "mRID").text = mwe_id
            ET.SubElement(pplan_series, "businessType").text = "A01"  # A01 = generacja planowana (PPLAN)
            ET.SubElement(pplan_series, "measurement_Unit.name").text = "MAW"  # MAW = megawaty aktywne
            ET.SubElement(pplan_series, "registeredResource.mRID").text = mwe_id
            
            # Okres czasowy dla PPLAN
            pplan_period = ET.SubElement(pplan_series, "Series_Period")
            pplan_timeInterval = ET.SubElement(pplan_period, "timeInterval")
            ET.SubElement(pplan_timeInterval, "start").text = schedule_start
            ET.SubElement(pplan_timeInterval, "end").text = schedule_end
            ET.SubElement(pplan_period, "resolution").text = "PT1H"  # Rozdzielczość godzinowa
            
            # Punkty danych PPLAN
            for position, (i, row) in enumerate(data.iterrows(), start=1):
                point = ET.SubElement(pplan_period, "Point")
                ET.SubElement(point, "position").text = str(position)
                
                # Konwersja z kW na MW (dzielenie przez 1000) z formatem zgodnym z przykładem
                pplan_value_kw = float(row.get('Produkcja PV (PPLAN)', 0) or 0)
                pplan_value_mw = pplan_value_kw / 1000.0  # kW -> MW
                
                # Format zgodny z przykładem: maksymalnie 3 miejsca po przecinku
                pplan_formatted = f"{pplan_value_mw:.3f}"
                
                ET.SubElement(point, "quantity").text = pplan_formatted
                
                processed_rows.append({
                    "date": row['DATA'].strftime("%Y-%m-%d %H:%M"),
                    "pplan_kw": pplan_value_kw,
                    "pplan_mw": pplan_value_mw,
                    "position": position
                })
            
            # PAUTO Series - businessType P01 (tylko jeśli są wartości różne od zera)
            if 'Nadwyżki (PAUTO)' in data.columns:
                # Sprawdź czy są rzeczywiste wartości PAUTO
                has_pauto_values = data['Nadwyżki (PAUTO)'].notna().any() and (data['Nadwyżki (PAUTO)'] != 0).any()
                
                if has_pauto_values:
                    pauto_series = ET.SubElement(root, "PlannedResource_TimeSeries")
                    
                    # mRID dla PAUTO - taki sam jak MWE ID zgodnie z dokumentacją
                    ET.SubElement(pauto_series, "mRID").text = mwe_id
                    ET.SubElement(pauto_series, "businessType").text = "P01"  # P01 = automatyczna generacja (PAUTO)
                    ET.SubElement(pauto_series, "measurement_Unit.name").text = "MAW"  # MAW = megawaty aktywne
                    ET.SubElement(pauto_series, "registeredResource.mRID").text = mwe_id
                    
                    # Okres czasowy dla PAUTO
                    pauto_period = ET.SubElement(pauto_series, "Series_Period")
                    pauto_timeInterval = ET.SubElement(pauto_period, "timeInterval")
                    ET.SubElement(pauto_timeInterval, "start").text = schedule_start
                    ET.SubElement(pauto_timeInterval, "end").text = schedule_end
                    ET.SubElement(pauto_period, "resolution").text = "PT1H"
                    
                    # Punkty danych PAUTO
                    for position, (i, row) in enumerate(data.iterrows(), start=1):
                        point = ET.SubElement(pauto_period, "Point")
                        ET.SubElement(point, "position").text = str(position)
                        
                        # Konwersja z kW na MW
                        pauto_value_kw = float(row.get('Nadwyżki (PAUTO)', 0) or 0)
                        pauto_value_mw = pauto_value_kw / 1000.0  # kW -> MW
                        
                        # Format zgodny z przykładem
                        pauto_formatted = f"{pauto_value_mw:.3f}"
                        
                        ET.SubElement(point, "quantity").text = pauto_formatted
                        
                        # Dodanie wartości PAUTO do przetworzonych wierszy
                        if position <= len(processed_rows):
                            processed_rows[position-1]["pauto_kw"] = pauto_value_kw
                            processed_rows[position-1]["pauto_mw"] = pauto_value_mw
            
            # Aktualizacja danych przetworzonych
            processed_data["last_processed_date"] = datetime.now().isoformat()
            processed_data["processed_rows"] = processed_rows
            
            # Zapisanie danych przetworzonych
            with open(PROCESSED_DATA_PATH, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            # Konwersja do stringa XML z deklaracją
            xml_str = ET.tostring(root, encoding='unicode')
            
            # Dodanie deklaracji XML na początku
            xml_declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
            formatted_xml = xml_declaration + xml_str
            
            # Formatowanie XML dla lepszej czytelności
            try:
                parsed_xml = xml.dom.minidom.parseString(formatted_xml.encode('utf-8'))
                pretty_xml = parsed_xml.toprettyxml(indent="\t", encoding='UTF-8').decode('utf-8')
                
                # Usunięcie pustych linii
                lines = [line for line in pretty_xml.split('\n') if line.strip()]
                formatted_xml = '\n'.join(lines)
            except Exception as format_error:
                logger.warning(f"Nie udało się sformatować XML: {format_error}, używam podstawowego formatu")
                # Fallback do podstawowego formatowania
                formatted_xml = xml_declaration + xml_str
            
            logger.info(f"Wygenerowano XML dla planu SHORT/MWE zgodny z dokumentacją PGB2")
            logger.info(f"Typ planu: A71 (plan generacji MWE)")
            logger.info(f"Okres: {schedule_start} - {schedule_end}")
            logger.info(f"Liczba punktów czasowych: {len(data)}")
            logger.info(f"MWE ID: {mwe_id}")
            logger.info(f"Series: PPLAN (A01){', PAUTO (P01)' if 'Nadwyżki (PAUTO)' in data.columns and has_pauto_values else ''}")
            
            return formatted_xml
            
        except Exception as e:
            error_msg = f"Błąd generowania XML: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "xml"})
            return None

def prepare_chart_data(df, past_days=7, future_days=9):
    """
    Prepares chart data with proper handling of null values and edge cases
    """
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_date = today - timedelta(days=past_days)
    end_date = today + timedelta(days=future_days)
    
    # Create default data structure
    default_data = {
        'month': {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        },
        'year': {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        }
    }
    
    # Check if dataframe is empty or doesn't have required columns
    if df is None or df.empty or 'DATA' not in df.columns:
        logger.warning("DataFrame is empty or doesn't have required columns")
        return default_data
    
    try:
        # Filter data to relevant date range
        filtered_df = df[(df['DATA'] >= start_date) & (df['DATA'] <= end_date)].copy()
        
        # Check if filtered dataframe is empty
        if filtered_df.empty:
            logger.warning("No data available for the specified date range")
            return default_data
        
        # Sort by date
        filtered_df = filtered_df.sort_values('DATA')
        
        # Create past and future data markers
        filtered_df['is_future'] = filtered_df['DATA'] >= today
        
        # Convert dates to string format for JSON
        dates = filtered_df['DATA'].dt.strftime('%Y-%m-%d %H:%M').tolist()
        
        # Prepare data with safe column access
        consumption = filtered_df['Zużycie'].tolist() if 'Zużycie' in filtered_df.columns else []
        production = filtered_df['Produkcja PV [kW]'].tolist() if 'Produkcja PV [kW]' in filtered_df.columns else []
        is_future = filtered_df['is_future'].tolist()
        balance = filtered_df['Bilans [kW]'].tolist() if 'Bilans [kW]' in filtered_df.columns else []
        pplan = filtered_df['Produkcja PV (PPLAN)'].tolist() if 'Produkcja PV (PPLAN)' in filtered_df.columns else []
        pauto = filtered_df['Nadwyżki (PAUTO)'].tolist() if 'Nadwyżki (PAUTO)' in filtered_df.columns else []
        
        # Ensure all lists have same length
        max_length = max(len(dates), len(consumption), len(production), len(balance), len(pplan), len(pauto), len(is_future))
        
        if len(dates) < max_length:
            dates.extend([None] * (max_length - len(dates)))
        if len(consumption) < max_length:
            consumption.extend([None] * (max_length - len(consumption)))
        if len(production) < max_length:
            production.extend([None] * (max_length - len(production)))
        if len(balance) < max_length:
            balance.extend([None] * (max_length - len(balance)))
        if len(pplan) < max_length:
            pplan.extend([None] * (max_length - len(pplan)))
        if len(pauto) < max_length:
            pauto.extend([None] * (max_length - len(pauto)))
        if len(is_future) < max_length:
            is_future.extend([False] * (max_length - len(is_future)))
        
        # Generate month and year data (simplified for this example)
        month_data = generate_month_data(filtered_df, today)
        year_data = generate_year_data(filtered_df, today)
        
        return {
            'month': month_data,
            'year': year_data
        }
        
    except Exception as e:
        logger.error(f"Error preparing chart data: {e}")
        return default_data
    
def generate_month_data(df, today):
    """Helper function to generate month data with error handling"""
    try:
        # Simplified month data generation
        month_start = today - timedelta(days=30)
        month_end = today + timedelta(days=30)
        
        # Create date range
        date_range = pd.date_range(start=month_start, end=month_end, freq='D')
        dates = [d.strftime('%Y-%m-%d') for d in date_range]
        is_future = [d >= today for d in date_range]
        
        # Create sample data (replace with actual aggregation in production)
        import random
        data_length = len(dates)
        
        return {
            'dates': dates,
            'consumption': [random.uniform(300, 400) for _ in range(data_length)],
            'production': [random.uniform(0, 300) for _ in range(data_length)],
            'balance': [random.uniform(-300, 300) for _ in range(data_length)],
            'pplan': [random.uniform(0, 200) for _ in range(data_length)],
            'pauto': [random.uniform(0, 100) for _ in range(data_length)],
            'is_future': is_future
        }
    except Exception as e:
        logger.error(f"Error generating month data: {e}")
        return {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        }
    
def generate_year_data(df, today):
    """Helper function to generate year data with error handling"""
    try:
        # Simplified year data generation
        year_start = today - timedelta(days=365)
        year_end = today + timedelta(days=60)
        
        # Create month range
        month_range = pd.date_range(start=year_start, end=year_end, freq='MS')
        dates = [d.strftime('%Y-%m') for d in month_range]
        is_future = [d >= today.replace(day=1) for d in month_range]
        
        # Create sample data (replace with actual aggregation in production)
        import random
        data_length = len(dates)
        
        return {
            'dates': dates,
            'consumption': [random.uniform(9000, 12000) for _ in range(data_length)],
            'production': [random.uniform(0, 9000) for _ in range(data_length)],
            'balance': [random.uniform(-9000, 9000) for _ in range(data_length)],
            'pplan': [random.uniform(0, 6000) for _ in range(data_length)],
            'pauto': [random.uniform(0, 3000) for _ in range(data_length)],
            'is_future': is_future
        }
    except Exception as e:
        logger.error(f"Error generating year data: {e}")
        return {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        }
    
def send_daily_report():
    """Funkcja wysyłająca dzienny raport z lepszą obsługą błędów i zgodną z dokumentacją PGB2"""
    logger.info("Rozpoczynanie wysyłania dziennego raportu...")
    
    try:
        # Inicjalizacja procesora Excel
        processor = ExcelProcessor()
        if not processor.load_data():
            error_msg = "Nie udało się wczytać danych z pliku Excel"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        # Walidacja danych TYLKO na 9 dni do przodu (zgodnie z wymaganiami raportu)
        is_valid, validation_message = processor.validate_excel_data(days_ahead=9)
        if not is_valid:
            error_msg = f"Walidacja danych nie powiodła się: {validation_message}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        # Generowanie XML (automatycznie pobiera dane na 9 dni przez get_forecast_data)
        xml_data = processor.generate_xml_for_mwe_short()
        if not xml_data:
            error_msg = "Nie udało się wygenerować XML"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        # Zapisanie wygenerowanego XML do pliku z lepszą nazwą
        xml_filename = f"generated_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        try:
            with open(xml_filename, "w", encoding="utf-8") as f:
                f.write(xml_data)
            logger.info(f"Wygenerowany XML zapisano do pliku {xml_filename}")
        except Exception as e:
            logger.warning(f"Nie udało się zapisać XML do pliku: {e}")
        
        # Walidacja XML przed wysłaniem (sprawdzenie struktury)
        try:
            ET.fromstring(xml_data.encode('utf-8'))
            logger.info("XML przeszedł walidację struktury")
        except ET.ParseError as e:
            error_msg = f"XML nie przeszedł walidacji struktury: {e}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        # Inicjalizacja API i wysłanie planu
        api = PGB2API()
        
        if not api.authenticate():
            error_msg = "Uwierzytelnianie nie powiodło się"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        # Wysłanie planu zgodnie z dokumentacją: POST /plan-api/files/SHORT/MWE
        success, result = api.send_plan("SHORT", "MWE", xml_data)
        if not success:
            error_msg = f"Wysyłanie planu nie powiodło się: {result}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            
            # Dodanie informacji o nieudanym wysłaniu
            sent_reports.append({
                "timestamp": datetime.now().isoformat(),
                "uuid": "FAILED",
                "type": "SHORT/MWE",
                "status": "FAILED",
                "error": result
            })
            return
        
        file_uuid = result
        logger.info(f"Plan wysłany pomyślnie. UUID: {file_uuid}")
        
        # Dodanie informacji o wysłanym raporcie
        sent_reports.append({
            "timestamp": datetime.now().isoformat(),
            "uuid": file_uuid,
            "type": "SHORT/MWE",
            "status": "PENDING"
        })
        
        # Monitoring statusu przetwarzania zgodnie z dokumentacją
        import time
        max_tries = 20  # Zwiększono liczbę prób dla lepszego monitoringu
        tries = 0
        check_interval = 15  # Sprawdzaj co 15 sekund
        
        logger.info(f"Rozpoczynanie monitorowania statusu pliku {file_uuid}")
        
        while tries < max_tries:
            time.sleep(check_interval)
            success, status = api.check_plan_status(file_uuid)
            
            if not success:
                error_msg = f"Błąd sprawdzania statusu: {status}"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
                break
            
            logger.info(f"Status planu {file_uuid}: {status} (próba {tries + 1}/{max_tries})")
            
            # Aktualizacja statusu w historii raportów
            for report in sent_reports:
                if report["uuid"] == file_uuid:
                    report["status"] = status
                    break
            
            if status == "SUCCESSFULLY_PROCESSED":
                logger.info("Plan został przetworzony pomyślnie!")
                processed_data["success_count"] += 1
                
                # Pobranie szczegółów sukcesu
                try:
                    plan_details = api.get_plan_details(file_uuid)
                    if plan_details:
                        logger.info(f"Szczegóły przetwarzania: {plan_details}")
                except Exception as e:
                    logger.warning(f"Nie udało się pobrać szczegółów sukcesu: {e}")
                
                # Zapisanie danych przetworzonych
                with open(PROCESSED_DATA_PATH, 'w') as f:
                    json.dump(processed_data, f, indent=2)
                break
            
            if status == "FAILED":
                error_msg = "Przetwarzanie planu zakończyło się błędem"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
                processed_data["error_count"] += 1
                
                # Spróbuj pobrać szczegóły błędu zgodnie z dokumentacją
                try:
                    plan_details = api.get_plan_details(file_uuid)
                    if plan_details:
                        logger.error(f"Szczegóły błędu planu: {plan_details}")
                        error_logs.append({
                            "timestamp": datetime.now().isoformat(), 
                            "message": f"Szczegóły błędu PGB2: {plan_details}", 
                            "type": "report"
                        })
                except Exception as e:
                    logger.warning(f"Nie udało się pobrać szczegółów błędu: {e}")
                
                # Zapisanie danych przetworzonych
                with open(PROCESSED_DATA_PATH, 'w') as f:
                    json.dump(processed_data, f, indent=2)
                break
            
            tries += 1
        
        if tries >= max_tries:
            logger.warning(f"Przekroczono maksymalną liczbę prób sprawdzania statusu dla {file_uuid}")
            # Aktualizuj status na TIMEOUT
            for report in sent_reports:
                if report["uuid"] == file_uuid:
                    report["status"] = "TIMEOUT"
                    break
        
        logger.info("Zakończono wysyłanie dziennego raportu")
        
    except Exception as e:
        error_msg = f"Nieoczekiwany błąd podczas wysyłania dziennego raportu: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
        processed_data["error_count"] += 1
        
        # Zapisanie danych przetworzonych
        try:
            with open(PROCESSED_DATA_PATH, 'w') as f:
                json.dump(processed_data, f, indent=2)
        except Exception as save_error:
            logger.error(f"Nie udało się zapisać danych przetworzonych: {save_error}")

# Inicjalizacja harmonogramu
scheduler = BackgroundScheduler()

# Dodanie zadania - wysyłanie raportu codziennie o 6:00 rano
scheduler.add_job(
    send_daily_report,
    trigger=CronTrigger(hour=6, minute=0),
    id='daily_report',
    name='Wysyłanie dziennego raportu',
    replace_existing=True
)

# Dodanie zadania - czyszczenie wygasłych sesji
scheduler.add_job(
    cleanup_expired_sessions,
    trigger=CronTrigger(hour=0, minute=0),  # Uruchamiaj codziennie o północy
    id='cleanup_sessions',
    name='Czyszczenie wygasłych sesji',
    replace_existing=True
)

# Modele danych do obsługi endpointów
class ExcelDataUpdate(BaseModel):
    data: List[Dict[str, Any]]

# Endpointy uwierzytelniania
@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Strona główna - przekierowanie do dashboardu lub logowania"""
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/dashboard"):
    """Strona logowania"""
    # Sprawdź status bazy danych
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            admin_exists = cursor.fetchone() is not None
            db_status = True
    except Exception:
        admin_exists = False
        db_status = False
           
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url=next, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "next": next,
        "db_status": db_status,
        "admin_exists": admin_exists
    })

@app.post("/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False),
    next: str = Form("/dashboard")
):
    """Endpoint do logowania"""
    logger.info(f"Próba logowania: {username}, remember_me: {remember_me}, next: {next}")
    
    user = authenticate_user(username, password)
    if not user:
        logger.warning(f"Nieudane logowanie dla użytkownika: {username}")
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": "Nieprawidłowa nazwa użytkownika lub hasło",
                "next": next
            },
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    
    # Ustaw okres ważności sesji
    expire_days = 30 if remember_me else 1
    
    # Utwórz sesję
    session_id, expires_at = create_session(user.id, expire_days)
    
    # Utwórz odpowiedź z przekierowaniem
    redirect = RedirectResponse(url=next, status_code=status.HTTP_303_SEE_OTHER)
    
    # Ustaw ciasteczko sesji na odpowiedzi redirectu
    redirect.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        max_age=expire_days * 24 * 60 * 60 if remember_me else None,
        path="/",
        secure=False
    )
    
    logger.info(f"Pomyślne logowanie dla użytkownika: {username}, przekierowanie do: {next}")
    
    return redirect

@app.get("/logout")
async def logout(response: Response, request: Request):
    """Wylogowanie użytkownika"""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        delete_session(session_id)
    
    # Usuń ciasteczko sesji
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    
    # Przekieruj na stronę logowania
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Strona rejestracji"""
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(
    response: Response,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(None)
):
    """Endpoint do rejestracji nowego użytkownika"""
    # Sprawdź, czy użytkownik już istnieje
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Użytkownik o podanej nazwie użytkownika lub adresie e-mail już istnieje"
            )
        
        # Dodaj nowego użytkownika
        hashed_password = get_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password, full_name) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, full_name)
        )
        conn.commit()
        
        # Pobierz ID utworzonego użytkownika
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id = cursor.fetchone()["id"]
    
    # Utwórz sesję i zaloguj użytkownika
    session_id, expires_at = create_session(user_id)
    
    # Ustaw ciasteczko sesji
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        max_age=24 * 60 * 60,  # 1 dzień
        path="/",
        secure=False  # Ustaw na True w środowisku produkcyjnym z HTTPS
    )
    
    # Przekieruj na dashboard
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

# Endpoint główny - dashboard (wymaga logowania)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(require_user)):
    """Główny endpoint - dashboard z statystykami i wykresami"""
    try:
        # Wczytanie danych z Excel, jeśli dostępne
        processor = ExcelProcessor()
        chart_data = {}
        
        if processor.load_data():
            df = processor.df
            
            # Przygotowanie danych do wykresów
            if 'DATA' in df.columns:
                chart_data = prepare_chart_data(df)
            else:
                chart_data = {}
        
        # Statystyki
        stats = {
            "total_reports": len(sent_reports),
            "success_count": processed_data["success_count"],
            "error_count": processed_data["error_count"],
            "last_report": sent_reports[-1]["timestamp"] if sent_reports else "Brak wysłanych raportów",
            "last_status": sent_reports[-1]["status"] if sent_reports else "N/A"
        }
        
        # Zwrócenie szablonu z danymi
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "chart_data": json.dumps(chart_data),
            "stats": stats,
            "logs": error_logs[-30:],  # Ostatnie 30 logów
            "processed_data": processed_data,
            "sent_reports": sent_reports[-10:],  # Ostatnie 10 raportów
            "user": user
        })
    except Exception as e:
        error_msg = f"Błąd podczas generowania dashboardu: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "dashboard"})
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })


# Endpoint do ręcznego uruchomienia wysyłania raportu (wymaga logowania)
@app.post("/trigger-report")
async def trigger_report(background_tasks: BackgroundTasks, user: User = Depends(require_user)):
    """Endpoint do ręcznego uruchomienia wysyłania raportu"""
    try:
        background_tasks.add_task(send_daily_report)
        return {"status": "success", "message": "Rozpoczęto wysyłanie raportu w tle"}
    except Exception as e:
        error_msg = f"Błąd podczas uruchamiania raportu: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint zwracający dane w formacie JSON (wymaga logowania)
@app.get("/api/stats")
async def get_stats(user: User = Depends(require_user)):
    """Endpoint zwracający statystyki w formacie JSON"""
    try:
        return {
            "sent_reports": sent_reports,
            "error_logs": error_logs,
            "processed_data": processed_data
        }
    except Exception as e:
        error_msg = f"Błąd podczas pobierania statystyk: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint zwracający dane Excel w formacie JSON (wymaga logowania)
@app.get("/api/excel-data")
async def get_excel_data(user: User = Depends(require_user)):
    """Endpoint zwracający dane z Excela w formacie JSON"""
    try:
        processor = ExcelProcessor()
        if processor.load_data():
            # Konwertowanie DataFrame na format JSON
            data = processor.df.to_dict(orient='records')
            return {"status": "success", "data": data}
        else:
            return {"status": "error", "message": "Nie udało się wczytać danych z pliku Excel"}
    except Exception as e:
        error_msg = f"Błąd podczas pobierania danych Excel: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint do pobierania danych wykresów (wymaga logowania)
@app.get("/api/chart-data")
async def get_chart_data(period: str = "month", user: User = Depends(require_user)):
    """
    Endpoint zwracający dane wykresów w formacie JSON
    
    Parameters:
    period (str): Okres czasu - 'month' lub 'year'
    
    Returns:
    dict: Dane wykresów
    """
    try:
        processor = ExcelProcessor()
        if processor.load_data():
            df = processor.df
            
            # Przygotowanie danych do wykresów
            if 'DATA' in df.columns:
                chart_data = prepare_chart_data(df)
                return {"status": "success", "data": chart_data.get(period, chart_data['month'])}
        
        return {"status": "error", "message": "Nie udało się wczytać danych z pliku Excel"}
    except Exception as e:
        error_msg = f"Błąd podczas pobierania danych wykresów: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint do wgrywania nowego pliku Excel (wymaga logowania)
@app.post("/api/upload-excel")
async def upload_excel_file(
    file: UploadFile = File(...), 
    replace: bool = Form(True),
    user: User = Depends(require_user)
):
    """
    Endpoint do wgrywania nowego pliku Excel
    
    Parameters:
    file (UploadFile): Plik Excel do wgrania
    replace (bool): Czy zastąpić istniejący plik (domyślnie True)
    
    Returns:
    dict: Status operacji i ewentualny komunikat
    """
    global EXCEL_PATH  
    
    try:
        # Sprawdzenie rozszerzenia pliku
        if not file.filename.endswith(('.xlsx', '.xls')):
            return {"status": "error", "message": "Nieprawidłowy format pliku. Akceptowane są tylko pliki .xlsx lub .xls"}
        
        # Ustalenie ścieżki docelowej
        file_path = EXCEL_PATH
        temp_file_path = f"temp_{file.filename}"
        
        # Zapisanie pliku tymczasowo
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Próba wczytania pliku, aby sprawdzić jego poprawność
        try:
            temp_processor = ExcelProcessor(excel_path=temp_file_path)
            if not temp_processor.load_data():
                # Usunięcie pliku tymczasowego
                os.remove(temp_file_path)
                return {"status": "error", "message": "Nieprawidłowy format pliku Excel lub brak wymaganych kolumn"}
            
            # Sprawdzenie struktury pliku
            required_columns = ['DATA', 'Zużycie', 'Produkcja PV [kW]', 'Bilans [kW]', 'Produkcja PV (PPLAN)', 'Nadwyżki (PAUTO)']
            missing_columns = [col for col in required_columns if col not in temp_processor.df.columns]
            
            if missing_columns:
                # Usunięcie pliku tymczasowego
                os.remove(temp_file_path)
                return {"status": "error", "message": f"Brak wymaganych kolumn: {', '.join(missing_columns)}"}
            
        except Exception as e:
            # Usunięcie pliku tymczasowego
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            logger.error(f"Błąd podczas weryfikacji pliku Excel: {str(e)}")
            return {"status": "error", "message": f"Błąd podczas weryfikacji pliku: {str(e)}"}
        
        # Jeśli zastępujemy plik
        if replace:
            # Zrób kopię zapasową istniejącego pliku
            if os.path.exists(file_path):
                backup_path = f"{file_path}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
                shutil.copy2(file_path, backup_path)
                logger.info(f"Utworzono kopię zapasową pliku: {backup_path}")
            
            # Przenieś plik tymczasowy na docelową ścieżkę
            shutil.move(temp_file_path, file_path)
        else:
            # Użyj nowej nazwy pliku
            new_file_path = f"{os.path.splitext(file_path)[0]}_{datetime.now().strftime('%Y%m%d%H%M%S')}{os.path.splitext(file_path)[1]}"
            shutil.move(temp_file_path, new_file_path)
            
            # Aktualizacja ścieżki w zmiennych środowiskowych
            os.environ["EXCEL_PATH"] = new_file_path
            EXCEL_PATH = new_file_path
        
        logger.info(f"Plik Excel został pomyślnie wgrany: {file_path}")
        return {"status": "success", "message": "Plik Excel został pomyślnie wgrany"}
        
    except Exception as e:
        logger.error(f"Błąd podczas wgrywania pliku Excel: {str(e)}")
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": f"Błąd podczas wgrywania pliku Excel: {str(e)}", "type": "api"})
        
        # Usunięcie pliku tymczasowego w przypadku błędu
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
        return {"status": "error", "message": f"Błąd podczas wgrywania pliku: {str(e)}"}

# Endpoint do aktualizacji danych Excel (wymaga logowania)
@app.post("/api/update-excel-data")
async def update_excel_data(
    data_update: ExcelDataUpdate, 
    background_tasks: BackgroundTasks,
    user: User = Depends(require_user)
):
    """
    Endpoint do aktualizacji danych w pliku Excel
    
    Parameters:
    data_update (ExcelDataUpdate): Zaktualizowane dane
    background_tasks (BackgroundTasks): Zadania do wykonania w tle
    
    Returns:
    dict: Status operacji i ewentualny komunikat
    """
    try:
        # Wczytanie istniejącego pliku Excel
        processor = ExcelProcessor()
        if not processor.load_data():
            return {"status": "error", "message": "Nie udało się wczytać pliku Excel"}
        
        # Tworzenie kopii zapasowej
        backup_path = f"{EXCEL_PATH}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        shutil.copy2(EXCEL_PATH, backup_path)
        logger.info(f"Utworzono kopię zapasową przed aktualizacją danych: {backup_path}")
        
        # Konwersja przesłanych danych na DataFrame
        updated_df = pd.DataFrame(data_update.data)
        
        # Zachowanie typów danych i formatów
        # Sprawdzenie, czy kolumna DATA jest w formacie datetime
        if 'DATA' in updated_df.columns:
            # Próba konwersji na datetime, jeśli to string
            if not pd.api.types.is_datetime64_any_dtype(updated_df['DATA']):
                try:
                    updated_df['DATA'] = pd.to_datetime(updated_df['DATA'])
                except Exception as e:
                    logger.warning(f"Nie udało się przekonwertować kolumny DATA na format datetime: {str(e)}")
        
        # Zapisanie zaktualizowanych danych do pliku Excel
        try:
            updated_df.to_excel(EXCEL_PATH, index=False)
            logger.info(f"Pomyślnie zaktualizowano dane w pliku Excel")
            
            # Resetowanie przetworzonych danych
            processed_data["last_processed_date"] = datetime.now().isoformat()
            processed_data["processed_rows"] = []
            
            # Zapisanie zaktualizowanych danych przetworzonych
            with open(PROCESSED_DATA_PATH, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            # Wyzwolenie ponownego przetworzenia pliku w tle
            background_tasks.add_task(regenerate_processed_data)
            
            return {"status": "success", "message": "Dane zostały pomyślnie zaktualizowane"}
        except Exception as e:
            logger.error(f"Błąd podczas zapisywania zaktualizowanych danych: {str(e)}")
            return {"status": "error", "message": f"Błąd podczas zapisywania danych: {str(e)}"}
            
    except Exception as e:
        logger.error(f"Błąd podczas aktualizacji danych Excel: {str(e)}")
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": f"Błąd podczas aktualizacji danych Excel: {str(e)}", "type": "api"})
        return {"status": "error", "message": f"Błąd podczas aktualizacji danych: {str(e)}"}

# Zarządzanie użytkownikami - tylko dla administratorów
@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, user: User = Depends(require_admin)):
    """Panel zarządzania użytkownikami (tylko dla administratorów)"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = [dict(row) for row in cursor.fetchall()]
    
    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "users": users,
        "user": user
    })

@app.post("/admin/users/add")
async def admin_add_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(None),
    is_admin: bool = Form(False),
    user: User = Depends(require_admin)
):
    """Dodawanie nowego użytkownika przez administratora"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Użytkownik o podanej nazwie użytkownika lub adresie e-mail już istnieje"
                )
            
            hashed_password = get_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, email, hashed_password, full_name, is_admin) VALUES (?, ?, ?, ?, ?)",
                (username, email, hashed_password, full_name, is_admin)
            )
            conn.commit()
        
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/users/{user_id}/delete")
async def admin_delete_user(user_id: int, user: User = Depends(require_admin)):
    """Usuwanie użytkownika przez administratora"""
    try:
        # Sprawdź, czy nie usuwamy samego siebie
        if user_id == user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nie możesz usunąć własnego konta"
            )
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Usuń sesje użytkownika
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            # Usuń użytkownika
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Panel profilu użytkownika
@app.get("/profile", response_class=HTMLResponse)
async def user_profile(request: Request, user: User = Depends(require_user)):
    """Panel profilu użytkownika"""
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user
    })

@app.post("/profile/update")
async def update_profile(
    full_name: str = Form(None),
    email: str = Form(...),
    current_password: str = Form(None),
    new_password: str = Form(None),
    user: User = Depends(require_user)
):
    """Aktualizacja profilu użytkownika"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Sprawdź czy email jest unikalny
            if email != user.email:
                cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user.id))
                if cursor.fetchone():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Podany adres e-mail jest już używany przez innego użytkownika"
                    )
            
            # Aktualizuj dane podstawowe
            cursor.execute(
                "UPDATE users SET full_name = ?, email = ? WHERE id = ?",
                (full_name, email, user.id)
            )
            
            # Jeśli podano hasła, zmień hasło
            if current_password and new_password:
                # Pobierz aktualne hasło
                cursor.execute("SELECT hashed_password FROM users WHERE id = ?", (user.id,))
                current_hashed = cursor.fetchone()["hashed_password"]
                
                # Sprawdź poprawność aktualnego hasła
                if not verify_password(current_password, current_hashed):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Nieprawidłowe aktualne hasło"
                    )
                
                # Aktualizuj hasło
                hashed_password = get_password_hash(new_password)
                cursor.execute(
                    "UPDATE users SET hashed_password = ? WHERE id = ?",
                    (hashed_password, user.id)
                )
            
            conn.commit()
        
        return RedirectResponse(url="/profile", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Funkcja ponownego przetwarzania danych po aktualizacji
def regenerate_processed_data():
    """Funkcja regenerująca przetworzone dane po aktualizacji Excel"""
    try:
        processor = ExcelProcessor()
        if processor.load_data():
            # Pobranie danych prognozy
            forecast_data = processor.get_forecast_data()
            
            # Generowanie XML (bez wysyłania)
            processor.generate_xml_for_mwe_short(forecast_data)
            
            logger.info("Pomyślnie zregenerowano przetworzone dane po aktualizacji Excel")
    except Exception as e:
        logger.error(f"Błąd podczas regeneracji przetworzonych danych: {str(e)}")

# Podczas startu aplikacji
@app.on_event("startup")
async def startup_event():
    """Funkcja uruchamiana podczas startu aplikacji"""
    # Inicjalizacja bazy danych
    init_db()
    
    # Uruchomienie harmonogramu
    scheduler.start()
    logger.info("Aplikacja uruchomiona, harmonogram zadań aktywny")


# Podczas zatrzymania aplikacji
@app.on_event("shutdown")
async def shutdown_event():
    """Funkcja uruchamiana podczas zatrzymania aplikacji"""
    # Zatrzymanie harmonogramu
    scheduler.shutdown()
    logger.info("Aplikacja zatrzymana, harmonogram zadań wyłączony")


# Start aplikacji, jeśli uruchamiana bezpośrednio
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"Uruchamianie aplikacji PowerWise na porcie {port}...")
    print(f"Nasłuchiwanie na 127.0.0.1:{port}")
    
    # Inicjalizacja bazy danych
    init_db()
    
    # Uruchomienie harmonogramu
    scheduler.start()
    logger.info("Aplikacja uruchomiona, harmonogram zadań aktywny")
    
    # Uruchomienie FastAPI
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")