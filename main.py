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
app = FastAPI(title="PGB2 Report Sender", description="Aplikacja do automatycznego wysyłania raportów do systemu PGB2")

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
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            return False
        
        user = dict(user_data)
        if not verify_password(password, user["hashed_password"]):
            return False
        
        return User(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            full_name=user["full_name"],
            is_admin=bool(user["is_admin"])
        )

def create_session(user_id: int, expire_days: int = SESSION_EXPIRE_DAYS):
    session_id = secrets.token_hex(32)
    expires_at = datetime.now() + timedelta(days=expire_days)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
            (session_id, user_id, expires_at)
        )
        conn.commit()
    
    return session_id, expires_at

def get_user_from_session(session_id: str):
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
            return None
        
        user_data = dict(result)
        return User(
            id=user_data["id"],
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"],
            is_admin=bool(user_data["is_admin"])
        )

def delete_session(session_id: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return cursor.rowcount > 0

# Middleware do autoryzacji
async def get_current_user(request: Request) -> Optional[User]:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    
    return get_user_from_session(session_id)

# Zależność do wymagania zalogowanego użytkownika
async def require_user(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login?next=" + request.url.path, status_code=status.HTTP_302_FOUND)
    return user

# Zależność do wymagania uprawnień administratora
async def require_admin(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login?next=" + request.url.path, status_code=status.HTTP_302_FOUND)
    if not user.is_admin:
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
        Wysłanie planu do API PGB2
        
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
        
        files = {
            'file': ('plan.xml', xml_data, 'application/xml')
        }
        
        try:
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
            
            result = response.json()
            if "error" in result and result["error"]:
                error_msg = f"Błąd wysyłania planu: {result['message']}"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "send"})
                return False, result["message"]
                
            file_uuid = result["message"]
            logger.info(f"Plan wysłany pomyślnie. UUID: {file_uuid}")
            return True, file_uuid
            
        except Exception as e:
            error_msg = f"Błąd wysyłania planu: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "send"})
            if hasattr(e, 'response') and e.response:
                logger.error(f"Odpowiedź serwera: {e.response.text}")
            return False, str(e)

    def check_plan_status(self, file_uuid):
        """
        Sprawdzenie statusu przetwarzania planu
        
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
            if "error" in result and result["error"]:
                error_msg = f"Błąd sprawdzania statusu: {result['message']}"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "status"})
                return False, result["message"]
                
            status = result["message"]
            logger.info(f"Status planu: {status}")
            return True, status
            
        except Exception as e:
            error_msg = f"Błąd sprawdzania statusu: {str(e)}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "status"})
            if hasattr(e, 'response') and e.response:
                logger.error(f"Odpowiedź serwera: {e.response.text}")
            return False, str(e)


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
        Generuje XML dla planu krótkoterminowego MWE
        
        Parametry:
        data (DataFrame): Opcjonalnie dataframe z danymi do przetworzenia
        
        Zwraca:
        str: Wygenerowany XML
        """
        if data is None:
            data = self.get_forecast_data()
            
        if data is None or data.empty:
            error_msg = "Brak danych do wygenerowania XML"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "xml"})
            return None
            
        try:
            # ID dokumentu z datą i godziną
            document_id = f"ID-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Data i czas dokumentu
            doc_datetime = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Tworzenie korzenia XML
            root = ET.Element("PlanDocument")
            
            # Sekcja identyfikacji dokumentu
            doc_ident = ET.SubElement(root, "DocumentIdentification")
            ET.SubElement(doc_ident, "DocumentType").text = "A71"  # Typ planu generacji dla MWE
            ET.SubElement(doc_ident, "DocumentIdentification").text = document_id
            ET.SubElement(doc_ident, "DocumentDateTime").text = doc_datetime
            
            # Sekcja TimeSeries
            time_series = ET.SubElement(root, "TimeSeries")
            
            # ID modułu wytwarzania energii (MWE) - pobieramy z env lub używamy wartości domyślnej
            mwe_id = os.getenv("MWE_ID", "_8eda81ec-90eb-46f9-abc8-7071ba98a5b1")
            ET.SubElement(time_series, "mRID").text = mwe_id
            
            # Określenie okresu czasowego
            period = ET.SubElement(time_series, "Period")
            
            # Zakres czasowy
            time_interval = ET.SubElement(period, "TimeInterval")
            
            # Znajdź minimalną i maksymalną datę w danych
            min_date = data['DATA'].min()
            max_date = data['DATA'].max()
            
            # Formatowanie dat do ISO
            start_time = min_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_time = (max_date + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")  # +1h dla końca okresu
            
            ET.SubElement(time_interval, "Start").text = start_time
            ET.SubElement(time_interval, "End").text = end_time
            
            # Rozdzielczość - godzinowa
            ET.SubElement(period, "Resolution").text = "PT1H"
            
            # Punkty danych
            # Zakładamy, że dane są już posortowane według daty
            data = data.sort_values('DATA')
            
            # Zapisz informacje o przetworzonych wierszach
            processed_rows = []
            
            for i, row in data.iterrows():
                point = ET.SubElement(period, "Point")
                ET.SubElement(point, "Position").text = str(i + 1)
                
                # Przyjmujemy, że "Produkcja PV (PPLAN)" to wartość planowana, a "Nadwyżki (PAUTO)" to autogeneracja
                pplan_value = row.get('Produkcja PV (PPLAN)', 0)
                pauto_value = row.get('Nadwyżki (PAUTO)', 0)
                
                # Dodajemy wartości PPLAN i PAUTO jako atrybuty
                ET.SubElement(point, "PPLAN").text = str(pplan_value)
                ET.SubElement(point, "PAUTO").text = str(pauto_value)
                
                # Dodanie przetworzonych wierszy do historii
                processed_rows.append({
                    "date": row['DATA'].strftime("%Y-%m-%d %H:%M"),
                    "pplan": pplan_value,
                    "pauto": pauto_value
                })
            
            # Aktualizacja danych przetworzonych
            processed_data["last_processed_date"] = datetime.now().isoformat()
            processed_data["processed_rows"] = processed_rows
            
            # Zapisanie danych przetworzonych
            with open(PROCESSED_DATA_PATH, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            # Konwersja do stringa
            xml_str = ET.tostring(root, encoding='utf-8')
            
            # Formatowanie XML do bardziej czytelnej postaci
            parsed_xml = xml.dom.minidom.parseString(xml_str)
            pretty_xml = parsed_xml.toprettyxml(indent="  ")
            
            logger.info("Wygenerowano XML dla planu SHORT/MWE")
            return pretty_xml
            
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
        return default_data  # Fixed: was default_datas
    
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
    """Funkcja wysyłająca dzienny raport"""
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
        
        # Generowanie XML
        xml_data = processor.generate_xml_for_mwe_short()
        if not xml_data:
            error_msg = "Nie udało się wygenerować XML"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        # Zapisanie wygenerowanego XML do pliku (opcjonalnie)
        xml_filename = f"generated_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        with open(xml_filename, "w", encoding="utf-8") as f:
            f.write(xml_data)
        logger.info(f"Wygenerowany XML zapisano do pliku {xml_filename}")
        
        # Inicjalizacja API i wysłanie planu
        api = PGB2API()
        
        if not api.authenticate():
            error_msg = "Uwierzytelnianie nie powiodło się"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        success, result = api.send_plan("SHORT", "MWE", xml_data)
        if not success:
            error_msg = f"Wysyłanie planu nie powiodło się: {result}"
            logger.error(error_msg)
            error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
            processed_data["error_count"] += 1
            return
        
        file_uuid = result
        logger.info(f"Plan wysłany pomyślnie. UUID: {file_uuid}")
        
        # Dodanie informacji o wysłanym raporcie
        sent_reports.append({
            "timestamp": datetime.now().isoformat(),
            "uuid": file_uuid,
            "type": "SHORT/MWE",
            "status": "Wysłany"
        })
        
        # Monitoring statusu przetwarzania
        import time
        max_tries = 10
        tries = 0
        
        while tries < max_tries:
            time.sleep(5)  # Czekaj 5 sekund przed kolejnym sprawdzeniem
            success, status = api.check_plan_status(file_uuid)
            
            if not success:
                error_msg = f"Błąd sprawdzania statusu: {status}"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
                break
            
            # Aktualizacja statusu w historii raportów
            for report in sent_reports:
                if report["uuid"] == file_uuid:
                    report["status"] = status
            
            if status == "SUCCESSFULLY_PROCESSED":
                logger.info("Plan został przetworzony pomyślnie!")
                processed_data["success_count"] += 1
                # Zapisanie danych przetworzonych
                with open(PROCESSED_DATA_PATH, 'w') as f:
                    json.dump(processed_data, f, indent=2)
                break
            
            if status == "FAILED":
                error_msg = "Przetwarzanie planu zakończyło się błędem"
                logger.error(error_msg)
                error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
                processed_data["error_count"] += 1
                # Zapisanie danych przetworzonych
                with open(PROCESSED_DATA_PATH, 'w') as f:
                    json.dump(processed_data, f, indent=2)
                break
            
            logger.info(f"Status planu: {status}. Oczekiwanie...")
            tries += 1
        
        logger.info("Zakończono wysyłanie dziennego raportu")
        
    except Exception as e:
        error_msg = f"Błąd podczas wysyłania dziennego raportu: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "report"})
        processed_data["error_count"] += 1
        # Zapisanie danych przetworzonych
        with open(PROCESSED_DATA_PATH, 'w') as f:
            json.dump(processed_data, f, indent=2)


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
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url=next, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request, "next": next})

@app.post("/login")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    remember_me: bool = Form(False),
    next: str = Form("/dashboard")
):
    """Endpoint do logowania"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowa nazwa użytkownika lub hasło",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Ustaw okres ważności sesji
    expire_days = 30 if remember_me else 1
    
    # Utwórz sesję
    session_id, expires_at = create_session(user.id, expire_days)
    
    # Ustaw ciasteczko sesji
    cookie_expiry = expires_at if remember_me else None  # None = cookie sesyjne
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        max_age=expire_days * 24 * 60 * 60 if remember_me else None,
        expires=cookie_expiry,
        secure=False  # Ustaw na True w środowisku produkcyjnym z HTTPS
    )
    
    # Przekieruj do żądanej strony lub na dashboard
    return RedirectResponse(url=next, status_code=status.HTTP_302_FOUND)

@app.get("/logout")
async def logout(response: Response, request: Request):
    """Wylogowanie użytkownika"""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        delete_session(session_id)
    
    # Usuń ciasteczko sesji
    response.delete_cookie(SESSION_COOKIE_NAME)
    
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
        secure=False  # Ustaw na True w środowisku produkcyjnym z HTTPS
    )
    
    # Przekieruj na dashboard
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

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
    print(f"Uruchamianie aplikacji PGB2 Report Sender na porcie {port}...")
    print(f"Nasłuchiwanie na 127.0.0.1:{port}")
    
    # Inicjalizacja bazy danych
    init_db()
    
    # Uruchomienie harmonogramu
    scheduler.start()
    logger.info("Aplikacja uruchomiona, harmonogram zadań aktywny")
    
    # Uruchomienie FastAPI
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")