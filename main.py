import os
import sys
import json
import logging
import pandas as pd
import requests
from datetime import datetime, timedelta
import xml.dom.minidom
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel
from dotenv import load_dotenv
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio

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
EXCEL_PATH = os.getenv("EXCEL_PATH", "SOGLbazaraportTAURON.xlsx")

# Historia wysłanych raportów
sent_reports = []

# Historia błędów
error_logs = []

# Ścieżka do zapisywania przetworzonych danych
PROCESSED_DATA_PATH = "processed_data.json"

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

@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Główny endpoint - strona główna"""
    return templates.TemplateResponse("index.html", {"request": request})

# Endpoint główny - dashboard
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Główny endpoint - dashboard z statystykami i wykresami"""
    try:
        # Wczytanie danych z Excel, jeśli dostępne
        processor = ExcelProcessor()
        if processor.load_data():
            df = processor.df
            
            # Przygotowanie danych do wykresów
            if 'DATA' in df.columns and 'Zużycie' in df.columns and 'Produkcja PV [kW]' in df.columns:
                # Wykres zużycia i produkcji
                consumption_production_fig = make_subplots(specs=[[{"secondary_y": True}]])
                
                consumption_production_fig.add_trace(
                    go.Scatter(x=df['DATA'], y=df['Zużycie'], name="Zużycie", line=dict(color="blue")),
                    secondary_y=False
                )
                
                consumption_production_fig.add_trace(
                    go.Scatter(x=df['DATA'], y=df['Produkcja PV [kW]'], name="Produkcja PV", line=dict(color="green")),
                    secondary_y=False
                )
                
                consumption_production_fig.update_layout(
                    title="Zużycie i Produkcja PV",
                    xaxis_title="Data",
                    yaxis_title="kW",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                
                consumption_production_chart = consumption_production_fig.to_html(full_html=False)
                
                # Wykres bilansu
                if 'Bilans [kW]' in df.columns:
                    balance_fig = go.Figure()
                    
                    balance_fig.add_trace(
                        go.Scatter(x=df['DATA'], y=df['Bilans [kW]'], name="Bilans", line=dict(color="red"))
                    )
                    
                    balance_fig.update_layout(
                        title="Bilans energii",
                        xaxis_title="Data",
                        yaxis_title="kW",
                        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                    )
                    
                    balance_chart = balance_fig.to_html(full_html=False)
                else:
                    balance_chart = "<p>Brak danych bilansu</p>"
                
                # Wykres PPLAN i PAUTO
                if 'Produkcja PV (PPLAN)' in df.columns and 'Nadwyżki (PAUTO)' in df.columns:
                    pplan_pauto_fig = make_subplots(specs=[[{"secondary_y": True}]])
                    
                    pplan_pauto_fig.add_trace(
                        go.Scatter(x=df['DATA'], y=df['Produkcja PV (PPLAN)'], name="PPLAN", line=dict(color="purple")),
                        secondary_y=False
                    )
                    
                    pplan_pauto_fig.add_trace(
                        go.Scatter(x=df['DATA'], y=df['Nadwyżki (PAUTO)'], name="PAUTO", line=dict(color="orange")),
                        secondary_y=False
                    )
                    
                    pplan_pauto_fig.update_layout(
                        title="PPLAN i PAUTO",
                        xaxis_title="Data",
                        yaxis_title="kW",
                        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                    )
                    
                    pplan_pauto_chart = pplan_pauto_fig.to_html(full_html=False)
                else:
                    pplan_pauto_chart = "<p>Brak danych PPLAN i PAUTO</p>"
            else:
                consumption_production_chart = "<p>Brak wymaganych kolumn w danych</p>"
                balance_chart = "<p>Brak wymaganych kolumn w danych</p>"
                pplan_pauto_chart = "<p>Brak wymaganych kolumn w danych</p>"
        else:
            consumption_production_chart = "<p>Nie udało się wczytać danych z pliku Excel</p>"
            balance_chart = "<p>Nie udało się wczytać danych z pliku Excel</p>"
            pplan_pauto_chart = "<p>Nie udało się wczytać danych z pliku Excel</p>"
        
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
            "consumption_production_chart": consumption_production_chart,
            "balance_chart": balance_chart,
            "pplan_pauto_chart": pplan_pauto_chart,
            "stats": stats,
            "logs": error_logs[-30:],  # Ostatnie 30 logów
            "processed_data": processed_data,
            "sent_reports": sent_reports[-10:]  # Ostatnie 10 raportów
        })
    except Exception as e:
        error_msg = f"Błąd podczas generowania dashboardu: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "dashboard"})
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })


# Endpoint do ręcznego uruchomienia wysyłania raportu
@app.post("/trigger-report")
async def trigger_report(background_tasks: BackgroundTasks):
    """Endpoint do ręcznego uruchomienia wysyłania raportu"""
    try:
        background_tasks.add_task(send_daily_report)
        return {"status": "success", "message": "Rozpoczęto wysyłanie raportu w tle"}
    except Exception as e:
        error_msg = f"Błąd podczas uruchamiania raportu: {str(e)}"
        logger.error(error_msg)
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint zwracający dane w formacie JSON
@app.get("/api/stats")
async def get_stats():
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


# Endpoint zwracający dane Excel w formacie JSON
@app.get("/api/excel-data")
async def get_excel_data():
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


# Podczas startu aplikacji
@app.on_event("startup")
async def startup_event():
    """Funkcja uruchamiana podczas startu aplikacji"""
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
    
    # Uruchomienie harmonogramu
    scheduler.start()
    logger.info("Aplikacja uruchomiona, harmonogram zadań aktywny")
    
    # Uruchomienie FastAPI
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")  