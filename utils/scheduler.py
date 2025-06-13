import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.config import config
from app.services.pgb2_api import PGB2API
from app.services.excel_processor import ExcelProcessor
from app.database.operations import cleanup_expired_sessions

logger = logging.getLogger("PGB2ReportSender")

# Historia wysłanych raportów
sent_reports = []

# Historia błędów
error_logs = []

# Inicjalizacja danych przetworzonych
processed_data = {
    "last_processed_date": None,
    "processed_rows": [],
    "success_count": 0,
    "error_count": 0
}

# Wczytanie danych przetworzonych, jeśli istnieją
try:
    with open(config.PROCESSED_DATA_PATH, 'r') as f:
        processed_data = json.load(f)
except Exception as e:
    logger.error(f"Błąd wczytywania danych przetworzonych: {e}")

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
                with open(config.PROCESSED_DATA_PATH, 'w') as f:
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
                with open(config.PROCESSED_DATA_PATH, 'w') as f:
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
            with open(config.PROCESSED_DATA_PATH, 'w') as f:
                json.dump(processed_data, f, indent=2)
        except Exception as save_error:
            logger.error(f"Nie udało się zapisać danych przetworzonych: {save_error}")

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

def setup_scheduler():
    """Konfiguracja i uruchomienie schedulera"""
    scheduler = BackgroundScheduler()
    
    # Dodanie zadania - wysyłanie raportu codziennie o określonej godzinie
    scheduler.add_job(
        send_daily_report,
        trigger=CronTrigger(hour=config.DAILY_REPORT_HOUR, minute=config.DAILY_REPORT_MINUTE),
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
    
    return scheduler

# Eksportuj globalne zmienne, aby inne moduły mogły je używać
def get_sent_reports():
    return sent_reports

def get_error_logs():
    return error_logs

def get_processed_data():
    return processed_data