import json
import logging
import shutil
import os
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File, Form
from fastapi.responses import JSONResponse

from app.models.user import User, ExcelDataUpdate
from app.dependencies import require_user
from app.services.excel_processor import ExcelProcessor
from app.services.chart_data import prepare_chart_data
from app.utils.scheduler import (
    get_sent_reports, get_error_logs, get_processed_data, 
    send_daily_report, regenerate_processed_data
)
from app.config import config
import pandas as pd

logger = logging.getLogger("PGB2ReportSender")
router = APIRouter(prefix="/api")

@router.post("/trigger-report")
async def trigger_report(background_tasks: BackgroundTasks, user: User = Depends(require_user)):
    """Endpoint do ręcznego uruchomienia wysyłania raportu"""
    try:
        background_tasks.add_task(send_daily_report)
        return {"status": "success", "message": "Rozpoczęto wysyłanie raportu w tle"}
    except Exception as e:
        error_msg = f"Błąd podczas uruchamiania raportu: {str(e)}"
        logger.error(error_msg)
        error_logs = get_error_logs()
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_stats(user: User = Depends(require_user)):
    """Endpoint zwracający statystyki w formacie JSON"""
    try:
        return {
            "sent_reports": get_sent_reports(),
            "error_logs": get_error_logs(),
            "processed_data": get_processed_data()
        }
    except Exception as e:
        error_msg = f"Błąd podczas pobierania statystyk: {str(e)}"
        logger.error(error_msg)
        error_logs = get_error_logs()
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/excel-data")
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
        error_logs = get_error_logs()
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/chart-data")
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
        error_logs = get_error_logs()
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": error_msg, "type": "api"})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/upload-excel")
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
    try:
        # Sprawdzenie rozszerzenia pliku
        if not file.filename.endswith(('.xlsx', '.xls')):
            return {"status": "error", "message": "Nieprawidłowy format pliku. Akceptowane są tylko pliki .xlsx lub .xls"}
        
        # Ustalenie ścieżki docelowej
        file_path = config.EXCEL_PATH
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
            
            # Aktualizacja ścieżki w konfiguracji (nie robimy tego w config.py dla bezpieczeństwa)
            # Zamiast tego informujemy użytkownika o nowej ścieżce
            logger.info(f"Plik zapisany jako: {new_file_path}")
        
        logger.info(f"Plik Excel został pomyślnie wgrany: {file_path}")
        return {"status": "success", "message": "Plik Excel został pomyślnie wgrany"}
        
    except Exception as e:
        logger.error(f"Błąd podczas wgrywania pliku Excel: {str(e)}")
        error_logs = get_error_logs()
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": f"Błąd podczas wgrywania pliku Excel: {str(e)}", "type": "api"})
        
        # Usunięcie pliku tymczasowego w przypadku błędu
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
        return {"status": "error", "message": f"Błąd podczas wgrywania pliku: {str(e)}"}

@router.post("/update-excel-data")
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
        backup_path = f"{config.EXCEL_PATH}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        shutil.copy2(config.EXCEL_PATH, backup_path)
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
            updated_df.to_excel(config.EXCEL_PATH, index=False)
            logger.info(f"Pomyślnie zaktualizowano dane w pliku Excel")
            
            # Resetowanie przetworzonych danych
            processed_data = get_processed_data()
            processed_data["last_processed_date"] = datetime.now().isoformat()
            processed_data["processed_rows"] = []
            
            # Zapisanie zaktualizowanych danych przetworzonych
            with open(config.PROCESSED_DATA_PATH, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            # Wyzwolenie ponownego przetworzenia pliku w tle
            background_tasks.add_task(regenerate_processed_data)
            
            return {"status": "success", "message": "Dane zostały pomyślnie zaktualizowane"}
        except Exception as e:
            logger.error(f"Błąd podczas zapisywania zaktualizowanych danych: {str(e)}")
            return {"status": "error", "message": f"Błąd podczas zapisywania danych: {str(e)}"}
            
    except Exception as e:
        logger.error(f"Błąd podczas aktualizacji danych Excel: {str(e)}")
        error_logs = get_error_logs()
        error_logs.append({"timestamp": datetime.now().isoformat(), "message": f"Błąd podczas aktualizacji danych Excel: {str(e)}", "type": "api"})
        return {"status": "error", "message": f"Błąd podczas aktualizacji danych: {str(e)}"}