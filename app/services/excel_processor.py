import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import xml.dom.minidom
import xml.etree.ElementTree as ET
from app.config import config

logger = logging.getLogger("PGB2ReportSender")

class ExcelProcessor:
    """Klasa do przetwarzania danych z pliku Excel"""

    def __init__(self, excel_path=None):
        """Inicjalizacja procesora danych Excel"""
        self.excel_path = excel_path or config.EXCEL_PATH
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
        Walidacja danych Excel TYLKO z przyszłości przed generowaniem XML
        
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
        
        # KLUCZOWA ZMIANA: Filtrowanie TYLKO danych z przyszłości
        now = datetime.now()
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        end_date = next_hour + timedelta(days=days_ahead)
        
        logger.info(f"=== WALIDACJA DANYCH Z PRZYSZŁOŚCI ===")
        logger.info(f"Aktualna data/czas: {now}")
        logger.info(f"Start walidacji (następna godzina): {next_hour}")
        logger.info(f"Koniec walidacji: {end_date}")
        
        # Filtrowanie danych TYLKO z przyszłości
        forecast_data = self.df[(self.df['DATA'] >= next_hour) & (self.df['DATA'] <= end_date)].copy()
        
        if forecast_data.empty:
            return False, f"Brak danych prognozy z przyszłości na następne {days_ahead} dni (od {next_hour.strftime('%Y-%m-%d %H:%M')} do {end_date.strftime('%Y-%m-%d %H:%M')})"
        
        # Automatyczne naprawianie danych czasowych przed walidacją
        logger.info("Próba automatycznego naprawienia danych przed walidacją...")
        original_count = len(forecast_data)
        forecast_data = self.fix_time_resolution(forecast_data)
        
        if len(forecast_data) != original_count:
            logger.info(f"Naprawiono dane: {original_count} -> {len(forecast_data)} rekordów")
        
        # Sprawdź pokrycie czasowe
        expected_records = days_ahead * 24  # 9 dni * 24 godziny = 216 rekordów
        coverage_percent = (len(forecast_data) / expected_records) * 100
        logger.info(f"Pokrycie czasowe: {len(forecast_data)}/{expected_records} rekordów ({coverage_percent:.1f}%)")
        
        # Walidacja wartości liczbowych
        numeric_columns = ['Zużycie', 'Produkcja PV [kW]', 'Bilans [kW]', 'Produkcja PV (PPLAN)']
        if 'Nadwyżki (PAUTO)' in forecast_data.columns:
            numeric_columns.append('Nadwyżki (PAUTO)')
        
        for col in numeric_columns:
            if not pd.api.types.is_numeric_dtype(forecast_data[col]):
                try:
                    self.df[col] = pd.to_numeric(self.df[col], errors='coerce')
                    forecast_data = self.df[(self.df['DATA'] >= next_hour) & (self.df['DATA'] <= end_date)].copy()
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
            
            # Sprawdź czy PAUTO <= PPLAN
            pauto_gt_pplan = forecast_data['Nadwyżki (PAUTO)'] > forecast_data['Produkcja PV (PPLAN)']
            if pauto_gt_pplan.any():
                problematic_rows = forecast_data[pauto_gt_pplan]
                first_problem = problematic_rows.iloc[0]
                return False, f"PAUTO ({first_problem['Nadwyżki (PAUTO)']}) nie może być większe od PPLAN ({first_problem['Produkcja PV (PPLAN)']}) - wiersz z datą {first_problem['DATA']}"
        
        logger.info(f"Walidacja danych z przyszłości przebiegła pomyślnie")
        return True, "Dane z przyszłości są poprawne"

    def get_forecast_data(self, days_ahead=9):
        """
        Pobieranie danych prognozy TYLKO z przyszłości (od następnej godziny)
        
        Parametry:
        days_ahead (int): Liczba dni do przodu
        
        Zwraca:
        DataFrame: Dane prognozy tylko z przyszłości
        """
        if self.df is None:
            if not self.load_data():
                return None
        
        # Aktualna data i czas
        now = datetime.now()
        
        # Następna pełna godzina (to jest start dla PGB2)
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        
        # Koniec okresu - days_ahead dni od następnej godziny
        end_date = next_hour + timedelta(days=days_ahead)
        
        logger.info(f"Filtrowanie danych prognozy:")
        logger.info(f"- Aktualna data/czas: {now}")
        logger.info(f"- Start danych (następna godzina): {next_hour}")
        logger.info(f"- Koniec danych: {end_date}")
        
        # Filtrowanie danych TYLKO z przyszłości (od następnej godziny)
        future_data = self.df[(self.df['DATA'] >= next_hour) & (self.df['DATA'] <= end_date)].copy()
        
        if future_data.empty:
            logger.warning(f"Brak danych prognozy z przyszłości na następnych {days_ahead} dni")
        else:
            logger.info(f"Znaleziono {len(future_data)} rekordów danych z przyszłości")
            
        return future_data

    def generate_xml_for_mwe_short(self, data=None):
        """
        Generuje XML dla planu krótkoterminowego MWE zgodny z formatem PGB2
        Zawiera PPLAN, PAUTO, PMAXLIM i PMINLIM zgodnie z wymaganiami API
        
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
            return None
            
        try:
            # Sortowanie danych według daty
            data = data.sort_values('DATA').reset_index(drop=True)
            
            # ID modułu wytwarzania energii (MWE) z config
            mwe_id = config.MWE_ID
            
            # Okres czasowy dla całego dokumentu w UTC
            min_date = data['DATA'].min()
            max_date = data['DATA'].max()
            
            # Konwersja na UTC - dokumentacja wymaga formatu UTC: YYYY-MM-DDTHH:MMZ
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
            
            # PMAXLIM Series - businessType A_60 (maksymalny limit mocy)
            pmaxlim_series = ET.SubElement(root, "PlannedResource_TimeSeries")
            ET.SubElement(pmaxlim_series, "mRID").text = mwe_id
            ET.SubElement(pmaxlim_series, "businessType").text = "A_60"  # A_60 = maksymalny limit mocy
            ET.SubElement(pmaxlim_series, "measurement_Unit.name").text = "MAW"
            ET.SubElement(pmaxlim_series, "registeredResource.mRID").text = mwe_id
            
            # Okres czasowy dla PMAXLIM
            pmaxlim_period = ET.SubElement(pmaxlim_series, "Series_Period")
            pmaxlim_timeInterval = ET.SubElement(pmaxlim_period, "timeInterval")
            ET.SubElement(pmaxlim_timeInterval, "start").text = schedule_start
            ET.SubElement(pmaxlim_timeInterval, "end").text = schedule_end
            ET.SubElement(pmaxlim_period, "resolution").text = "PT1H"
            
            # Punkty danych PMAXLIM (stała wartość dla wszystkich punktów)
            for position, (i, row) in enumerate(data.iterrows(), start=1):
                point = ET.SubElement(pmaxlim_period, "Point")
                ET.SubElement(point, "position").text = str(position)
                ET.SubElement(point, "quantity").text = f"{config.PMAXLIM_VALUE:.3f}"
                
                # Dodanie wartości PMAXLIM do przetworzonych wierszy
                if position <= len(processed_rows):
                    processed_rows[position-1]["pmaxlim_mw"] = config.PMAXLIM_VALUE
            
            # PMINLIM Series - businessType A_61 (minimalny limit mocy)
            pminlim_series = ET.SubElement(root, "PlannedResource_TimeSeries")
            ET.SubElement(pminlim_series, "mRID").text = mwe_id
            ET.SubElement(pminlim_series, "businessType").text = "A_61"  # A_61 = minimalny limit mocy
            ET.SubElement(pminlim_series, "measurement_Unit.name").text = "MAW"
            ET.SubElement(pminlim_series, "registeredResource.mRID").text = mwe_id
            
            # Okres czasowy dla PMINLIM
            pminlim_period = ET.SubElement(pminlim_series, "Series_Period")
            pminlim_timeInterval = ET.SubElement(pminlim_period, "timeInterval")
            ET.SubElement(pminlim_timeInterval, "start").text = schedule_start
            ET.SubElement(pminlim_timeInterval, "end").text = schedule_end
            ET.SubElement(pminlim_period, "resolution").text = "PT1H"
            
            # Punkty danych PMINLIM (stała wartość dla wszystkich punktów)
            for position, (i, row) in enumerate(data.iterrows(), start=1):
                point = ET.SubElement(pminlim_period, "Point")
                ET.SubElement(point, "position").text = str(position)
                ET.SubElement(point, "quantity").text = f"{config.PMINLIM_VALUE:.3f}"
                
                # Dodanie wartości PMINLIM do przetworzonych wierszy
                if position <= len(processed_rows):
                    processed_rows[position-1]["pminlim_mw"] = config.PMINLIM_VALUE
            
            # Aktualizacja danych przetworzonych
            processed_data = {
                "last_processed_date": datetime.now().isoformat(),
                "processed_rows": processed_rows
            }
            
            # Zapisanie danych przetworzonych
            with open(config.PROCESSED_DATA_PATH, 'w') as f:
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
            
            return formatted_xml
            
        except Exception as e:
            error_msg = f"Błąd generowania XML: {str(e)}"
            logger.error(error_msg)
            return None