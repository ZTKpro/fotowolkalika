import json
import logging
import requests
import tempfile
from datetime import datetime
from app.config import config

logger = logging.getLogger("PGB2ReportSender")

class PGB2API:
    """Klasa do obsługi API PGB2"""

    def __init__(self, base_url=None, client_id=None, client_secret=None, username=None, password=None):
        """Inicjalizacja klasy API PGB2"""
        self.base_url = base_url or config.PGB2_BASE_URL
        self.client_id = client_id or config.PGB2_CLIENT_ID
        self.client_secret = client_secret or config.PGB2_CLIENT_SECRET
        self.username = username or config.PGB2_USERNAME
        self.password = password or config.PGB2_PASSWORD
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
            return False, error_msg
        except Exception as e:
            error_msg = f"Nieoczekiwany błąd podczas wysyłania planu: {str(e)}"
            logger.error(error_msg)
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
                return False, result["message"]
                
            status = result["message"]
            logger.debug(f"Status planu: {status}")
            return True, status
            
        except Exception as e:
            error_msg = f"Błąd sprawdzania statusu: {str(e)}"
            logger.error(error_msg)
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