# PowerWise

Aplikacja webowa do automatycznego generowania i wysyłania raportów z pliku Excel do systemu PGB2 poprzez API. Aplikacja zawiera dashboard z wizualizacją danych i jest przystosowana do wdrożenia na platformie Render.

## Funkcjonalności

- Automatyczne wysyłanie raportów codziennie o 6:00 rano
- Dashboard z wykresami zużycia, produkcji PV i bilansu energii
- Wizualizacja danych Excel
- Monitorowanie historii wysłanych raportów
- Logowanie błędów i operacji systemowych
- Ręczne uruchamianie wysyłania raportów
- API dla danych statystycznych i Excel

## Wymagania

- Python 3.10+
- FastAPI
- Pandas
- Plotly
- APScheduler
- Requests
- Jinja2

## Instalacja i uruchomienie lokalne

1. Sklonuj repozytorium:
   ```bash
   git clone https://github.com/twoja-organizacja/pgb2-report-sender.git
   cd pgb2-report-sender
   ```

2. Utwórz i aktywuj wirtualne środowisko:
   ```bash
   python -m venv venv
   # Windows
   .\venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate
   ```

3. Zainstaluj wymagane biblioteki:
   ```bash
   pip install -r requirements.txt
   ```

4. Utwórz plik `.env` z danymi uwierzytelniającymi:
   ```
   PGB2_BASE_URL=https://pgb2.tauron-dystrybucja.pl
   PGB2_CLIENT_ID=twoj_client_id
   PGB2_CLIENT_SECRET=twoj_client_secret
   PGB2_USERNAME=twoj_username
   PGB2_PASSWORD=twoje_haslo
   MWE_ID=_8eda81ec-90eb-46f9-abc8-7071ba98a5b1
   EXCEL_PATH=SOGLbazaraportTAURON.xlsx
   ```

5. Umieść plik Excel z danymi w katalogu głównym projektu.

6. Uruchom aplikację:
   ```bash
   python main.py
   ```

7. Otwórz przeglądarkę i przejdź do adresu: `http://localhost:8000`

## Wdrożenie na platformie Render bez Dockera

1. Utwórz konto na platformie [Render](https://render.com/)

2. Połącz repozytorium GitHub z projektem

3. Utwórz nowy Web Service wybierając "Python" jako środowisko:
   - **Nazwa**: pgb2-report-sender
   - **Runtime Environment**: Python
   - **Build Command**: `chmod +x ./start.sh`
   - **Start Command**: `./start.sh`
   - **Python Version**: 3.10.0

4. Ustaw zmienne środowiskowe w panelu Render:
   - `PGB2_BASE_URL`
   - `PGB2_CLIENT_ID`
   - `PGB2_CLIENT_SECRET`
   - `PGB2_USERNAME`
   - `PGB2_PASSWORD`
   - `MWE_ID`
   - `EXCEL_PATH`

5. Plik `render.yaml` zawiera konfigurację potrzebną do automatycznego wdrożenia za pomocą Render Blueprint

6. Upewnij się, że plik Excel został dodany do repozytorium

## Struktura danych Excel

Aplikacja oczekuje określonej struktury danych w pliku Excel:

| DATA | Zużycie | Produkcja PV [kW] | Bilans [kW] | Produkcja PV (PPLAN) | Nadwyżki (PAUTO) |
|------|---------|------------------|------------|---------------------|-----------------|
| 01/05/2025 12:00 | 373.20 | 0 | -373.20 | 0.000 | 0.000 |

- `DATA` - data i godzina w formacie DD/MM/YYYY HH:MM
- `Zużycie` - wartość zużycia energii w kW
- `Produkcja PV [kW]` - wartość produkcji energii z paneli fotowoltaicznych w kW
- `Bilans [kW]` - bilans energii (produkcja minus zużycie) w kW
- `Produkcja PV (PPLAN)` - wartość planowana do wysłania jako PPLAN w API PGB2
- `Nadwyżki (PAUTO)` - wartość planowana do wysłania jako PAUTO w API PGB2

## Endpointy API

- `GET /` - główny dashboard
- `POST /trigger-report` - ręczne uruchomienie wysyłania raportu
- `GET /api/stats` - statystyki wysłanych raportów i błędów
- `GET /api/excel-data` - dane z pliku Excel w formacie JSON

## Harmonogram

Domyślny harmonogram wysyłania raportów jest ustawiony na godzinę 6:00 rano codziennie. Można go zmienić w pliku `main.py` w sekcji inicjalizacji harmonogramu:

```python
scheduler.add_job(
    send_daily_report,
    trigger=CronTrigger(hour=6, minute=0),
    id='daily_report',
    name='Wysyłanie dziennego raportu',
    replace_existing=True
)
```

## Rozwiązywanie problemów

### Problemy z uwierzytelnianiem
- Sprawdź poprawność danych w pliku `.env` lub zmiennych środowiskowych na Render
- Upewnij się, że Twoje konto ma uprawnienia "USER_API" w systemie PGB2

### Problemy z odczytem pliku Excel
- Upewnij się, że plik Excel znajduje się w katalogu głównym projektu
- Sprawdź czy plik ma odpowiednią strukturę kolumn

### Problemy z wysyłaniem raportów
- Sprawdź logi systemowe na dashboardzie
- Zweryfikuj poprawność identyfikatora MWE

### Problemy z wdrożeniem na Render
- Sprawdź logi budowania i uruchamiania w panelu Render
- Upewnij się, że skrypt `start.sh` ma uprawnienia do wykonywania
- Sprawdź czy wszystkie zmienne środowiskowe zostały poprawnie skonfigurowane

## Rozszerzanie funkcjonalności

Aby dostosować aplikację do innych typów raportów:

1. Dodaj nowe metody generujące XML w klasie `ExcelProcessor`
2. Rozszerz funkcję `send_daily_report()` o nowe typy raportów
3. Dodaj nowe zakładki w dashboardzie w pliku `templates/dashboard.html`

