import json
import logging
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.models.user import User
from app.dependencies import require_user
from app.services.excel_processor import ExcelProcessor
from app.services.chart_data import prepare_chart_data
from app.utils.scheduler import get_sent_reports, get_error_logs, get_processed_data

logger = logging.getLogger("PGB2ReportSender")
router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(require_user)):
    """Główny endpoint - dashboard z statystykami i wykresami"""
    try:
        # Pobieranie danych z utils/scheduler
        sent_reports = get_sent_reports()
        error_logs = get_error_logs()
        processed_data = get_processed_data()
        
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
            "success_count": processed_data.get("success_count", 0),
            "error_count": processed_data.get("error_count", 0),
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
        error_logs = get_error_logs()
        error_logs.append({"timestamp": "datetime.now().isoformat()", "message": error_msg, "type": "dashboard"})
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })

@router.get("/profile", response_class=HTMLResponse)
async def user_profile(request: Request, user: User = Depends(require_user)):
    """Panel profilu użytkownika"""
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user
    })

@router.post("/profile/update")
async def update_profile(
    request: Request,
    user: User = Depends(require_user)
):
    """Aktualizacja profilu użytkownika"""
    from fastapi import Form
    from app.database.operations import update_user, get_user_by_id
    from app.auth.authentication import verify_password, get_password_hash
    
    # Pobierz dane z formularza
    form = await request.form()
    full_name = form.get("full_name")
    email = form.get("email")
    current_password = form.get("current_password")
    new_password = form.get("new_password")
    
    try:
        # Sprawdź czy email jest unikalny
        if email != user.email:
            from app.database.connection import get_db_connection
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user.id))
                if cursor.fetchone():
                    return templates.TemplateResponse("profile.html", {
                        "request": request,
                        "user": user,
                        "error": "Podany adres e-mail jest już używany przez innego użytkownika"
                    })
        
        # Aktualizuj dane podstawowe
        update_data = {"full_name": full_name, "email": email}
        
        # Jeśli podano hasła, zmień hasło
        if current_password and new_password:
            # Pobierz aktualne hasło
            current_user_data = get_user_by_id(user.id)
            current_hashed = dict(current_user_data)["hashed_password"]
            
            # Sprawdź poprawność aktualnego hasła
            if not verify_password(current_password, current_hashed):
                return templates.TemplateResponse("profile.html", {
                    "request": request,
                    "user": user,
                    "error": "Nieprawidłowe aktualne hasło"
                })
            
            # Aktualizuj hasło
            update_data["hashed_password"] = get_password_hash(new_password)
        
        update_user(user.id, **update_data)
        
        # Aktualizuj obiekt użytkownika
        user.full_name = full_name
        user.email = email
        
        return templates.TemplateResponse("profile.html", {
            "request": request,
            "user": user,
            "success": "Profil został pomyślnie zaktualizowany"
        })
        
    except Exception as e:
        logger.error(f"Błąd podczas aktualizacji profilu: {str(e)}")
        return templates.TemplateResponse("profile.html", {
            "request": request,
            "user": user,
            "error": f"Błąd podczas aktualizacji profilu: {str(e)}"
        })