import logging
from fastapi import APIRouter, Request, Form, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.models.user import User
from app.dependencies import require_admin
from app.auth.authentication import get_password_hash
from app.database.operations import (
    get_all_users, create_user, delete_user, update_user, 
    get_user_by_username, get_user_by_id
)

logger = logging.getLogger("PGB2ReportSender")
router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")

@router.get("/users", response_class=HTMLResponse)
async def admin_users(request: Request, user: User = Depends(require_admin)):
    """Panel zarządzania użytkownikami (tylko dla administratorów)"""
    users = get_all_users()
    
    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "users": users,
        "user": user
    })

@router.post("/users/add")
async def admin_add_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(None),
    is_admin: bool = Form(False),
    user: User = Depends(require_admin)
):
    """Dodawanie nowego użytkownika przez administratora"""
    try:
        # Sprawdź, czy użytkownik już istnieje
        existing_user = get_user_by_username(username)
        if existing_user:
            return RedirectResponse(
                url="/admin/users?error=Użytkownik o podanej nazwie już istnieje", 
                status_code=status.HTTP_303_SEE_OTHER
            )
        
        # Sprawdź email
        from app.database.connection import get_db_connection
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                return RedirectResponse(
                    url="/admin/users?error=Adres e-mail jest już używany", 
                    status_code=status.HTTP_303_SEE_OTHER
                )
        
        hashed_password = get_password_hash(password)
        create_user(username, email, hashed_password, full_name, is_admin)
        
        return RedirectResponse(
            url="/admin/users?success=Użytkownik został pomyślnie dodany", 
            status_code=status.HTTP_303_SEE_OTHER
        )
    except Exception as e:
        logger.error(f"Błąd podczas dodawania użytkownika: {str(e)}")
        return RedirectResponse(
            url=f"/admin/users?error=Błąd podczas dodawania użytkownika: {str(e)}", 
            status_code=status.HTTP_303_SEE_OTHER
        )

@router.post("/users/{user_id}/delete")
async def admin_delete_user(
    user_id: int, 
    user: User = Depends(require_admin)
):
    """Usuwanie użytkownika przez administratora"""
    try:
        # Sprawdź, czy nie usuwamy samego siebie
        if user_id == user.id:
            return RedirectResponse(
                url="/admin/users?error=Nie możesz usunąć własnego konta", 
                status_code=status.HTTP_303_SEE_OTHER
            )
        
        success = delete_user(user_id)
        if success:
            return RedirectResponse(
                url="/admin/users?success=Użytkownik został usunięty", 
                status_code=status.HTTP_303_SEE_OTHER
            )
        else:
            return RedirectResponse(
                url="/admin/users?error=Nie znaleziono użytkownika do usunięcia", 
                status_code=status.HTTP_303_SEE_OTHER
            )
    except Exception as e:
        logger.error(f"Błąd podczas usuwania użytkownika: {str(e)}")
        return RedirectResponse(
            url=f"/admin/users?error=Błąd podczas usuwania użytkownika: {str(e)}", 
            status_code=status.HTTP_303_SEE_OTHER
        )

@router.post("/users/edit")
async def admin_edit_user(
    request: Request,
    user_id: int = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(None),
    full_name: str = Form(None),
    is_admin: bool = Form(False),
    admin_user: User = Depends(require_admin)
):
    """Edycja użytkownika przez administratora"""
    try:
        # Sprawdź, czy użytkownik istnieje
        existing_user = get_user_by_id(user_id)
        if not existing_user:
            return RedirectResponse(
                url="/admin/users?error=Nie znaleziono użytkownika", 
                status_code=status.HTTP_303_SEE_OTHER
            )
        
        existing_user_dict = dict(existing_user)
        
        # Sprawdź, czy nazwa użytkownika nie jest zajęta przez innego użytkownika
        if username != existing_user_dict["username"]:
            username_check = get_user_by_username(username)
            if username_check:
                return RedirectResponse(
                    url="/admin/users?error=Nazwa użytkownika jest już zajęta", 
                    status_code=status.HTTP_303_SEE_OTHER
                )
        
        # Sprawdź email
        if email != existing_user_dict["email"]:
            from app.database.connection import get_db_connection
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email = ? AND id != ?", (email, user_id))
                if cursor.fetchone():
                    return RedirectResponse(
                        url="/admin/users?error=Adres e-mail jest już używany", 
                        status_code=status.HTTP_303_SEE_OTHER
                    )
        
        # Przygotuj dane do aktualizacji
        update_data = {
            "username": username,
            "email": email,
            "full_name": full_name,
            "is_admin": is_admin
        }
        
        # Jeśli podano nowe hasło, dodaj je do aktualizacji
        if password and password.strip():
            update_data["hashed_password"] = get_password_hash(password)
        
        update_user(user_id, **update_data)
        
        return RedirectResponse(
            url="/admin/users?success=Użytkownik został pomyślnie zaktualizowany", 
            status_code=status.HTTP_303_SEE_OTHER
        )
    except Exception as e:
        logger.error(f"Błąd podczas edycji użytkownika: {str(e)}")
        return RedirectResponse(
            url=f"/admin/users?error=Błąd podczas edycji użytkownika: {str(e)}", 
            status_code=status.HTTP_303_SEE_OTHER
        )