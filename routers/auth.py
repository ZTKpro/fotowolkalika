import logging
from fastapi import APIRouter, Request, Response, Form, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.models.user import User
from app.auth.authentication import authenticate_user, get_password_hash
from app.auth.session import create_session, delete_session
from app.database.operations import get_user_by_username, create_user, get_db_connection
from app.dependencies import get_current_user
from app.config import config

logger = logging.getLogger("PGB2ReportSender")
router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Strona główna - przekierowanie do dashboardu lub logowania"""
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("index.html", {"request": request})

@router.get("/login", response_class=HTMLResponse)
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

@router.post("/login")
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
        key=config.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        max_age=expire_days * 24 * 60 * 60 if remember_me else None,
        path="/",
        secure=False
    )
    
    logger.info(f"Pomyślne logowanie dla użytkownika: {username}, przekierowanie do: {next}")
    
    return redirect

@router.get("/logout")
async def logout(response: Response, request: Request):
    """Wylogowanie użytkownika"""
    session_id = request.cookies.get(config.SESSION_COOKIE_NAME)
    if session_id:
        delete_session(session_id)
    
    # Usuń ciasteczko sesji
    response.delete_cookie(config.SESSION_COOKIE_NAME, path="/")
    
    # Przekieruj na stronę logowania
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Strona rejestracji"""
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
async def register(
    response: Response,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(None)
):
    """Endpoint do rejestracji nowego użytkownika"""
    # Sprawdź, czy użytkownik już istnieje
    existing_user = get_user_by_username(username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Użytkownik o podanej nazwie użytkownika już istnieje"
        )
    
    # Sprawdź email
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Adres e-mail jest już używany"
            )
    
    # Dodaj nowego użytkownika
    hashed_password = get_password_hash(password)
    user_id = create_user(username, email, hashed_password, full_name)
    
    # Utwórz sesję i zaloguj użytkownika
    session_id, expires_at = create_session(user_id)
    
    # Ustaw ciasteczko sesji
    response.set_cookie(
        key=config.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        max_age=24 * 60 * 60,  # 1 dzień
        path="/",
        secure=False  # Ustaw na True w środowisku produkcyjnym z HTTPS
    )
    
    # Przekieruj na dashboard
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)