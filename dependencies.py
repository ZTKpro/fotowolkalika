import logging
from fastapi import Request, HTTPException, status
from app.models.user import User
from app.auth.session import get_user_from_session
from app.config import config

logger = logging.getLogger("PGB2ReportSender")

async def get_current_user(request: Request) -> User:
    """Pobiera aktualnego użytkownika z sesji"""
    session_id = request.cookies.get(config.SESSION_COOKIE_NAME)
    if not session_id:
        logger.debug(f"Brak cookie sesji w żądaniu: {request.url.path}")
        return None
    
    logger.debug(f"Znaleziono cookie sesji: {session_id[:8]}... dla ścieżki: {request.url.path}")
    
    user = get_user_from_session(session_id)
    if user:
        logger.debug(f"Pomyślnie zidentyfikowano użytkownika: {user.username} dla ścieżki: {request.url.path}")
    else:
        logger.debug(f"Nie znaleziono użytkownika dla sesji: {session_id[:8]}... i ścieżki: {request.url.path}")
    
    return user

async def require_user(request: Request):
    """Zależność do wymagania zalogowanego użytkownika"""
    user = await get_current_user(request)
    if not user:
        logger.warning(f"Odmowa dostępu: użytkownik nie zalogowany, URL: {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/login?next={request.url.path}"}
        )
    return user

async def require_admin(request: Request):
    """Zależność do wymagania uprawnień administratora"""
    user = await get_current_user(request)
    if not user:
        logger.warning(f"Odmowa dostępu: użytkownik nie zalogowany, URL: {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/login?next={request.url.path}"}
        )
    if not user.is_admin:
        logger.warning(f"Odmowa dostępu: użytkownik {user.username} nie ma uprawnień administratora")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Brak wymaganych uprawnień"
        )
    return user