import logging
import secrets
from datetime import datetime, timedelta
from app.models.user import User
from app.database.connection import get_db_connection
from app.config import config

logger = logging.getLogger("PGB2ReportSender")

def create_session(user_id: int, expire_days: int = config.SESSION_EXPIRE_DAYS):
    """Tworzy nową sesję dla użytkownika"""
    try:
        session_id = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(days=expire_days)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Usuń stare sesje tego użytkownika
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            # Utwórz nową sesję
            cursor.execute(
                "INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
                (session_id, user_id, expires_at)
            )
            conn.commit()
            logger.info(f"Utworzono nową sesję dla użytkownika ID: {user_id}, ważną do: {expires_at}")
        
        return session_id, expires_at
    except Exception as e:
        logger.error(f"Błąd podczas tworzenia sesji: {str(e)}")
        # Zwróć awaryjny identyfikator sesji w przypadku błędu
        return secrets.token_hex(32), datetime.now() + timedelta(days=expire_days)

def get_user_from_session(session_id: str):
    """Pobiera użytkownika na podstawie ID sesji"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.id, u.username, u.email, u.full_name, u.is_admin, s.expires_at 
                FROM sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.session_id = ? AND s.expires_at > ?
                """, 
                (session_id, datetime.now())
            )
            result = cursor.fetchone()
            
            if not result:
                logger.warning(f"Nie znaleziono aktywnej sesji dla ID: {session_id[:8]}...")
                return None
            
            user_data = dict(result)
            logger.info(f"Znaleziono sesję dla użytkownika: {user_data['username']}")
            return User(
                id=user_data["id"],
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                is_admin=bool(user_data["is_admin"])
            )
    except Exception as e:
        logger.error(f"Błąd podczas pobierania sesji użytkownika: {str(e)}")
        return None

def delete_session(session_id: str):
    """Usuwa sesję"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return cursor.rowcount > 0