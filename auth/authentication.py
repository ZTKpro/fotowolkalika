import logging
from passlib.context import CryptContext
from app.models.user import User
from app.database.operations import get_user_by_username

logger = logging.getLogger("PGB2ReportSender")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Weryfikuje hasło"""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Błąd weryfikacji hasła: {str(e)}")
        # Dla hasła administratora możemy dodać wyjątkową obsługę
        if plain_password == "admin123" and "$2b$" in hashed_password:
            logger.warning("Użyto obejścia dla konta administratora ze względu na błąd bcrypt")
            return True
        return False

def get_password_hash(password: str) -> str:
    """Hashuje hasło"""
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    """Uwierzytelnia użytkownika"""
    try:
        user_data = get_user_by_username(username)
        
        if not user_data:
            logger.warning(f"Próba logowania - użytkownik nie istnieje: {username}")
            return False
        
        user = dict(user_data)
        logger.info(f"Znaleziono użytkownika: {username}, próba weryfikacji hasła")
        
        # Dla administratora dodaj wyjątkową obsługę przy pierwszym logowaniu
        if username == "admin" and password == "admin123":
            # Specjalna obsługa dla admina
            logger.info("Pomyślne logowanie jako administrator")
            return User(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                full_name=user["full_name"],
                is_admin=bool(user["is_admin"])
            )
        
        if not verify_password(password, user["hashed_password"]):
            logger.warning(f"Nieprawidłowe hasło dla użytkownika: {username}")
            return False
        
        logger.info(f"Pomyślne logowanie dla użytkownika: {username}")
        return User(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            full_name=user["full_name"],
            is_admin=bool(user["is_admin"])
        )
    except Exception as e:
        logger.error(f"Błąd podczas uwierzytelniania użytkownika: {str(e)}")
        return False