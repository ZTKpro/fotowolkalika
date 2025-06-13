from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class User(BaseModel):
    """Model użytkownika"""
    id: Optional[int] = None
    username: str
    email: str
    full_name: Optional[str] = None
    is_admin: bool = False

class UserCreate(BaseModel):
    """Model do tworzenia nowego użytkownika"""
    username: str
    email: str
    password: str
    full_name: Optional[str] = None

class UserInDB(User):
    """Model użytkownika z hasłem w bazie danych"""
    hashed_password: str

class SessionData(BaseModel):
    """Model danych sesji"""
    user_id: int
    expires_at: datetime

class LoginForm(BaseModel):
    """Model formularza logowania"""
    username: str
    password: str
    remember_me: bool = False

class ExcelDataUpdate(BaseModel):
    """Model do aktualizacji danych Excel"""
    data: List[Dict[str, Any]]