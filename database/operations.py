import logging
from datetime import datetime
from app.database.connection import get_db_connection
from app.auth.authentication import get_password_hash

logger = logging.getLogger("PGB2ReportSender")

def init_db():
    """Inicjalizacja bazy danych - tworzenie tabel jeśli nie istnieją"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Tabela użytkowników
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            full_name TEXT,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Tabela sesji
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        conn.commit()
        
        # Sprawdź czy istnieje domyślny użytkownik admin
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if not admin_user:
            # Tworzenie domyślnego użytkownika admin z hasłem 'admin123'
            hashed_password = get_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, email, hashed_password, full_name, is_admin) VALUES (?, ?, ?, ?, ?)",
                ("admin", "admin@example.com", hashed_password, "Administrator", True)
            )
            conn.commit()
            logger.info("Utworzono domyślne konto administratora (login: admin, hasło: admin123)")

def cleanup_expired_sessions():
    """Usuwa wygasłe sesje z bazy danych"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(),))
            conn.commit()
            logger.info(f"Usunięto {cursor.rowcount} wygasłych sesji")
    except Exception as e:
        logger.error(f"Błąd podczas czyszczenia wygasłych sesji: {str(e)}")

def get_user_by_username(username: str):
    """Pobiera użytkownika po nazwie użytkownika"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def get_user_by_id(user_id: int):
    """Pobiera użytkownika po ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

def create_user(username: str, email: str, hashed_password: str, full_name: str = None, is_admin: bool = False):
    """Tworzy nowego użytkownika"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password, full_name, is_admin) VALUES (?, ?, ?, ?, ?)",
            (username, email, hashed_password, full_name, is_admin)
        )
        conn.commit()
        return cursor.lastrowid

def update_user(user_id: int, **kwargs):
    """Aktualizuje dane użytkownika"""
    if not kwargs:
        return
    
    set_clause = ", ".join([f"{key} = ?" for key in kwargs.keys()])
    values = list(kwargs.values()) + [user_id]
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        conn.commit()

def delete_user(user_id: int):
    """Usuwa użytkownika"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Usuń sesje użytkownika
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        # Usuń użytkownika
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0

def get_all_users():
    """Pobiera wszystkich użytkowników"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        return [dict(row) for row in cursor.fetchall()]