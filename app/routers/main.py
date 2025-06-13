import os
import sys
import logging
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Konfiguracja logowania
from app.config import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("PGB2ReportSender")

# Inicjalizacja FastAPI
app = FastAPI(
    title="PowerWise", 
    description="Aplikacja do automatycznego wysyłania raportów do systemu PGB2",
    version="1.0.0"
)

# Statyczne pliki i szablony
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Import routerów
from app.routers import auth, dashboard, admin, api

# Rejestracja routerów
app.include_router(auth.router, tags=["Authentication"])
app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(admin.router, tags=["Administration"])
app.include_router(api.router, tags=["API"])

# Scheduler
scheduler = None

@app.on_event("startup")
async def startup_event():
    """Funkcja uruchamiana podczas startu aplikacji"""
    global scheduler
    
    # Inicjalizacja bazy danych
    from app.database.operations import init_db
    init_db()
    
    # Uruchomienie harmonogramu
    from app.utils.scheduler import setup_scheduler
    scheduler = setup_scheduler()
    scheduler.start()
    logger.info("Aplikacja uruchomiona, harmonogram zadań aktywny")

@app.on_event("shutdown")
async def shutdown_event():
    """Funkcja uruchamiana podczas zatrzymania aplikacji"""
    global scheduler
    
    # Zatrzymanie harmonogramu
    if scheduler:
        scheduler.shutdown()
        logger.info("Aplikacja zatrzymana, harmonogram zadań wyłączony")

# Obsługa błędów 404
@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Obsługa błędów 404"""
    return templates.TemplateResponse("error.html", {
        "request": request,
        "error": "Strona nie została znaleziona"
    }, status_code=404)

# Obsługa błędów 500
@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """Obsługa błędów 500"""
    logger.error(f"Błąd serwera: {str(exc)}")
    return templates.TemplateResponse("error.html", {
        "request": request,
        "error": "Wystąpił błąd serwera"
    }, status_code=500)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Endpoint sprawdzania zdrowia aplikacji"""
    return {
        "status": "healthy",
        "scheduler_running": scheduler.running if scheduler else False,
        "version": "1.0.0"
    }

# Root endpoint redirect
from fastapi.responses import RedirectResponse

@app.get("/")
async def root():
    """Przekierowanie z głównej strony"""
    return RedirectResponse(url="/dashboard")

if __name__ == "__main__":
    import uvicorn
    print(f"Uruchamianie aplikacji PowerWise na porcie {config.PORT}...")
    print(f"Nasłuchiwanie na {config.HOST}:{config.PORT}")
    
    # Inicjalizacja bazy danych
    from app.database.operations import init_db
    init_db()
    
    # Uruchomienie harmonogramu
    from app.utils.scheduler import setup_scheduler
    scheduler = setup_scheduler()
    scheduler.start()
    logger.info("Aplikacja uruchomiona, harmonogram zadań aktywny")
    
    # Uruchomienie FastAPI
    uvicorn.run(
        "app.main:app", 
        host=config.HOST, 
        port=config.PORT, 
        log_level="info",
        reload=config.DEBUG
    )