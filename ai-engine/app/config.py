from pydantic_settings import BaseSettings, SettingsConfigDict
import os
import secrets
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../../.env"))

class Settings(BaseSettings):
    app_name: str = "HalluciShield AI Engine"
    version: str = "1.0.0"
    port: int = int(os.getenv("AI_ENGINE_PORT", 8000))
    debug: bool = False
    llm_base_url: str = os.getenv("LLM_BASE_URL", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    default_llm_model: str = os.getenv("DEFAULT_LLM_MODEL", "llama-3.3-70b-versatile")
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://hallucishield:hallucishield@localhost:5432/hallucishield"
    )
    database_url_sync: str = os.getenv(
        "DATABASE_URL_SYNC",
        "postgresql://hallucishield:hallucishield@localhost:5432/hallucishield"
    )
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:3000")

    def model_post_init(self, __context):
        if not self.jwt_secret:
            if os.environ.get("ENVIRONMENT", "development") == "production":
                raise ValueError("JWT_SECRET must be set in production")
            self.jwt_secret = secrets.token_hex(32)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
