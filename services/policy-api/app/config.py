from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://anispam:anispam@postgres:5432/anispam"
    redis_url: str = "redis://redis:6379/0"
    default_superadmin_email: str = "admin@local.anispam"
    default_superadmin_password: str = "change-me"
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    ai_provider_mode: str = "disabled"
    ollama_base_url: str = "http://ollama:11434/v1"
    ollama_model: str = "llama3.1"
    gpustack_base_url: str = "http://gpustack:8080/v1"
    gpustack_api_key: str = ""
    gpustack_model: str = "llama3.1"
    enable_ai_enforcement: bool = False
    smtp_decision_timeout_ms: int = 1500
    scan_queue_name: str = "anispam:scan-jobs"
    clamav_config_dir: str = "/shared/clamav-config"


settings = Settings()
