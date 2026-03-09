from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    milter_policy_url: str = "http://policy-api:8080/api/v1/milter/evaluate"
    milter_socket: str = "inet:9900@0.0.0.0"
    milter_timeout_seconds: int = 30
    smtp_decision_timeout_ms: int = 1500


settings = Settings()
