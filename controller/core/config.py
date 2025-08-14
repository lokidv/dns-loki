"""
Configuration management for DNS-Loki Controller
Centralized configuration with validation and environment variable support
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import Field
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


class Settings(BaseSettings):
    """Application settings with validation"""

    # pydantic-settings v2 config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Server Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8080, env="PORT", ge=1, le=65535)
    debug: bool = Field(default=False, env="DEBUG")

    # Data Storage
    data_dir: Path = Field(default=Path("/opt/dns-proxy/data"), env="DATA_DIR")
    state_file: str = Field(default="state.json", env="STATE_FILE")

    # Git/Code Configuration
    default_git_repo: Optional[str] = Field(default=None, env="DEFAULT_GIT_REPO")
    default_git_branch: str = Field(default="main", env="DEFAULT_GIT_BRANCH")
    code_repo: Optional[str] = Field(default=None, env="CODE_REPO")
    code_branch: Optional[str] = Field(default=None, env="CODE_BRANCH")
    git_repo: Optional[str] = Field(default=None, env="GIT_REPO")
    git_branch: Optional[str] = Field(default=None, env="GIT_BRANCH")

    # Security / Auth
    secret_key: Optional[str] = Field(default=None, env="SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(default=24, env="JWT_EXPIRATION_HOURS")
    access_token_expire_minutes: int = Field(default=60, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    enable_auth: bool = Field(default=False, env="ENABLE_AUTH")

    # API Configuration
    api_version: str = Field(default="v1")
    api_prefix: str = Field(default="/api")
    cors_origins: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    allowed_hosts: List[str] = Field(default_factory=list, env="ALLOWED_HOSTS")

    # Agent Configuration
    agent_heartbeat_timeout: int = Field(default=180)  # seconds
    agent_update_check_interval: int = Field(default=60)  # seconds

    # DNS/Proxy Configuration
    enforce_dns_clients: bool = Field(default=True, env="ENFORCE_DNS_CLIENTS")
    enforce_proxy_clients: bool = Field(default=False, env="ENFORCE_PROXY_CLIENTS")

    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    log_file: Optional[Path] = Field(default=None, env="LOG_FILE")

    @field_validator("secret_key", mode="before")
    @classmethod
    def generate_secret_key(cls, v):
        """Generate a secret key if not provided"""
        if not v:
            import secrets
            return secrets.token_urlsafe(32)
        return v

    @field_validator("data_dir", mode="before")
    @classmethod
    def ensure_data_dir(cls, v):
        """Ensure data directory exists"""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        """Parse allowed hosts from string or list"""
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return v

    # --- Compatibility properties (uppercase aliases) ---
    # These provide backward compatibility with older code referencing
    # uppercase setting names.
    @property
    def HOST(self) -> str:
        return self.host

    @property
    def PORT(self) -> int:
        return self.port

    @property
    def DEBUG(self) -> bool:
        return self.debug

    @property
    def LOG_LEVEL(self) -> str:
        return self.log_level

    @property
    def CORS_ORIGINS(self) -> List[str]:
        return self.cors_origins

    @property
    def ALLOWED_HOSTS(self) -> List[str]:
        return self.allowed_hosts

    @property
    def SECRET_KEY(self) -> str:
        return self.secret_key or ""

    @property
    def ALGORITHM(self) -> str:
        return self.jwt_algorithm

    @property
    def ACCESS_TOKEN_EXPIRE_MINUTES(self) -> int:
        # Prefer explicit minutes if set, else derive from hours
        return self.access_token_expire_minutes or self.jwt_expiration_hours * 60


class ConfigManager:
    """Manages application configuration"""
    
    _instance: Optional['ConfigManager'] = None
    _settings: Optional[Settings] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @property
    def settings(self) -> Settings:
        """Get application settings"""
        if self._settings is None:
            self._settings = Settings()
        return self._settings
    
    def reload(self):
        """Reload configuration from environment"""
        self._settings = Settings()
    
    def load_from_file(self, config_file: Path):
        """Load additional configuration from YAML file"""
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
                if config_data:
                    # Update settings with file data
                    for key, value in config_data.items():
                        if hasattr(self._settings, key):
                            setattr(self._settings, key, value)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        return getattr(self.settings, key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        if hasattr(self.settings, key):
            setattr(self.settings, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary"""
        return self.settings.model_dump()


# Global configuration instance
config = ConfigManager()

# Module-level convenience export used across the project
# Provides a Settings with compatibility aliases for older code.
settings = config.settings
