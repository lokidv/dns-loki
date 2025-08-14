"""
Centralized logging configuration for DNS-Loki
"""

import logging
import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from logging.handlers import RotatingFileHandler


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for better readability"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)


class LoggerManager:
    """Manages application logging configuration"""
    
    _instance: Optional['LoggerManager'] = None
    _configured: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def setup_logging(
        self,
        level: str = "INFO",
        format_type: str = "json",
        log_file: Optional[Path] = None,
        max_bytes: int = 10485760,  # 10MB
        backup_count: int = 5
    ):
        """Configure application logging"""
        
        if self._configured:
            return
        
        # Get root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, level.upper()))
        
        # Remove existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        
        # Set formatter based on format type
        if format_type == "json":
            formatter = JSONFormatter()
        else:
            if sys.stdout.isatty():
                formatter = ColoredFormatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
        
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(getattr(logging, level.upper()))
            file_handler.setFormatter(JSONFormatter())
            root_logger.addHandler(file_handler)
        
        # Set levels for third-party libraries
        logging.getLogger("uvicorn").setLevel(logging.WARNING)
        logging.getLogger("fastapi").setLevel(logging.WARNING)
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        
        self._configured = True
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance"""
        logger = logging.getLogger(name)
        return LoggerAdapter(logger)


class LoggerAdapter(logging.LoggerAdapter):
    """Custom logger adapter for adding context"""
    
    def __init__(self, logger: logging.Logger):
        super().__init__(logger, {})
    
    def process(self, msg, kwargs):
        """Process log message and add extra context"""
        extra = kwargs.get('extra', {})
        
        # Add any global context here
        if hasattr(self, 'context'):
            extra.update(self.context)
        
        kwargs['extra'] = {'extra_data': extra} if extra else {}
        return msg, kwargs
    
    def with_context(self, **context) -> 'LoggerAdapter':
        """Create a new logger with additional context"""
        new_logger = LoggerAdapter(self.logger)
        new_logger.context = context
        return new_logger


# Global logger manager
logger_manager = LoggerManager()


def get_logger(name: str) -> LoggerAdapter:
    """Get a logger instance for a module"""
    return logger_manager.get_logger(name)
