"""
Модуль для настройки и использования логирования.
"""
import logging
from typing import Optional

def setup_logging(log_file: Optional[str] = None, level: int = logging.INFO) -> None:
    format_str = "%(asctime)s [%(levelname)s] %(message)s"
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers,
        force=True
    )

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name)