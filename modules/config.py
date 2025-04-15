"""
Модуль для работы с конфигурацией приложения.
"""
from typing import Any, Dict, Tuple
import tomllib
import os

class ConfigError(Exception):
    pass

def read_config(config_file: str = "config.toml") -> Tuple[list[str], str, str, str, str, str, int, int, int, int, float, int]:
    if not os.path.exists(config_file):
        raise ConfigError(f"Файл конфигурации {config_file} не найден.")
    try:
        with open(config_file, 'rb') as f:
            config = tomllib.load(f)
        exe_list = config['Processes']['exe_list']
        exe_list = list(dict.fromkeys(exe_list))
        ip_file = config['Output']['ip_file']
        keenetic_file = config['Output']['keenetic_file']
        ping_file = config['Output']['ping_file']
        domain_file = config['Output'].get('domain_file', 'domain.txt')
        subnet_mask = config['Subnet'].get('mask', "32")
        if subnet_mask not in ["16", "24", "32"]:
            subnet_mask = "32"
        enable_ping = int(config['Ping']['enable_ping'])
        enable_domain_tracking = int(config.get('Domain', {}).get('enable_domain_tracking', 0))
        threading_config = config.get('Threading', {})
        max_ping_threads = int(threading_config.get('max_ping_threads', 2))
        max_active_tasks = int(threading_config.get('max_active_tasks', 4))
        ping_delay = float(threading_config.get('ping_delay', 0.5))
        ping_interval = int(threading_config.get('ping_interval', 600))
        return exe_list, ip_file, keenetic_file, ping_file, domain_file, subnet_mask, enable_ping, enable_domain_tracking, max_ping_threads, max_active_tasks, ping_delay, ping_interval
    except Exception as e:
        raise ConfigError(f"Ошибка при чтении конфигурационного файла: {e}")