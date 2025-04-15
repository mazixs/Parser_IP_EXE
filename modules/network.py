"""
Модуль для сетевых операций и работы с процессами.
"""
from typing import List, Dict, Optional
import psutil
import ipaddress
import socket
import threading

file_lock = threading.Lock()

def is_local_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback or ip_obj.is_private
    except ValueError:
        return False

def get_pids_by_names(exe_names: List[str]) -> Dict[int, str]:
    pid_name_map: Dict[int, str] = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in exe_names:
                pid_name_map[proc.info['pid']] = proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return pid_name_map

def get_network_connections_by_pid(pid: int) -> List[str]:
    connections: List[str] = []
    try:
        proc = psutil.Process(pid)
        for conn in proc.net_connections(kind='inet'):
            if conn.raddr:
                remote_ip = conn.raddr.ip
                if not is_local_ip(remote_ip):
                    connections.append(remote_ip)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return connections

def is_ip_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def get_domain_by_ip(ip: str, domain_cache: dict, domain_cache_ttl: int = 3600) -> Optional[str]:
    import time
    current_time = time.time()
    if ip in domain_cache:
        cache_time, domain = domain_cache[ip]
        if current_time - cache_time < domain_cache_ttl and domain is not None:
            return domain
        elif current_time - cache_time < domain_cache_ttl * 3:
            return None
    try:
        domain = socket.gethostbyaddr(ip)[0]
        if not is_ip_address(domain):
            domain_cache[ip] = (current_time, domain)
            return domain
    except (socket.herror, socket.gaierror, socket.timeout):
        try:
            socket.setdefaulttimeout(5)
            domain = socket.gethostbyaddr(ip)[0]
            if not is_ip_address(domain):
                domain_cache[ip] = (current_time, domain)
                return domain
        except (socket.herror, socket.gaierror, socket.timeout):
            domain_cache[ip] = (current_time, None)
    return None