"""
Утилитарные функции для проекта.
"""
from typing import Set, List
import ipaddress
import platform

def group_ips_into_subnets(ips: Set[str], submask: str) -> Set[str]:
    subnets: Set[str] = set()
    valid_masks = {"16", "24", "32"}
    if submask not in valid_masks:
        submask = "32"
    for ip in ips:
        try:
            ip_address = ipaddress.ip_address(ip)
            if ip_address.version == 4:
                if submask == "24":
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnet = f"{network.network_address}/24"
                elif submask == "16":
                    network = ipaddress.ip_network(f"{ip}/16", strict=False)
                    subnet = f"{network.network_address}/16"
                else:
                    subnet = f"{ip}/32"
                subnets.add(subnet)
            elif ip_address.version == 6:
                subnet = f"{ip}/128"
                subnets.add(subnet)
        except ValueError:
            continue
    return subnets

def parse_average_ping_time(output: str) -> str | None:
    avg_ping = None
    lines = output.splitlines()
    if platform.system().lower() == 'windows':
        for line in lines:
            line = line.strip()
            if "Average =" in line or "Среднее =" in line:
                # Пример: Minimum = 1ms, Maximum = 2ms, Average = 1ms
                parts = line.split(',')
                for part in parts:
                    if "Average =" in part or "Среднее =" in part:
                        avg_part = part.split('=')
                        if len(avg_part) >= 2:
                            avg_ping = avg_part[1].strip().replace('ms', '').replace('мсек', '').strip()
                            avg_ping = ''.join([c for c in avg_ping if c.isdigit() or c == '.' or c == ','])
                            avg_ping = avg_ping.replace(',', '.')
                        break
                if avg_ping:
                    break
    else:
        for line in lines:
            line = line.strip()
            if '=' in line and '/' in line:
                # Пример: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
                parts = line.split('=')
                if len(parts) >= 2:
                    stats = parts[1].split('/')
                    if len(stats) >= 2:
                        avg_ping = stats[1].strip()
                        avg_ping = avg_ping.replace(',', '.')
                        # Удаляем единицы измерения, если есть
                        avg_ping = ''.join([c for c in avg_ping if c.isdigit() or c == '.' or c == ','])
                if avg_ping:
                    break
    return avg_ping