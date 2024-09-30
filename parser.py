import psutil
import time
import configparser
import platform
import subprocess
import signal
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Флаг для остановки программы при получении сигнала
stop_event = None

# Лок для синхронизации доступа к файлам
file_lock = threading.Lock()

# Функция для определения, является ли IP локальным
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return True
        return False
    except ValueError:
        return False

# Получаем PID процессов по именам .exe
def get_pids_by_names(exe_names):
    pid_name_map = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in exe_names:
                pid_name_map[proc.info['pid']] = proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return pid_name_map

# Получаем сетевые подключения процесса по PID
def get_network_connections_by_pid(pid):
    connections = []
    try:
        proc = psutil.Process(pid)
        for conn in proc.net_connections(kind='inet'):
            if conn.raddr:
                remote_ip = conn.raddr.ip
                if not is_local_ip(remote_ip):
                    connections.append(remote_ip)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print(f"Ошибка доступа к процессу {pid}: {e}")
    return connections

# Функция для парсинга среднего пинга из вывода команды ping
def parse_average_ping_time(output):
    avg_ping = None
    lines = output.splitlines()
    if platform.system().lower() == 'windows':
        for line in lines:
            line = line.strip()
            if "Average =" in line or "Среднее =" in line:
                parts = line.split('=')
                if len(parts) >= 2:
                    avg_ping = parts[1].strip()
                    avg_ping = avg_ping.replace('ms', '').replace('мсек', '').strip()
                break
            elif "Minimum =" in line or "Минимальное =" in line:
                # Обработка строки вида "Minimum = 1ms, Maximum = 2ms, Average = 1ms"
                parts = line.split(',')
                for part in parts:
                    if "Average =" in part or "Среднее =" in part:
                        avg_part = part.split('=')
                        if len(avg_part) >= 2:
                            avg_ping = avg_part[1].strip()
                            avg_ping = avg_ping.replace('ms', '').replace('мсек', '').strip()
                        break
                if avg_ping:
                    break
    else:
        for line in lines:
            if 'min/avg/max' in line or 'rtt min/avg/max/mdev' in line:
                parts = line.split('=')
                if len(parts) >=2:
                    stats = parts[1].split('/')
                    if len(stats) >= 2:
                        avg_ping = stats[1].strip()
                break
    return avg_ping

# Функция для пинга IP-адреса
def ping_ip(ip, ping_file, last_success_ping, num_pings=5, num_attempts=3):
    if stop_event.is_set():
        return

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(num_pings), ip]

    attempt = 0
    success = False

    while attempt < num_attempts and not success and not stop_event.is_set():
        attempt += 1
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            output = result.stdout

            if result.returncode == 0:
                avg_ping = parse_average_ping_time(output)
                avg_ping = avg_ping if avg_ping else "неизвестно"
                current_time = time.time()
                last_success_ping[ip] = current_time

                with file_lock:
                    with open(ping_file, 'a', encoding='utf-8') as f_ping:
                        f_ping.write(f"IP {ip} пингуется успешно. Средний пинг: {avg_ping} мс.\n")
                success = True
                return True
            else:
                if attempt < num_attempts:
                    time.sleep(1)
                else:
                    with file_lock:
                        with open(ping_file, 'a', encoding='utf-8') as f_ping:
                            f_ping.write(f"IP {ip} не пингуется с момента отслеживания.\n")
                continue
        except subprocess.TimeoutExpired:
            print(f"Пинг {ip} превысил время ожидания.")
            if attempt >= num_attempts:
                with file_lock:
                    with open(ping_file, 'a', encoding='utf-8') as f_ping:
                        f_ping.write(f"IP {ip} не пингуется с момента отслеживания.\n")
            continue
        except Exception as e:
            print(f"Ошибка выполнения пинга для {ip}: {e}")
            if attempt >= num_attempts:
                with file_lock:
                    with open(ping_file, 'a', encoding='utf-8') as f_ping:
                        f_ping.write(f"IP {ip} не пингуется с момента отслеживания.\n")
            continue

    return False

# Функция для чтения конфигурационного файла
def read_config():
    config = configparser.ConfigParser()
    config.read('config.ini')

    exe_list = config.get('Processes', 'exe_list').split(',')
    exe_list = [exe.strip() for exe in exe_list]  # Убираем пробелы

    ip_file = config.get('Output', 'ip_file')
    keenetic_file = config.get('Output', 'keenetic_file')
    ping_file = config.get('Output', 'ping_file')

    # Чтение настройки маски подсети (32, 24, 16)
    subnet_mask = config.get('Subnet', 'mask', fallback="32")

    enable_ping = config.getint('Ping', 'enable_ping')

    return exe_list, ip_file, keenetic_file, ping_file, subnet_mask, enable_ping

# Функция для агрегации IP-адресов в подсети
def group_ips_into_subnets(ips, submask):
    subnets = set()
    for ip in ips:
        try:
            ip_address = ipaddress.ip_address(ip)
            if submask == "24":
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnet = f"{network.network_address}/24"
                subnets.add(subnet)
            elif submask == "16":
                network = ipaddress.ip_network(f"{ip}/16", strict=False)
                subnet = f"{network.network_address}/16"
                subnets.add(subnet)
            elif submask == "32":
                subnet = f"{ip}/32"
                subnets.add(subnet)
            else:
                print(f"Неподдерживаемая маска подсети: {submask}")
        except ValueError as e:
            print(f"Ошибка в IP адресе: {ip} - {e}")
    return subnets

# Обработчик сигнала SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nОстановка программы...")
    stop_event.set()

# Основная функция
def main():
    global stop_event
    stop_event = threading.Event()

    signal.signal(signal.SIGINT, signal_handler)

    exe_list, ip_file, keenetic_file, ping_file, subnet_mask, enable_ping = read_config()

    # Очистка выходных файлов
    open(ip_file, 'w').close()
    open(keenetic_file, 'w').close()
    if enable_ping:
        open(ping_file, 'w', encoding='utf-8').close()

    tracked_ips = set()
    unique_keenetic_ips = set()
    last_success_ping = {}

    # Создаем ThreadPoolExecutor для пинга
    if enable_ping:
        ping_executor = ThreadPoolExecutor(max_workers=10)

    try:
        while not stop_event.is_set():
            pid_name_map = get_pids_by_names(exe_list)
            for pid, exe_name in pid_name_map.items():
                connections = get_network_connections_by_pid(pid)
                if connections:
                    for ip in connections:
                        if ip not in tracked_ips:
                            # Новый IP-адрес
                            tracked_ips.add(ip)
                            print(f"Новый IP для {exe_name}: {ip}")

                            with file_lock:
                                with open(ip_file, 'a') as f_ip:
                                    f_ip.write(f"{exe_name}: {ip}\n")

                            unique_keenetic_ips.add(ip)

                            if enable_ping:
                                # Пингуем новый IP в отдельном потоке
                                ping_executor.submit(ping_ip, ip, ping_file, last_success_ping, 5, 3)
                        else:
                            # Существующий IP-адрес
                            if enable_ping:
                                # Пингуем существующий IP в отдельном потоке
                                ping_executor.submit(ping_ip, ip, ping_file, last_success_ping, 1, 1)

            time.sleep(5)
    except KeyboardInterrupt:
        print("\nПрерывание программы (Ctrl+C)")
    finally:
        stop_event.set()
        if enable_ping:
            ping_executor.shutdown(wait=False)
        print("Программа завершена.")

    # После завершения, агрегируем IP-адреса
    aggregated_subnets = group_ips_into_subnets(unique_keenetic_ips, subnet_mask)

    # Запись агрегированных команд маршрутизации в файл
    with open(keenetic_file, 'w') as f:
        for subnet in sorted(aggregated_subnets):
            if subnet_mask == "24":
                mask = "255.255.255.0"
            elif subnet_mask == "16":
                mask = "255.255.0.0"
            elif subnet_mask == "32":
                mask = "255.255.255.255"
            else:
                # Если маска не распознана, пропускаем
                continue
            network_address = subnet.split('/')[0]
            route_command = f"route ADD {network_address} MASK {mask} 0.0.0.0\n"
            f.write(route_command)

if __name__ == "__main__":
    main()
