import psutil
import time
import tomllib  # Встроенный модуль для работы с TOML в Python 3.11+
import platform
import subprocess
import signal
import threading
import ipaddress
import os
import datetime
import socket
import random
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
def ping_ip(ip, ping_file, last_success_ping, num_pings=2, num_attempts=1, interval=600):
    if stop_event.is_set():
        return

    # Проверяем, когда последний раз пинговали этот IP
    current_time = time.time()
    if ip in last_success_ping:
        # Если IP уже пинговался успешно в течение заданного интервала, пропускаем
        if current_time - last_success_ping[ip] < interval:  # Используем переданный интервал
            return True

    # Ограничиваем количество пингов для снижения нагрузки
    num_pings = min(num_pings, 2)  # Максимум 2 пинга
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Используем более эффективную команду ping с ограничением времени ожидания
    command = ['ping', param, str(num_pings), ip, '-w', '500']  # Уменьшаем таймаут до 500 мс

    attempt = 0
    success = False
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Добавляем случайную задержку перед запуском пинга для распределения нагрузки
    time.sleep(random.uniform(0.1, 0.3))

    while attempt < num_attempts and not success and not stop_event.is_set():
        attempt += 1
        try:
            # Используем subprocess с ограничением времени выполнения
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            output = result.stdout

            if result.returncode == 0:
                avg_ping = parse_average_ping_time(output)
                avg_ping = avg_ping if avg_ping else "неизвестно"
                last_success_ping[ip] = current_time

                log_ping_result(ping_file, ip, True, avg_ping, timestamp)
                success = True
                return True
            else:
                if attempt < num_attempts:
                    time.sleep(0.5)  # Уменьшаем задержку между попытками
                else:
                    log_ping_result(ping_file, ip, False, None, timestamp)
                continue
        except subprocess.TimeoutExpired:
            print(f"Пинг {ip} превысил время ожидания.")
            if attempt >= num_attempts:
                log_ping_result(ping_file, ip, False, None, timestamp)
            continue
        except Exception as e:
            print(f"Ошибка выполнения пинга для {ip}: {e}")
            if attempt >= num_attempts:
                log_ping_result(ping_file, ip, False, None, timestamp, str(e))
            continue

    return False

# Функция для логирования результатов пинга
def log_ping_result(ping_file, ip, success, avg_ping=None, timestamp=None, error=None):
    if timestamp is None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with file_lock:
        with open(ping_file, 'a', encoding='utf-8') as f_ping:
            if success:
                f_ping.write(f"[{timestamp}] IP {ip} пингуется успешно. Средний пинг: {avg_ping} мс.\n")
            else:
                message = f"[{timestamp}] IP {ip} не пингуется с момента отслеживания."
                if error:
                    message += f" Ошибка: {error}"
                f_ping.write(message + "\n")

# Кэш для доменных имен, чтобы не делать повторные запросы
domain_cache = {}
# Время жизни кэша доменных имен (в секундах)
domain_cache_ttl = 3600  # 1 час

# Функция для получения доменного имени по IP-адресу
def get_domain_by_ip(ip):
    current_time = time.time()
    
    # Проверяем кэш
    if ip in domain_cache:
        cache_time, domain = domain_cache[ip]
        # Если кэш не устарел и домен был найден
        if current_time - cache_time < domain_cache_ttl and domain is not None:
            return domain
        # Если кэш не устарел, но домен не был найден
        elif current_time - cache_time < domain_cache_ttl * 3:  # Для отрицательных результатов кэш живет дольше
            return None
    
    try:
        domain = socket.gethostbyaddr(ip)[0]
        # Проверяем, что полученное имя не является IP-адресом
        if not is_ip_address(domain):
            # Сохраняем в кэш
            domain_cache[ip] = (current_time, domain)
            return domain
    except (socket.herror, socket.gaierror, socket.timeout):
        # Увеличиваем таймаут для повторной попытки
        try:
            socket.setdefaulttimeout(5)  # Увеличиваем таймаут до 5 секунд
            domain = socket.gethostbyaddr(ip)[0]
            if not is_ip_address(domain):
                # Сохраняем в кэш
                domain_cache[ip] = (current_time, domain)
                return domain
        except (socket.herror, socket.gaierror, socket.timeout):
            # Сохраняем отрицательный результат в кэш
            domain_cache[ip] = (current_time, None)
            pass
    return None

# Функция для проверки, является ли строка IP-адресом
def is_ip_address(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

# Функция для записи доменного имени в файл
def log_domain(domain_file, ip, domain, exe_name, timestamp=None):
    if timestamp is None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with file_lock:
        with open(domain_file, 'a', encoding='utf-8') as f_domain:
            f_domain.write(f"[{timestamp}] {exe_name}: {ip} -> {domain}\n")

# Функция для чтения конфигурационного файла
def read_config():
    config_file = 'config.toml'
    # Проверка существования конфигурационного файла
    if not os.path.exists(config_file):
        print(f"Ошибка: Файл конфигурации {config_file} не найден.")
        print("Создаю файл конфигурации по умолчанию...")
        create_default_config(config_file)
    try:
        with open(config_file, 'rb') as f:
            config = tomllib.load(f)
        # В TOML exe_list уже является списком, не нужно разделять строку
        exe_list = config['Processes']['exe_list']
        # Удаление дубликатов из списка exe_list
        exe_list = list(dict.fromkeys(exe_list))
        # --- ДОБАВИТЬ после импорта datetime ---
        # Генерация уникальной подпапки для результатов по времени запуска
        run_timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        results_dir = os.path.join("results", run_timestamp)
        os.makedirs(results_dir, exist_ok=True)
        ip_file = os.path.join(results_dir, config['Output']['ip_file'])
        keenetic_file = os.path.join(results_dir, config['Output']['keenetic_file'])
        ping_file = os.path.join(results_dir, config['Output']['ping_file'])
        domain_file = os.path.join(results_dir, config['Output'].get('domain_file', 'domain.txt'))
        # Чтение настройки маски подсети (32, 24, 16)
        subnet_mask = config['Subnet'].get('mask', "32")
        # Проверка корректности маски подсети
        if subnet_mask not in ["16", "24", "32"]:
            print(f"Предупреждение: Неподдерживаемая маска подсети: {subnet_mask}. Используется маска по умолчанию: 32")
            subnet_mask = "32"
        enable_ping = config['Ping']['enable_ping']
        # Чтение настройки отслеживания доменов
        enable_domain_tracking = config.get('Domain', {}).get('enable_domain_tracking', 0)
        # Чтение настроек многопоточности
        threading_config = config.get('Threading', {})
        max_ping_threads = threading_config.get('max_ping_threads', 2)
        max_active_tasks = threading_config.get('max_active_tasks', 4)
        ping_delay = threading_config.get('ping_delay', 0.5)
        ping_interval = threading_config.get('ping_interval', 600)
        return exe_list, ip_file, keenetic_file, ping_file, domain_file, subnet_mask, enable_ping, enable_domain_tracking, max_ping_threads, max_active_tasks, ping_delay, ping_interval
    except Exception as e:
        print(f"Ошибка при чтении конфигурационного файла: {e}")
        print("Создаю файл конфигурации по умолчанию...")
        create_default_config(config_file)
        return read_config()

# Функция для создания конфигурационного файла по умолчанию
def create_default_config(config_file):
    default_config = '''# Конфигурационный файл в формате TOML

# Если нужно указать несколько exe метод вводы: example1.exe, example2.exe
[Processes]
exe_list = ["example1.exe", "example2.exe"]

# Можно изменить как обозвать как захочется выходные файлы
[Output]
ip_file = "ip.txt"
keenetic_file = "keenetic.bat"
ping_file = "ping.log"
domain_file = "domain.txt"

# 1 для включения проверки пинга, 0 для отключения
[Ping]
enable_ping = 1

# Настройки многопоточности
[Threading]
# Максимальное количество потоков для пинга (по умолчанию 2)
max_ping_threads = 2
# Максимальное количество одновременных задач пинга (по умолчанию 4)
max_active_tasks = 4
# Задержка между запусками пингов в секундах (по умолчанию 0.5)
ping_delay = 0.5
# Интервал повторного пинга в секундах (по умолчанию 600 = 10 минут)
ping_interval = 600

# 1 для включения сбора доменных имен, 0 для отключения
[Domain]
enable_domain_tracking = 1

# Выбор подсети для сохранения 16, 24 или 32
[Subnet]
mask = "32"
'''
    
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(default_config)
    print(f"Файл конфигурации {config_file} создан.")
    print("Пожалуйста, отредактируйте его перед запуском программы.")
    print("Нажмите Enter для продолжения...")
    input()

# Функция для агрегации IP-адресов в подсети
def group_ips_into_subnets(ips, submask):
    subnets = set()
    ipv4_count = 0
    ipv6_count = 0
    error_count = 0
    
    # Проверка валидности маски подсети
    valid_masks = {"16", "24", "32"}
    if submask not in valid_masks:
        print(f"Предупреждение: Неподдерживаемая маска подсети: {submask}. Используется маска по умолчанию: 32")
        submask = "32"
    
    for ip in ips:
        try:
            ip_address = ipaddress.ip_address(ip)
            
            # Обработка IPv4 и IPv6 адресов
            if ip_address.version == 4:
                ipv4_count += 1
                if submask == "24":
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnet = f"{network.network_address}/24"
                elif submask == "16":
                    network = ipaddress.ip_network(f"{ip}/16", strict=False)
                    subnet = f"{network.network_address}/16"
                else:  # submask == "32" или другое значение
                    subnet = f"{ip}/32"
                subnets.add(subnet)
            elif ip_address.version == 6:
                ipv6_count += 1
                # IPv6 адреса обрабатываются отдельно
                # Для IPv6 можно использовать другие маски, например /64 или /128
                subnet = f"{ip}/128"  # По умолчанию для IPv6 используем /128
                subnets.add(subnet)
        except ValueError as e:
            error_count += 1
            print(f"Ошибка в IP адресе: {ip} - {e}")
    
    # Вывод статистики агрегации
    print(f"Агрегация завершена: обработано {ipv4_count} IPv4 и {ipv6_count} IPv6 адресов")
    if error_count > 0:
        print(f"Обнаружено {error_count} ошибок при обработке IP-адресов")
    
    return subnets

# Обработчик сигнала SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nОстановка программы...")
    stop_event.set()

# Мониторинг дочерних процессов и песочницы ---
def list_child_processes(parent_pid):
    try:
        parent = psutil.Process(parent_pid)
        children = parent.children(recursive=True)
        return children
    except Exception as e:
        print(f"[Мониторинг] Не удалось получить дочерние процессы: {e}")
        return []

def kill_child_processes(parent_pid):
    children = list_child_processes(parent_pid)
    for child in children:
        try:
            print(f"[Мониторинг] Завершаю дочерний процесс PID={child.pid} ({child.name()})")
            child.terminate()
        except Exception as e:
            print(f"[Мониторинг] Не удалось завершить процесс {child.pid}: {e}")
    gone, alive = psutil.wait_procs(children, timeout=3)
    for p in alive:
        try:
            print(f"[Мониторинг] Принудительное завершение PID={p.pid}")
            p.kill()
        except Exception as e:
            print(f"[Мониторинг] Не удалось принудительно завершить процесс {p.pid}: {e}")

# Обертка для subprocess с мониторингом ---
def run_subprocess_monitored(command, **kwargs):
    print(f"[Терминал] Запуск команды: {' '.join(command) if isinstance(command, list) else command}")
    try:
        proc = subprocess.Popen(command, **kwargs)
        print(f"[Терминал] Запущен дочерний процесс PID={proc.pid}")
        return proc
    except Exception as e:
        print(f"[Терминал] Ошибка запуска процесса: {e}")
        return None

# Функция для агрегации IP-адресов в подсети
def group_ips_into_subnets(ips, submask):
    subnets = set()
    ipv4_count = 0
    ipv6_count = 0
    error_count = 0
    
    # Проверка валидности маски подсети
    valid_masks = {"16", "24", "32"}
    if submask not in valid_masks:
        print(f"Предупреждение: Неподдерживаемая маска подсети: {submask}. Используется маска по умолчанию: 32")
        submask = "32"
    
    for ip in ips:
        try:
            ip_address = ipaddress.ip_address(ip)
            
            # Обработка IPv4 и IPv6 адресов
            if ip_address.version == 4:
                ipv4_count += 1
                if submask == "24":
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnet = f"{network.network_address}/24"
                elif submask == "16":
                    network = ipaddress.ip_network(f"{ip}/16", strict=False)
                    subnet = f"{network.network_address}/16"
                else:  # submask == "32" или другое значение
                    subnet = f"{ip}/32"
                subnets.add(subnet)
            elif ip_address.version == 6:
                ipv6_count += 1
                # IPv6 адреса обрабатываются отдельно
                # Для IPv6 можно использовать другие маски, например /64 или /128
                subnet = f"{ip}/128"  # По умолчанию для IPv6 используем /128
                subnets.add(subnet)
        except ValueError as e:
            error_count += 1
            print(f"Ошибка в IP адресе: {ip} - {e}")
    
    # Вывод статистики агрегации
    print(f"Агрегация завершена: обработано {ipv4_count} IPv4 и {ipv6_count} IPv6 адресов")
    if error_count > 0:
        print(f"Обнаружено {error_count} ошибок при обработке IP-адресов")
    
    return subnets

# Обработчик сигнала SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nОстановка программы...")
    stop_event.set()

# Основная фунция
def main():
    global stop_event
    stop_event = threading.Event()

    signal.signal(signal.SIGINT, signal_handler)

    # Чтение конфигурации
    exe_list, ip_file, keenetic_file, ping_file, domain_file, subnet_mask, enable_ping, enable_domain_tracking, max_ping_threads, max_active_tasks, ping_delay, ping_interval = read_config()
    
    if not exe_list:
        print("Ошибка: Список процессов для отслеживания пуст.")
        print("Пожалуйста, отредактируйте файл конфигурации и укажите процессы для отслеживания.")
        return

    # Создание директорий для выходных файлов, если они не существуют
    for file_path in [ip_file, keenetic_file, ping_file, domain_file]:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

    # Очистка выходных файлов
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ip_file, 'w', encoding='utf-8') as f:
        f.write(f"# Файл создан {timestamp}\n# Отслеживаемые процессы: {', '.join(exe_list)}\n\n")
    
    open(keenetic_file, 'w').close()
    
    if enable_ping:
        with open(ping_file, 'w', encoding='utf-8') as f:
            f.write(f"# Лог пингов создан {timestamp}\n# Отслеживаемые процессы: {', '.join(exe_list)}\n\n")
            
    if enable_domain_tracking:
        with open(domain_file, 'w', encoding='utf-8') as f:
            f.write(f"# Лог доменных имен создан {timestamp}\n# Отслеживаемые процессы: {', '.join(exe_list)}\n\n")

    tracked_ips = set()
    tracked_domains = set()  # Множество для отслеживания уникальных пар IP-домен
    unique_keenetic_ips = set()
    last_success_ping = {}
    active_futures = set()
    ping_queue = set()  # Множество для отслеживания IP в очереди на пинг

    print(f"Начало отслеживания процессов: {', '.join(exe_list)}")
    print("Для остановки нажмите Ctrl+C")

    # Используем контекстный менеджер для ThreadPoolExecutor
    try:
        # Создаем ThreadPoolExecutor только если включен пинг
        if enable_ping:
            max_workers = min(max_ping_threads, os.cpu_count() or 1)
            with ThreadPoolExecutor(max_workers=max_workers) as ping_executor:
                print(f"Запущено {max_workers} потоков для пинга IP-адресов")
                print(f"Максимальное количество одновременных задач пинга: {max_active_tasks}")
                print(f"Задержка между запусками пингов: {ping_delay} сек")
                print(f"Интервал повторного пинга: {ping_interval} сек")
                
                # Функция для проверки всех активных подключений
                def check_all_active_connections(ping_executor=None, interval=600):
                    pid_name_map = get_pids_by_names(exe_list)
                    if not pid_name_map:
                        return
                        
                    # Собираем все IP-адреса сначала, чтобы избежать дублирования запросов
                    all_connections = {}
                    for pid, exe_name in pid_name_map.items():
                        connections = get_network_connections_by_pid(pid)
                        for ip in connections:
                            if ip not in all_connections:
                                all_connections[ip] = []
                            all_connections[ip].append(exe_name)
                    
                    # Обрабатываем собранные IP-адреса
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    for ip, exe_names in all_connections.items():
                        exe_name = exe_names[0]  # Берем первый процесс для логирования
                        
                        if ip not in tracked_ips:
                            # Новый IP-адрес
                            tracked_ips.add(ip)
                            print(f"[{timestamp}] Новый IP для {exe_name}: {ip}")
                
                            with file_lock:
                                with open(ip_file, 'a', encoding='utf-8') as f_ip:
                                    f_ip.write(f"[{timestamp}] {exe_name}: {ip}\n")
                
                            unique_keenetic_ips.add(ip)
                
                            # Проверяем, не слишком ли много активных задач пинга
                            if enable_ping and ping_executor and ip not in ping_queue and len(active_futures) < max_active_tasks:
                                # Добавляем IP в очередь на пинг
                                ping_queue.add(ip)
                                # Добавляем увеличенную задержку перед запуском нового пинга
                                time.sleep(ping_delay)
                                # Пингуем новый IP в отдельном потоке с меньшим количеством попыток
                                future = ping_executor.submit(ping_ip, ip, ping_file, last_success_ping, 3, 2, interval)
                                future.add_done_callback(lambda f, ip=ip: ping_queue.discard(ip))
                                active_futures.add(future)
                        
                        # Проверяем доменное имя только для новых IP или если прошло достаточно времени
                        if enable_domain_tracking:
                            current_time = time.time()
                            domain = get_domain_by_ip(ip)
                            if domain and (ip, domain) not in tracked_domains:
                                tracked_domains.add((ip, domain))
                                print(f"[{timestamp}] Домен для {ip}: {domain}")
                                log_domain(domain_file, ip, domain, exe_name, timestamp)
                        else:
                            # Существующий IP-адрес
                            current_time = time.time()
                            # Пингуем существующий IP только раз в 5 минут и если он не в очереди
                            if ip not in ping_queue and len(active_futures) < max_active_tasks / 3:  # Используем только треть доступных слотов для повторных пингов
                                # Проверяем, когда последний раз пинговали этот IP
                                if ip not in last_success_ping or current_time - last_success_ping[ip] >= ping_interval:  # Используем интервал из конфигурации
                                    # Добавляем IP в очередь на пинг
                                    ping_queue.add(ip)
                                    # Добавляем увеличенную задержку перед запуском нового пинга
                                    time.sleep(ping_delay * 2 + random.uniform(0.5, 1.0))  # Случайная дополнительная задержка
                                    # Пингуем с минимальным приоритетом (1 пинг, 1 попытка)
                                    future = ping_executor.submit(ping_ip, ip, ping_file, last_success_ping, 1, 1, ping_interval)
                                    future.add_done_callback(lambda f, ip=ip: ping_queue.discard(ip))
                                    active_futures.add(future)
                                    
                                    # Проверяем доменное имя для существующего IP-адреса
                                    if enable_domain_tracking:
                                        # Периодически проверяем доменные имена для существующих IP
                                        domain = get_domain_by_ip(ip)
                                        if domain and (ip, domain) not in tracked_domains:
                                            tracked_domains.add((ip, domain))
                                            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                            print(f"[{timestamp}] Обнаружен домен для {ip}: {domain}")
                                            log_domain(domain_file, ip, domain, exe_name, timestamp)

                    time.sleep(5)
                
                # При запуске проверяем все активные подключения
                print("Проверка всех активных подключений при запуске...")
                check_all_active_connections(ping_executor, ping_interval)
                
                # Основной цикл программы с включенным пингом
                print("Запуск основного цикла мониторинга...")
                while not stop_event.is_set():
                    pid_name_map = get_pids_by_names(exe_list)
                    if not pid_name_map:
                        print("[Этап] Не найдено ни одного отслеживаемого процесса. Ожидание...")
                        time.sleep(5)
                        continue
                    
                    # Периодически проверяем все активные подключения
                    check_all_active_connections(ping_executor, ping_interval)
                    
                    # Очистка завершенных задач из списка активных
                    active_futures = {f for f in active_futures if not f.done()}
                    
                    # Задержка между проверками
                    time.sleep(5)
        else:
            # Если пинг отключен, просто отслеживаем IP-адреса
            print("[Этап] Пинг отключен. Только отслеживание IP-адресов.")
            print("[Этап] Проверка всех активных подключений при запуске...")
            check_all_active_connections(None, ping_interval)
                            
            while not stop_event.is_set():
                pid_name_map = get_pids_by_names(exe_list)
                if not pid_name_map:
                    print("[Этап] Не найдено ни одного отслеживаемого процесса. Ожидание...")
                    time.sleep(5)
                    continue
                    
                for pid, exe_name in pid_name_map.items():
                    connections = get_network_connections_by_pid(pid)
                    if connections:
                        for ip in connections:
                            if ip not in tracked_ips:
                                # Новый IP-адрес
                                tracked_ips.add(ip)
                                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                print(f"[{timestamp}] Новый IP для {exe_name}: {ip}")

                                with file_lock:
                                    with open(ip_file, 'a', encoding='utf-8') as f_ip:
                                        f_ip.write(f"[{timestamp}] {exe_name}: {ip}\n")

                                unique_keenetic_ips.add(ip)
                                
                                if enable_domain_tracking:
                                    # Получаем доменное имя для IP-адреса
                                    domain = get_domain_by_ip(ip)
                                    if domain and (ip, domain) not in tracked_domains:
                                        tracked_domains.add((ip, domain))
                                        print(f"[{timestamp}] Новый домен для {ip}: {domain}")
                                        log_domain(domain_file, ip, domain, exe_name, timestamp)
                                elif enable_domain_tracking:
                                    # Проверяем доменное имя для существующего IP-адреса
                                    domain = get_domain_by_ip(ip)
                                    if domain and (ip, domain) not in tracked_domains:
                                        tracked_domains.add((ip, domain))
                                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        print(f"[{timestamp}] Обнаружен домен для {ip}: {domain}")
                                        log_domain(domain_file, ip, domain, exe_name, timestamp)

                time.sleep(5)
    except KeyboardInterrupt:
        print("\n[Этап] Прерывание программы (Ctrl+C)")
        print("[Мониторинг] Завершение всех дочерних процессов...")
        kill_child_processes(os.getpid())
        stop_event.set()
        print("[Этап] Программа завершена.")
        # Ожидаем завершения всех активных задач
        if active_futures:
            print(f"Ожидание завершения {len(active_futures)} активных задач...")
            # Ждем завершения всех активных задач, но не более 5 секунд
            wait_time = 0
            while active_futures and wait_time < 5:
                active_futures = {f for f in active_futures if not f.done()}
                if active_futures:
                    time.sleep(0.5)
                    wait_time += 0.5
            if active_futures:
                print(f"Осталось {len(active_futures)} незавершенных задач. Принудительное завершение.")
                # Отменяем все незавершенные задачи (доступно в Python 3.9+)
                for future in active_futures:
                    if not future.done():
                        future.cancel()
            else:
                print("Все задачи успешно завершены.")

    # После завершения, агрегируем IP-адреса
    print(f"Агрегация {len(unique_keenetic_ips)} IP-адресов в подсети с маской /{subnet_mask}...")
    aggregated_subnets = group_ips_into_subnets(unique_keenetic_ips, subnet_mask)

    # Запись агрегированных команд маршрутизации в файл
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(keenetic_file, 'w', encoding='utf-8') as f:
        f.write(f"@echo off\n:: Файл создан {timestamp}\n:: Содержит {len(aggregated_subnets)} маршрутов\n\n")
        for subnet in sorted(aggregated_subnets):
            if subnet_mask == "24":
                mask = "255.255.255.0"
            elif subnet_mask == "16":
                mask = "255.255.0.0"
            elif subnet_mask == "32":
                mask = "255.255.255.255"
            else:
                continue
            network_address = subnet.split('/')[0]
            route_command = f"route ADD {network_address} MASK {mask} 0.0.0.0\n"
            f.write(route_command)
    
    print(f"Создано {len(aggregated_subnets)} маршрутов в файле {keenetic_file}")
    print(f"Всего отслежено {len(tracked_ips)} уникальных IP-адресов")

if __name__ == "__main__":
    main()
