import psutil
import time
import configparser
import os
import platform
import subprocess
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Флаг для остановки программы при получении сигнала
stop_event = None

# Функция для определения, является ли IP локальным
def is_local_ip(ip):
    if ip.startswith('127.') or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.') or ip == '::1':
        return True
    return False

# Получаем PID процесса по имени .exe
def get_pid_by_name(exe_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == exe_name:
            return proc.info['pid']
    return None

# Получаем сетевые подключения процесса по PID
def get_network_connections_by_pid(pid):
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.pid == pid and conn.raddr:
            remote_ip = conn.raddr.ip
            if not is_local_ip(remote_ip):
                connections.append(remote_ip)
    return connections

# Функция для пинга IP-адреса
def ping_ip(ip, ping_file, last_success_ping):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]  # Один пакет пинга

    try:
        # Если это Windows, принудительно декодируем вывод через cp866 и затем в utf-8
        if platform.system().lower() == 'windows':
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output = result.stdout.decode('cp866').encode('utf-8').decode('utf-8')
        else:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

        print(f"Ping output for {ip}:\n{output}")

        # Если пинг успешен
        if result.returncode == 0:
            avg_ping = None
            if platform.system().lower() == 'windows':
                # Для Windows ищем строку со средней задержкой
                for line in output.splitlines():
                    if "Среднее" in line:
                        print(f"Обработка строки: {line}")  # Диагностический вывод
                        avg_ping = line.split("=")[-1].replace("мсек", "").strip()  # Извлекаем пинг
                        break
            else:
                # Для Unix-подобных систем (Linux, macOS)
                for line in output.splitlines():
                    if 'rtt min/avg/max/mdev' in line:  # Обрабатываем строку с результатом
                        avg_ping = line.split('/')[1]  # Берем среднее значение (avg)
                        break

            avg_ping = avg_ping if avg_ping else "неизвестно"

            # Обновляем время последнего успешного пинга
            current_time = time.time()
            last_success_ping[ip] = current_time

            # Записываем результат пинга в лог-файл (в формате UTF-8)
            with open(ping_file, 'a', encoding='utf-8') as f_ping:
                f_ping.write(f"IP {ip} пингуется успешно. Средний пинг: {avg_ping} мс.\n")
            return True
        else:
            # Если пинг не успешен, проверяем, когда был последний успешный пинг
            last_ping_time = last_success_ping.get(ip)
            if last_ping_time:
                time_since_last_ping = time.time() - last_ping_time
                with open(ping_file, 'a', encoding='utf-8') as f_ping:
                    f_ping.write(f"IP {ip} не пингуется. Перестал отвечать через {round(time_since_last_ping, 2)} секунд.\n")
            else:
                with open(ping_file, 'a', encoding='utf-8') as f_ping:
                    f_ping.write(f"IP {ip} не пингуется с момента отслеживания.\n")
            return False
    except Exception as e:
        print(f"Ошибка выполнения пинга для {ip}: {e}")
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

    enable_ping = config.getint('Ping', 'enable_ping')

    return exe_list, ip_file, keenetic_file, ping_file, enable_ping

# Функция для отслеживания IP адресов процесса
def track_ips_by_process(exe_name, ip_file, keenetic_file, ping_file, enable_ping, unique_keenetic_ips):
    print(f"Запущено отслеживание для процесса {exe_name}...")

    pid = None
    while not stop_event.is_set():  # Ожидаем запуска процесса
        pid = get_pid_by_name(exe_name)
        if pid is not None:
            break
        time.sleep(2)

    print(f"Процесс {exe_name} найден с PID: {pid}")
    tracked_ips = set()  # Для хранения уникальных IP-адресов
    last_success_ping = {}  # Для хранения времени последнего успешного пинга

    while not stop_event.is_set():
        connections = get_network_connections_by_pid(pid)
        if connections:
            for ip in connections:
                if ip not in tracked_ips:
                    tracked_ips.add(ip)
                    print(f"Новый IP для {exe_name}: {ip}")

                    # Записываем в ip_file с указанием имени процесса
                    with open(ip_file, 'a') as f_ip:
                        f_ip.write(f"{exe_name}: {ip}\n")

                    # Проверяем на дубли в keenetic_file
                    if ip not in unique_keenetic_ips:
                        route_command = f"route ADD {ip} MASK 255.255.255.255 0.0.0.0\n"
                        with open(keenetic_file, 'a') as f_keenetic:
                            f_keenetic.write(route_command)
                        unique_keenetic_ips.add(ip)

                    # Если включен пинг, выполняем его
                    if enable_ping:
                        ping_ip(ip, ping_file, last_success_ping)
                elif enable_ping:
                    ping_ip(ip, ping_file, last_success_ping)

        time.sleep(5)

# Обработчик сигнала SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nОстановка программы...")
    stop_event.set()  # Останавливаем все запущенные задачи
    sys.exit(0)

# Основная функция для чтения конфигурации и запуска отслеживания процессов
def main():
    global stop_event
    stop_event = threading.Event()  # Инициализируем событие для остановки потоков

    # Устанавливаем обработчик сигнала Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    exe_list, ip_file, keenetic_file, ping_file, enable_ping = read_config()

    # Очищаем содержимое файлов перед записью новых данных
    open(ip_file, 'w').close()
    open(keenetic_file, 'w').close()
    if enable_ping:
        open(ping_file, 'w', encoding='utf-8').close()

    unique_keenetic_ips = set()  # Множество для хранения уникальных IP

    with ThreadPoolExecutor(max_workers=len(exe_list)) as executor:
        futures = []
        for exe_name in exe_list:
            futures.append(
                executor.submit(
                    track_ips_by_process, exe_name, ip_file, keenetic_file, ping_file, enable_ping, unique_keenetic_ips
                )
            )

        for future in as_completed(futures):
            try:
                future.result()  # Ожидаем выполнения
            except Exception as e:
                print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()
