import sys
import requests
import logging
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed


# Настройка логирования
logging.basicConfig(level=logging.INFO)

#ASCII-баннер ДА АНО
banner = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣶⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⣀⡀⣠⣾⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⡇⠀⠀⠀⠀
⠀⣶⣿⣦⣜⣿⣿⣿⡟⠻⣿⣿⣿⣿⣿⣿⣿⡿⢿⡏⣴⣺⣦⣙⣿⣷⣄⠀⠀⠀
⠀⣯⡇⣻⣿⣿⣿⣿⣷⣾⣿⣬⣥⣭⣽⣿⣿⣧⣼⡇⣯⣇⣹⣿⣿⣿⣿⣧⠀⠀
⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠸⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


CATSCAN v.1.0       Author: ~MidN1ght~

"""
print(banner)

# Определение службы по порту
def get_service_name(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP Alternate"
    }
    return services.get(port, "Unknown Service")


# Функция сканирования порта
def scan_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Установите таймаут на 1 секунду
        result = s.connect_ex((target, port))
        service_name = get_service_name(port)
        if result == 0 and service_name != "Unknown Service":
            logging.info(f"Открытый порт | {port} | {service_name}")
            return port, service_name
    return None


# Функция для сканирования портов и служб
def scan_ports_and_services(target):
    open_ports = []

    with ThreadPoolExecutor(max_workers=200) as executor:  # Увеличьте количество потоков
        future_to_port = {executor.submit(scan_port, target, port): port for port in range(1, 10240)}
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result[0])
                if result[1] == "SSH":
                    display_ssh_keys(target)  # Это можно сделать в отдельном потоке
                if result[1] in ["MySQL", "PostgreSQL"]:
                    logging.info(f"Обнаружена служба базы данных: {result[1]}")
                if result[0] in [80, 443]:
                    get_server_version(target, result[0])  # Это тоже можно в отдельном потоке

    return open_ports


def get_server_version(target, port):
    try:
        response = requests.get(f"http://{target}", timeout=5)
        server = response.headers.get('Server', 'Unknown Server')
        logging.info(f"Обнаружен веб-сервер: {server} на порту {port}")
    except requests.Timeout:
        logging.warning("Запрос к серверу превысил время ожидания.")
    except requests.RequestException as e:
        logging.error(f"Не удалось определить версию сервера: {e}")


# Отображение публичных SSH ключей
def display_ssh_keys(target):
    try:
        response = requests.get(f"http://{target}/.ssh/authorized_keys", timeout=5)
        if response.status_code == 200:
            logging.info("[+] Найдены публичные SSH ключи:")
            logging.info(response.text)
        else:
            logging.warning("[-] Публичные SSH ключи не найдены или доступ запрещён.")
    except requests.Timeout:
        logging.warning("Запрос на получение SSH ключей превысил время ожидания.")
    except requests.RequestException as e:
        logging.error(f"Не удалось получить SSH ключи: {e}")


# Обнаружение CMS
def detect_cms(url):

    cms_detected = []
    try:
        response = requests.get(url)
        if 'wp-content' in response.text:
            cms_detected.append("WordPress")
            logging.info(f"[+] Обнаружена CMS: WordPress по адресу {url}")
        if 'joomla' in response.text.lower():
            cms_detected.append("Joomla")
            logging.info(f"[+] Обнаружена CMS: Joomla по адресу {url}")
        if 'bitrix' in response.text.lower():
            cms_detected.append("Bitrix")
            logging.info(f"[+] Обнаружена CMS: Bitrix по адресу {url}")
        if 'drupal' in response.text.lower():
            cms_detected.append("Drupal")
            logging.info(f"[+] Обнаружена CMS: Drupal по адресу {url}")
        if not cms_detected:
            logging.warning("[-] Известные CMS не обнаружены.")
    except requests.RequestException as e:
        logging.error(f"Запрос не удался: {e}")
    return cms_detected


def detect_wordpress_usernames(url):
    usernames = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(requests.get, f"{url}/?author={i}"): i for i in range(1, 10)}
        for future in as_completed(futures):
            i = futures[future]
            try:
                response = future.result()
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        username = title_tag.text.split(' ')[0]
                        logging.info(f"[+] Найден пользователь WordPress: {username}")
                        usernames.append(username)
            except Exception as e:
                logging.error(f"Ошибка при получении пользователя WordPress {i}: {e}")
    return usernames


def detect_usernames(url, cms):
    usernames = []
    if "WordPress" in cms:
        usernames.extend(detect_wordpress_usernames(url))
    if "Joomla" in cms:
        usernames.extend(detect_joomla_usernames(url))
    if "Bitrix" in cms:
        usernames.extend(detect_bitrix_usernames(url))
    if "Drupal" in cms:
        usernames.extend(detect_drupal_usernames(url))
    return usernames


def detect_joomla_usernames(url):
    usernames = []
    user_url = f"{url}/index.php?option=com_users"
    try:
        response = requests.get(user_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta', attrs={"name": "author"})
            for meta in meta_tags:
                username = meta.get("content")
                if username:
                    logging.info(f"[+] Найден пользователь Joomla: {username}")
                    usernames.append(username)
    except Exception as e:
        logging.error(f"Ошибка при получении пользователей Joomla: {e}")
    return usernames


def detect_bitrix_usernames(url):
    usernames = []
    user_url = f"{url}/bitrix/admin/user_edit.php"
    try:
        response = requests.get(user_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            user_tags = soup.find_all('input', {'name': 'LOGIN'})
            for tag in user_tags:
                username = tag.get('value')
                if username:
                    logging.info(f"[+] Найден пользователь Bitrix: {username}")
                    usernames.append(username)
    except Exception as e:
        logging.error(f"Ошибка при получении пользователей Bitrix: {e}")
    return usernames


def detect_drupal_usernames(url):
    usernames = []
    user_url = f"{url}/user"
    try:
        response = requests.get(user_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            user_tags = soup.find_all('a', href=True)
            for tag in user_tags:
                if '/user/' in tag['href']:
                    username = tag.text
                    logging.info(f"[+] Найден пользователь Drupal: {username}")
                    usernames.append(username)
    except Exception as e:
        logging.error(f"Ошибка при получении пользователей Drupal: {e}")
    return usernames


def load_dir_list(file_path):
    """Загружает список директорий из файла."""
    try:
        with open(file_path, 'r') as f:
            dir_list = [line.strip() for line in f if line.strip()]  # Убираем лишние пробелы и пустые строки
        return dir_list
    except FileNotFoundError:
        logging.error(f"Файл {file_path} не найден.")
        return []
    except Exception as e:
        logging.error(f"Ошибка при чтении файла {file_path}: {e}")
        return []


def scan_directory(url, path):

    full_url = f"{url}/{path}"
    try:
        response = requests.get(full_url, timeout=3)  # Установите таймаут
        if response.status_code >= 200 and response.status_code < 400:
            logging.info(f"{Fore.GREEN}[+] Найдено: {full_url} (Статус: {response.status_code}){Style.RESET_ALL}")
        elif response.status_code == 403 or response.status_code >= 500:
            logging.info(f"{Fore.BLUE}[+] Найдено: {full_url} (Статус: {response.status_code}){Style.RESET_ALL}")
    except requests.RequestException as e:
        logging.error(f"Ошибка доступа к {full_url}: {e}")

def scan_directories_and_pages(url, dir_list):
    with ThreadPoolExecutor(max_workers=20) as executor:  # Выберите подходящее количество потоков
        # Отправляем запросы параллельно
        futures = {executor.submit(scan_directory, url, path): path for path in dir_list}
        for future in as_completed(futures):
            future.result()  # Обработка результатов (можно оставить пустым, если не нужно)

def main():
    url = input("Введите целевой URL (сайт или IP адрес): ")
    find_cms = input("Нужно ли находить CMS и юзернеймы? (Y/N): ").strip().lower()
    find_directories = input("Нужно ли сканировать директории и страницы? (Y/N): ").strip().lower()

    # Добавление http://, если схема не указана
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Проверка и извлечение целевого адреса из URL
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        logging.error("Некорректный формат URL. Пожалуйста, включите действующую схему (http или https).")
        return
    target = parsed_url.netloc  # Извлекаем целевой адрес

    # Сканирование портов и служб
    open_ports = scan_ports_and_services(target)

    if not open_ports:
        logging.warning("Не найдены открытые порты с известными службами. Выход.")
        return

    # Запрос на нахождение CMS и юзернеймов
    cms = []
    if find_cms == 'y':
        cms = detect_cms(url)
        if cms:
            detected_usernames = detect_usernames(url, cms)
            if detected_usernames:
                logging.info("[+] Найденные пользователи:")
                for username in detected_usernames:
                    logging.info(username)
            else:
                logging.warning("Пользователи не найдены.")

    # Запрос на сканирование директорий и страниц
    if find_directories == 'y':
        dir_list = load_dir_list('dir_list.txt')  # Замените на свой список
        scan_directories_and_pages(url, dir_list)

    # Явное завершение программы
    logging.info("Сканирование завершено.")
    sys.exit(0)

if __name__ == "__main__":
    main()
