import requests
import time
import tkinter as tk
from tkinter import simpledialog


def get_wiki_admin_credentials(parent_window):
    """Запрос логина и пароля администратора Wiki через диалоговые окна"""
    # Запрашиваем логин администратора
    admin_login = simpledialog.askstring(
        "Логин администратора Wiki",
        "Введите логин администратора Wiki:",
        parent=parent_window,
        initialvalue="Administrator"
    )

    if not admin_login:
        return None, None

    # Запрашиваем пароль администратора
    admin_password = simpledialog.askstring(
        "Пароль администратора Wiki",
        "Введите пароль администратора Wiki:",
        parent=parent_window,
        show='*'
    )

    return admin_login, admin_password


def wiki_login_routine(username, password, parent_window, logger=None):
    """Автоматический вход пользователя в wiki и добавление в группу targem"""
    WIKI_API_ENDPOINT = "https://wiki.targem.ru/api.php"

    # Получаем логин и пароль администратора
    admin_login, admin_password = get_wiki_admin_credentials(parent_window)
    if not admin_login or not admin_password:
        if logger:
            logger("Ошибка: Не введены учетные данные администратора wiki")
        return False

    if logger:
        logger(f"Получены учетные данные администратора wiki: {admin_login}")
        logger("Попытка входа пользователя в wiki... ждем 60 секунд")

    time.sleep(60)  # Ждем 60 секунд

    try:
        # Попробуем использовать старый метод с секретным ключом (как в оригинальном bash-скрипте)
        WIKI_API_ENDPOINT_WITH_SECRET = "https://wiki.targem.ru/api.php?secret=nh1AHxMWRv5H"

        if logger:
            logger("Попытка входа с использованием секретного ключа...")

        # 1. Первый вход пользователя (старый метод)
        if logger:
            logger("Первый вход пользователя в wiki")

        # Получаем токен для пользователя (старый метод)
        token_url = f"{WIKI_API_ENDPOINT_WITH_SECRET}&format=json&lgdomain=TARGEM.LOCAL&action=login&lgname={username}&lgpassword={password}&lgtoken="
        response = requests.post(token_url, timeout=30)
        token_data = response.json()
        user_token = token_data.get('login', {}).get('token', '')

        if not user_token:
            if logger:
                logger("Ошибка: Не удалось получить токен для пользователя (старый метод)")
                logger(f"Ответ сервера: {token_data}")
            return False

        # Входим пользователем (старый метод)
        login_url = f"{WIKI_API_ENDPOINT_WITH_SECRET}&format=json&lgdomain=TARGEM.LOCAL&action=login&lgname={username}&lgpassword={password}&lgtoken={user_token}"
        login_response = requests.post(login_url, timeout=30)
        login_data = login_response.json()
        login_result = login_data.get('login', {}).get('result', '')

        if login_result != 'Success':
            if logger:
                logger(f"Ошибка входа пользователя: {login_result}")
                logger(f"Детали ошибки: {login_data}")
            return False

        if logger:
            logger("Пользователь успешно вошел в wiki")

        time.sleep(10)

        # 2. Вход администратором для управления группами (старый метод)
        if logger:
            logger("Вход администратором для управления группами")

        # Получаем токен для администратора (старый метод)
        admin_token_url = f"{WIKI_API_ENDPOINT_WITH_SECRET}&format=json&lgdomain=TARGEM.LOCAL&action=login&lgname={admin_login}&lgpassword={admin_password}&lgtoken="
        admin_response = requests.post(admin_token_url, timeout=30)
        admin_token_data = admin_response.json()
        admin_token = admin_token_data.get('login', {}).get('token', '')

        if not admin_token:
            if logger:
                logger("Ошибка: Не удалось получить токен для администратора (старый метод)")
                logger(f"Ответ сервера: {admin_token_data}")
            return False

        # Входим администратором (старый метод)
        admin_login_url = f"{WIKI_API_ENDPOINT_WITH_SECRET}&format=json&lgdomain=TARGEM.LOCAL&action=login&lgname={admin_login}&lgpassword={admin_password}&lgtoken={admin_token}"
        admin_login_response = requests.post(admin_login_url, timeout=30)
        admin_login_data = admin_login_response.json()
        admin_login_result = admin_login_data.get('login', {}).get('result', '')

        if admin_login_result != 'Success':
            if logger:
                logger(f"Ошибка входа администратора: {admin_login_result}")
                logger(f"Детали ошибки: {admin_login_data}")
            return False

        # Сохраняем куки из ответа
        admin_cookies = admin_login_response.cookies

        if logger:
            logger("Администратор успешно вошел в wiki")

        # 3. Получаем токен для управления правами пользователя (старый метод)
        if logger:
            logger("Получение токена для управления правами...")

        userrights_token_url = f"{WIKI_API_ENDPOINT_WITH_SECRET}&action=query&list=users&ususers={username}&format=json&ustoken=userrights"
        userrights_response = requests.post(userrights_token_url, cookies=admin_cookies, timeout=30)
        userrights_data = userrights_response.json()

        # Извлекаем токен из ответа (может быть в разных форматах)
        userrights_token = None
        if 'query' in userrights_data and 'users' in userrights_data['query']:
            users = userrights_data['query']['users']
            if users and 'userrightstoken' in users[0]:
                userrights_token = users[0]['userrightstoken']

        if not userrights_token:
            if logger:
                logger("Ошибка: Не удалось получить токен управления правами")
                logger(f"Ответ сервера: {userrights_data}")
            return False

        # 4. Добавляем пользователя в группу targem (старый метод)
        if logger:
            logger("Добавление пользователя в группу targem...")

        add_group_url = f"{WIKI_API_ENDPOINT_WITH_SECRET}&action=userrights&user={username}&format=json&add=targem&token={userrights_token}"
        add_group_response = requests.post(add_group_url, cookies=admin_cookies, timeout=30)

        if add_group_response.status_code == 200:
            try:
                add_group_data = add_group_response.json()
                if logger:
                    logger(f"Ответ сервера на добавление в группу: {add_group_data}")

                if 'userrights' in add_group_data and 'added' in add_group_data['userrights']:
                    if logger:
                        logger(f"Пользователь {username} успешно добавлен в группу targem в wiki")
                    return True
                else:
                    if logger:
                        logger("Пользователь добавлен, но ответ сервера не содержит ожидаемых данных")
                    return True
            except:
                # Если не удалось распарсить JSON, но статус 200 - вероятно успех
                if logger:
                    logger(f"Пользователь {username} добавлен в группу targem (статус 200)")
                return True
        else:
            if logger:
                logger(f"Ошибка добавления в группу: {add_group_response.status_code}")
                logger(f"Текст ответа: {add_group_response.text}")
            return False

    except requests.exceptions.Timeout:
        if logger:
            logger("Ошибка: Таймаут при подключении к wiki")
        return False
    except requests.exceptions.ConnectionError:
        if logger:
            logger("Ошибка: Не удалось подключиться к wiki")
        return False
    except Exception as e:
        if logger:
            logger(f"Ошибка при работе с wiki API: {str(e)}")
        return False