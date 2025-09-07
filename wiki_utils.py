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
        # 1. Вход пользователя (старый метод - как в bash скрипте)
        if logger:
            logger("Вход пользователя в wiki...")

        user_session = requests.Session()

        # Первый запрос для получения токена (как в оригинальном bash скрипте)
        token_params = {
            'action': 'login',
            'lgname': username,
            'lgpassword': password,
            'lgdomain': 'TARGEM.LOCAL',
            'format': 'json'
        }

        token_response = user_session.post(WIKI_API_ENDPOINT, data=token_params, timeout=30)
        token_data = token_response.json()
        user_token = token_data.get('login', {}).get('token', '')

        if not user_token:
            if logger:
                logger("Ошибка: Не удалось получить токен для пользователя")
                logger(f"Ответ сервера: {token_data}")
            return False

        if logger:
            logger(f"Получен токен пользователя: {user_token}")

        # Входим пользователем с токеном
        login_params = {
            'action': 'login',
            'lgname': username,
            'lgpassword': password,
            'lgtoken': user_token,
            'lgdomain': 'TARGEM.LOCAL',
            'format': 'json'
        }

        login_response = user_session.post(WIKI_API_ENDPOINT, data=login_params, timeout=30)
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

        # 2. Вход администратором (старый метод)
        if logger:
            logger("Вход администратором для управления группами...")

        admin_session = requests.Session()

        # Получаем токен для администратора
        admin_token_params = {
            'action': 'login',
            'lgname': admin_login,
            'lgpassword': admin_password,
            'lgdomain': 'TARGEM.LOCAL',
            'format': 'json'
        }

        admin_token_response = admin_session.post(WIKI_API_ENDPOINT, data=admin_token_params, timeout=30)
        admin_token_data = admin_token_response.json()
        admin_token = admin_token_data.get('login', {}).get('token', '')

        if not admin_token:
            if logger:
                logger("Ошибка: Не удалось получить токен для администратора")
                logger(f"Ответ сервера: {admin_token_data}")
            return False

        if logger:
            logger(f"Получен токен администратора: {admin_token}")

        # Входим администратором с токеном
        admin_login_params = {
            'action': 'login',
            'lgname': admin_login,
            'lgpassword': admin_password,
            'lgtoken': admin_token,
            'lgdomain': 'TARGEM.LOCAL',
            'format': 'json'
        }

        admin_login_response = admin_session.post(WIKI_API_ENDPOINT, data=admin_login_params, timeout=30)
        admin_login_data = admin_login_response.json()
        admin_login_result = admin_login_data.get('login', {}).get('result', '')

        if admin_login_result != 'Success':
            if logger:
                logger(f"Ошибка входа администратора: {admin_login_result}")
                logger(f"Детали ошибки: {admin_login_data}")
            return False

        if logger:
            logger("Администратор успешно вошел в wiki")

        # 3. Получаем токен для управления правами (старый метод)
        if logger:
            logger("Получение токена для управления правами...")

        # Используем старый метод получения токена прав (как в bash скрипте)
        userrights_token_params = {
            'action': 'query',
            'list': 'users',
            'ususers': username,
            'ustoken': 'userrights',
            'format': 'json'
        }

        userrights_response = admin_session.get(WIKI_API_ENDPOINT, params=userrights_token_params, timeout=30)
        userrights_data = userrights_response.json()

        # Извлекаем токен из ответа (старый формат)
        userrights_token = None
        if 'query' in userrights_data and 'users' in userrights_data['query']:
            users = userrights_data['query']['users']
            if users and len(users) > 0:
                userrights_token = users[0].get('userrightstoken', '')

        if not userrights_token:
            if logger:
                logger("Ошибка: Не удалось получить токен управления правами")
                logger(f"Ответ сервера: {userrights_data}")

            # Попробуем альтернативный метод - получить токен через action=query&meta=tokens
            try:
                token_params_alt = {
                    'action': 'query',
                    'meta': 'tokens',
                    'type': 'userrights',
                    'format': 'json'
                }

                token_response_alt = admin_session.get(WIKI_API_ENDPOINT, params=token_params_alt, timeout=30)
                token_data_alt = token_response_alt.json()
                userrights_token = token_data_alt.get('query', {}).get('tokens', {}).get('userrightstoken', '')

                if not userrights_token:
                    if logger:
                        logger("Альтернативный метод также не сработал")
                    return False
            except:
                if logger:
                    logger("Альтернативный метод получения токена не сработал")
                return False

        if logger:
            logger(f"Получен токен управления правами: {userrights_token}")

        # 4. Добавляем пользователя в группу targem (старый метод)
        if logger:
            logger("Добавление пользователя в группу targem...")

        add_group_params = {
            'action': 'userrights',
            'user': username,
            'add': 'targem',
            'token': userrights_token,
            'format': 'json'
        }

        add_group_response = admin_session.post(WIKI_API_ENDPOINT, data=add_group_params, timeout=30)
        add_group_data = add_group_response.json()

        if add_group_response.status_code == 200:
            # Проверяем различные возможные форматы успешного ответа
            success = False
            if 'userrights' in add_group_data:
                success = True
            elif 'error' in add_group_data and 'already in' in add_group_data['error'].get('info', '').lower():
                success = True
            elif 'success' in str(add_group_data).lower():
                success = True

            if success:
                if logger:
                    logger(f"Пользователь {username} успешно добавлен в группу targem в wiki")
                    logger(f"Ответ сервера: {add_group_data}")
                return True
            else:
                if logger:
                    logger(f"Неожиданный ответ сервера: {add_group_data}")
                return False
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

#work