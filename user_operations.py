import random
import string
import iuliia
from ldap3 import MODIFY_ADD
import email_utils
import zimbra_utils
import paramiko

def generate_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))


def create_user(conn, base_dn, full_name, selected_groups_dn, selected_ou_dn, wiki, office_login, owncloud, logger):
    if not full_name.strip():
        logger("Ошибка: Введите имя и фамилию")
        return False

    parts = full_name.strip().split()
    if len(parts) < 2:
        logger("Ошибка: Введите имя и фамилию")
        return False

    first_name = parts[0].capitalize()
    last_name = parts[1].capitalize()
    username = f"{iuliia.WIKIPEDIA.translate(first_name).lower()}_{iuliia.WIKIPEDIA.translate(last_name).lower()}"
    password = generate_password()
    display_name = f"{first_name} {last_name}"

    logger(f"Создание пользователя {display_name} (логин: {username}, пароль: {password})...")

    try:
        user_dn = f"CN={display_name},{selected_ou_dn}" if selected_ou_dn else f"CN={display_name},CN=Users,{base_dn}"
        conn.add(
            dn=user_dn,
            object_class=['top', 'person', 'organizationalPerson', 'user'],
            attributes={
                'cn': display_name,
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@office.targem.ru",
                'mail': f"{username}@office.targem.ru",
                'displayName': display_name,
                'givenName': first_name,
                'sn': last_name
            }
        )
        if conn.result['description'] != 'success':
            logger(f"Ошибка создания: {conn.result}")
            return False

        # пароль + включение учётки
        conn.extend.microsoft.modify_password(user_dn, password)
        conn.modify(user_dn, {'userAccountControl': [(2, [512])]})

        # Добавление в группы
        added_groups = []
        for group_cn, group_dn in selected_groups_dn:
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
            logger(f"{username} добавлен в группу {group_cn}")
            added_groups.append(group_cn)

        # Создание почты
        email = zimbra_utils.create_zimbra_mail(
            username, password, first_name, last_name, display_name,
            outsource="outsource" if "owncloud_outsrc" in added_groups else "internal"
        )
        if email:
            logger(f"Почта создана: {email}")

        # Доп. сервисы по чекбоксам (заглушки под ваши API)
        if wiki:
            logger("Создаём учётную запись в Wiki (TODO: интеграция API)...")
        if office_login:
            logger("Логиним пользователя в office.targem.ru (TODO: интеграция API)...")
        if owncloud:
            if "owncloud_outsrc" in added_groups:
                logger("Добавляем пользователя в OwnCloud (TODO: интеграция API)...")
            else:
                logger("OwnCloud: пропуск — не выбрана группа owncloud_outsrc.")

        # Уведомление IT
        email_utils.send_email(username, password, email, added_groups, display_name)
        return True

    except Exception as e:
        logger(f"Ошибка: {str(e)}")
        return False


def delete_user(conn, base_dn, username, delete_mail=False, block_mail=False, logger=None):
    if not username.strip():
        if logger:
            logger("Ошибка: Введите логин для удаления")
        return False

    if logger:
        logger(f"Удаление пользователя {username}...")

    conn.search(search_base=base_dn, search_filter=f"(sAMAccountName={username})", attributes=["distinguishedName"])
    if not conn.entries:
        if logger:
            logger(f"Пользователь {username} не найден")
        return False

    user_dn = conn.entries[0].distinguishedName.value
    if not conn.delete(user_dn):
        if logger:
            logger(f"Ошибка удаления в AD: {conn.result}")
        return False

    if logger:
        logger(f"Пользователь {username} удалён из AD")

    # Почтовые действия
    if delete_mail or block_mail:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=zimbra_utils.ZIMBRA_HOST, username=zimbra_utils.ZIMBRA_USER,
                           key_filename=zimbra_utils.ZIMBRA_KEY)
            email = f"{username}@office.targem.ru"
            if delete_mail:
                client.exec_command(f"/opt/zimbra/bin/zmprov da {email}")
                if logger:
                    logger(f"Почта {email} удалена")
            elif block_mail:
                client.exec_command(f"/opt/zimbra/bin/zmprov ma {email} zimbraAccountStatus closed")
                if logger:
                    logger(f"Почта {email} заблокирована")
            client.close()
        except Exception as e:
            if logger:
                logger(f"Ошибка при работе с Zimbra: {e}")

    return True