import paramiko
from constants import ZIMBRA_HOST, ZIMBRA_USER, ZIMBRA_KEY

def create_zimbra_mail(username, password, first_name, last_name, display_name, outsource="internal"):
    """Создание почтового ящика в Zimbra через SSH ключ"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=ZIMBRA_HOST, username=ZIMBRA_USER, key_filename=ZIMBRA_KEY)

        email = f"{username}@office.targem.ru"
        cmd_create = f"/opt/zimbra/bin/zmprov ca {email} {password} displayName '{display_name}' givenName '{first_name}' sn '{last_name}'"
        _, stdout, stderr = client.exec_command(cmd_create)
        error = stderr.read().decode()
        if error:
            print(f"Ошибка Zimbra: {error}")
        else:
            print(f"Почта {email} создана.")

        # пример рассылок — выполняется для внутренних (не аутсорс)
        if outsource != "outsource":
            for dl in ["targem@office.targem.ru", "laters@office.targem.ru"]:
                _, stdout, stderr = client.exec_command(f"/opt/zimbra/bin/zmprov adlm {dl} {email}")
                dl_error = stderr.read().decode()
                if dl_error:
                    print(f"Ошибка добавления в рассылку {dl}: {dl_error}")
                else:
                    print(f"{email} добавлен в рассылку {dl}")

        client.close()
        return email
    except Exception as e:
        print(f"Ошибка подключения к Zimbra: {e}")
        return None