import smtplib
from email.mime.text import MIMEText
from constants import SMTP_SERVER, SMTP_PORT, MAIL_FROM, MAIL_TO

def send_email(username, password, email, groups, display_name):
    """Отправка письма с данными нового пользователя"""
    try:
        groups_str = ", ".join(groups) if groups else "нет"
        body = f"""
Создан новый пользователь в AD и Zimbra:

ФИО: {display_name}
Логин: {username}
Пароль: {password}
Email: {email}
Группы: {groups_str}
"""
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"Создан пользователь: {display_name}"
        msg["From"] = MAIL_FROM
        msg["To"] = MAIL_TO

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(MAIL_FROM, [MAIL_TO], msg.as_string())
    except Exception as e:
        print(f"Ошибка отправки письма: {e}")