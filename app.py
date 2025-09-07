import tkinter as tk
from tkinter import messagebox, ttk
import ttkbootstrap as tb
from ldap3 import Server, Connection, ALL, MODIFY_ADD
import random
import string
import iuliia
import paramiko
import smtplib
from email.mime.text import MIMEText

# ---------------- Глобальные переменные ----------------
conn = None
GROUPS = []
OUS = []
BASE_DN = None

PROTECTED_GROUPS = [
    'Domain Admins', 'Administrators', 'Enterprise Admins', 'Protected Users',
    'Incoming Forest Trust Builders', 'Print Operators', 'Pre-Windows 2000 Compatible Access',
    'Guests', 'Backup Operators', 'Schema Admins', 'Allowed RODC Password Replication Group',
    'Network Configuration Operators', 'Replicator', 'Domain Guests',
    'Terminal Server License Servers', 'Domain Controllers', 'Certificate Service DCOM Access',
    'Cert Publishers', 'Enterprise Read-only Domain Controllers', 'IIS_IUSRS', 'DnsAdmins',
    'Performance Monitor Users', 'Account Operators', 'Server Operators', 'Event Log Readers',
    'DnsUpdateProxy', 'Distributed COM Users', 'Group Policy Creator Owners',
    'Read-only Domain Controllers', 'RAS and IAS Servers', 'Cryptographic Operators',
    'Denied RODC Password Replication Group', 'Performance Log Users',
    'Windows Authorization Access Group', 'Domain Computers'
]

ZIMBRA_HOST = "192.168.20.2"
ZIMBRA_USER = "root"
ZIMBRA_KEY = r"C:\Users\vladimir_svyazhin\.ssh\vladmir_svyazhin"

SMTP_SERVER = "192.168.20.2"  # Zimbra SMTP
SMTP_PORT = 25
MAIL_FROM = "noreply@office.targem.ru"
MAIL_TO = "it@office.targem.ru"

# ---------------- Вспомогательные функции ----------------
def generate_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

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

def create_connection(server_address, domain, admin_user, admin_pass):
    server = Server(server_address, use_ssl=True, get_info=ALL)
    try:
        connection = Connection(
            server,
            user=f"{admin_user}@{domain}",
            password=admin_pass,
            authentication='SIMPLE',
            auto_bind=True
        )
        return connection
    except Exception as e:
        messagebox.showerror("Ошибка подключения", str(e))
        return None

def get_groups():
    global conn
    if not conn:
        return []
    conn.search(search_base=BASE_DN, search_filter='(objectClass=group)',
                attributes=['cn', 'distinguishedName', 'groupType'])
    groups = []
    for entry in conn.entries:
        cn = entry.cn.value
        dn = entry.distinguishedName.value
        gtype = entry.groupType.value
        # Только глобальные/универсальные группы безопасности, исключая защищённые
        if gtype and (gtype & 0x80000000) and cn not in PROTECTED_GROUPS:
            groups.append((cn, dn))
    return groups

def get_ous():
    global conn
    if not conn:
        return []
    conn.search(search_base=BASE_DN, search_filter='(objectClass=organizationalUnit)',
                attributes=['ou', 'distinguishedName'])
    return [(entry.ou.value, entry.distinguishedName.value) for entry in conn.entries]

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

# ---------------- Создание/Удаление пользователей ----------------
def create_user(full_name, selected_groups_dn, selected_ou_dn, window, wiki, office_login, owncloud):
    global conn, BASE_DN
    if not full_name.strip():
        messagebox.showerror("Ошибка", "Введите имя и фамилию")
        return

    parts = full_name.strip().split()
    if len(parts) < 2:
        messagebox.showerror("Ошибка", "Введите имя и фамилию")
        return

    first_name = parts[0].capitalize()
    last_name = parts[1].capitalize()
    username = f"{iuliia.WIKIPEDIA.translate(first_name).lower()}_{iuliia.WIKIPEDIA.translate(last_name).lower()}"
    password = generate_password()
    display_name = f"{first_name} {last_name}"

    window.log(f"Создание пользователя {display_name} (логин: {username}, пароль: {password})...")

    try:
        user_dn = f"CN={display_name},{selected_ou_dn}" if selected_ou_dn else f"CN={display_name},CN=Users,{BASE_DN}"
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
            window.log(f"Ошибка создания: {conn.result}")
            messagebox.showerror("Ошибка", f"Не удалось создать пользователя: {conn.result}")
            return

        # пароль + включение учётки
        conn.extend.microsoft.modify_password(user_dn, password)
        conn.modify(user_dn, {'userAccountControl': [(2, [512])]})

        # Добавление в группы
        added_groups = []
        for group_cn, group_dn in selected_groups_dn:
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
            window.log(f"{username} добавлен в группу {group_cn}")
            added_groups.append(group_cn)

        # Создание почты
        email = create_zimbra_mail(
            username, password, first_name, last_name, display_name,
            outsource="outsource" if "owncloud_outsrc" in added_groups else "internal"
        )
        if email:
            window.log(f"Почта создана: {email}")

        # Доп. сервисы по чекбоксам (заглушки под ваши API)
        if wiki:
            window.log("Создаём учётную запись в Wiki (TODO: интеграция API)...")
        if office_login:
            window.log("Логиним пользователя в office.targem.ru (TODO: интеграция API)...")
        if owncloud:
            if "owncloud_outsrc" in added_groups:
                window.log("Добавляем пользователя в OwnCloud (TODO: интеграция API)...")
            else:
                window.log("OwnCloud: пропуск — не выбрана группа owncloud_outsrc.")

        # Уведомление IT
        send_email(username, password, email, added_groups, display_name)

    except Exception as e:
        window.log(f"Ошибка: {str(e)}")
        messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")

def delete_user(username, window, delete_mail=False, block_mail=False):
    global conn
    if not username.strip():
        messagebox.showerror("Ошибка", "Введите логин для удаления")
        return
    window.log(f"Удаление пользователя {username}...")

    conn.search(search_base=BASE_DN, search_filter=f"(sAMAccountName={username})", attributes=["distinguishedName"])
    if not conn.entries:
        window.log(f"Пользователь {username} не найден")
        messagebox.showerror("Ошибка", f"Пользователь {username} не найден")
        return

    user_dn = conn.entries[0].distinguishedName.value
    if not conn.delete(user_dn):
        window.log(f"Ошибка удаления в AD: {conn.result}")
        messagebox.showerror("Ошибка", f"Не удалось удалить пользователя в AD: {conn.result}")
        return

    window.log(f"Пользователь {username} удалён из AD")

    # Почтовые действия
    if delete_mail or block_mail:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ZIMBRA_HOST, username=ZIMBRA_USER, key_filename=ZIMBRA_KEY)
            email = f"{username}@office.targem.ru"
            if delete_mail:
                client.exec_command(f"/opt/zimbra/bin/zmprov da {email}")
                window.log(f"Почта {email} удалена")
            elif block_mail:
                client.exec_command(f"/opt/zimbra/bin/zmprov ma {email} zimbraAccountStatus closed")
                window.log(f"Почта {email} заблокирована")
            client.close()
        except Exception as e:
            window.log(f"Ошибка при работе с Zimbra: {e}")

# ---------------- GUI ----------------
class MainWindow:
    def __init__(self, master):
        self.root = tb.Toplevel(master)
        self.root.title("Управление пользователями AD")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.logout)

        self.tabs = ttk.Notebook(self.root)
        self.tab_create = tb.Frame(self.tabs)
        self.tab_delete = tb.Frame(self.tabs)
        self.tabs.add(self.tab_create, text="Создание пользователя")
        self.tabs.add(self.tab_delete, text="Удаление пользователя")
        self.tabs.pack(expand=1, fill="both")

        self.setup_create_tab()
        self.setup_delete_tab()
        self.setup_log()

        tb.Button(self.root, text="Выход / Разлогиниться", bootstyle="danger", command=self.logout).pack(pady=5)

    # Лог с контекстным меню
    def setup_log(self):
        self.log_frame = tb.Frame(self.root)
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(self.log_frame, height=12, font=("Arial", 10))
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_scroll = ttk.Scrollbar(self.log_frame, command=self.log_text.yview)
        self.log_scroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=self.log_scroll.set)
        self.log_text.bind("<Button-3>", self.show_context_menu)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Копировать", command=self.copy_log)

    def show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def copy_log(self):
        text = self.log_text.get("sel.first", "sel.last") if self.log_text.tag_ranges("sel") else self.log_text.get("1.0", "end")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def log(self, message):
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")

    # Вкладка «Создание»
    def setup_create_tab(self):
        tb.Label(self.tab_create, text="Имя и фамилия (например: Иван Петров):").pack(pady=5)
        self.entry_fullname = tb.Entry(self.tab_create)
        self.entry_fullname.pack(pady=5, fill="x", padx=10)

        tb.Label(self.tab_create, text="Выберите OU:").pack(pady=5)
        self.ou_combobox = ttk.Combobox(self.tab_create, values=[ou[0] for ou in OUS], state="readonly")
        self.ou_combobox.pack(pady=5, fill="x", padx=10)
        if OUS:
            self.ou_combobox.current(0)

        tb.Label(self.tab_create, text="Добавить в группы:").pack(pady=5)
        self.groups_listbox = tk.Listbox(self.tab_create, selectmode="multiple", height=10)
        self.groups_listbox.pack(pady=5, fill="both", padx=10, expand=True)
        for grp_cn, _ in GROUPS:
            self.groups_listbox.insert("end", grp_cn)

        # Чекбоксы (в строку)
        opts_frame = tb.Frame(self.tab_create)
        opts_frame.pack(pady=10, fill="x", padx=10)
        self.chk_wiki = tk.IntVar()
        self.chk_office = tk.IntVar()
        self.chk_owncloud = tk.IntVar()

        tk.Checkbutton(opts_frame, text="Создать в Wiki", variable=self.chk_wiki).grid(row=0, column=0, sticky="w", padx=10)
        tk.Checkbutton(opts_frame, text="Залогинить в office.targem.ru", variable=self.chk_office).grid(row=0, column=1, sticky="w", padx=10)
        tk.Checkbutton(opts_frame, text="Добавить в OwnCloud (аутсорс)", variable=self.chk_owncloud).grid(row=0, column=2, sticky="w", padx=10)

        tb.Button(self.tab_create, text="Создать пользователя", bootstyle="success", command=self.create_user_action).pack(pady=15)

    # Вкладка «Удаление»
    def setup_delete_tab(self):
        tb.Label(self.tab_delete, text="Логин для удаления (sAMAccountName):").pack(pady=5)
        self.entry_delete = tb.Entry(self.tab_delete)
        self.entry_delete.pack(pady=5, fill="x", padx=10)

        # Чекбоксы почты
        checks = tb.Frame(self.tab_delete)
        checks.pack(pady=5, fill="x", padx=10)
        self.chk_delete_mail = tk.IntVar()
        self.chk_block_mail = tk.IntVar()
        tk.Checkbutton(checks, text="Удалить почту", variable=self.chk_delete_mail).grid(row=0, column=0, sticky="w", padx=10)
        tk.Checkbutton(checks, text="Блокировать почту", variable=self.chk_block_mail).grid(row=0, column=1, sticky="w", padx=10)

        tb.Button(self.tab_delete, text="Удалить пользователя", bootstyle="danger", command=self.delete_user_action).pack(pady=15)

    def logout(self):
        global conn, GROUPS, OUS, BASE_DN
        conn = None
        GROUPS = []
        OUS = []
        BASE_DN = None
        self.root.destroy()
        self.root.master.deiconify()

    def create_user_action(self):
        selected_indices = self.groups_listbox.curselection()
        selected_groups_dn = [GROUPS[i] for i in selected_indices]
        selected_ou_dn = None
        if self.ou_combobox.get():
            for ou_name, ou_dn in OUS:
                if ou_name == self.ou_combobox.get():
                    selected_ou_dn = ou_dn
                    break
        create_user(
            self.entry_fullname.get(),
            selected_groups_dn,
            selected_ou_dn,
            self,
            self.chk_wiki.get(),
            self.chk_office.get(),
            self.chk_owncloud.get()
        )

    def delete_user_action(self):
        delete_user(self.entry_delete.get(), self, self.chk_delete_mail.get(), self.chk_block_mail.get())

# ---------------- Окно авторизации ----------------
class LoginWindow:
    def __init__(self):
        self.root = tb.Window(themename="superhero")
        self.root.title("Авторизация")
        self.root.geometry("600x400")

        tb.Label(self.root, text="Адрес LDAP-сервера:").pack(pady=5)
        self.entry_server = tb.Entry(self.root); self.entry_server.pack(pady=5)
        tb.Label(self.root, text="Домен:").pack(pady=5)
        self.entry_domain = tb.Entry(self.root); self.entry_domain.pack(pady=5)
        tb.Label(self.root, text="Логин администратора:").pack(pady=5)
        self.entry_user = tb.Entry(self.root); self.entry_user.pack(pady=5)
        tb.Label(self.root, text="Пароль:").pack(pady=5)
        self.entry_pass = tb.Entry(self.root, show="*"); self.entry_pass.pack(pady=5)

        tb.Button(self.root, text="Войти", bootstyle="success", command=self.login).pack(pady=15)
        tb.Button(self.root, text="Выход", bootstyle="danger", command=self.root.destroy).pack(pady=5)

        self.root.mainloop()

    def login(self):
        global conn, GROUPS, OUS, BASE_DN
        server_address = self.entry_server.get().strip()
        domain = self.entry_domain.get().strip()
        admin_user = self.entry_user.get().strip()
        admin_pass = self.entry_pass.get().strip()

        if not server_address or not domain or not admin_user or not admin_pass:
            messagebox.showerror("Ошибка", "Все поля должны быть заполнены")
            return

        conn = create_connection(server_address, domain, admin_user, admin_pass)
        if conn:
            BASE_DN = ",".join([f"DC={d}" for d in domain.split(".")])
            GROUPS = get_groups()
            OUS = get_ous()
            self.root.withdraw()
            MainWindow(master=self.root)

# ---------------- Запуск ----------------
if __name__ == "__main__":
    LoginWindow()
