import tkinter as tk
from tkinter import messagebox, ttk
import ttkbootstrap as tb
import auth
import user_operations


class LoginWindow:
    def __init__(self):
        self.root = tb.Window(themename="superhero")
        self.root.title("Авторизация")
        self.root.geometry("600x400")

        tb.Label(self.root, text="Адрес LDAP-сервера:").pack(pady=5)
        self.entry_server = tb.Entry(self.root)
        self.entry_server.pack(pady=5)

        tb.Label(self.root, text="Домен:").pack(pady=5)
        self.entry_domain = tb.Entry(self.root)
        self.entry_domain.pack(pady=5)

        tb.Label(self.root, text="Логин администратора:").pack(pady=5)
        self.entry_user = tb.Entry(self.root)
        self.entry_user.pack(pady=5)

        tb.Label(self.root, text="Пароль:").pack(pady=5)
        self.entry_pass = tb.Entry(self.root, show="*")
        self.entry_pass.pack(pady=5)

        tb.Button(self.root, text="Войти", bootstyle="success", command=self.login).pack(pady=15)
        tb.Button(self.root, text="Выход", bootstyle="danger", command=self.root.destroy).pack(pady=5)

        self.conn = None
        self.base_dn = None
        self.groups = []
        self.ous = []

        self.root.mainloop()

    def login(self):
        server_address = self.entry_server.get().strip()
        domain = self.entry_domain.get().strip()
        admin_user = self.entry_user.get().strip()
        admin_pass = self.entry_pass.get().strip()

        if not server_address or not domain or not admin_user or not admin_pass:
            messagebox.showerror("Ошибка", "Все поля должны быть заполнены")
            return

        try:
            self.conn = auth.create_connection(server_address, domain, admin_user, admin_pass)
            self.base_dn = ",".join([f"DC={d}" for d in domain.split(".")])
            self.groups = auth.get_groups(self.conn, self.base_dn)
            self.ous = auth.get_ous(self.conn, self.base_dn)
            self.root.withdraw()
            MainWindow(self.root, self.conn, self.base_dn, self.groups, self.ous)
        except Exception as e:
            messagebox.showerror("Ошибка подключения", str(e))


class MainWindow:
    def __init__(self, master, conn, base_dn, groups, ous):
        self.root = tb.Toplevel(master)
        self.root.title("Управление пользователями AD")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.logout)

        self.conn = conn
        self.base_dn = base_dn
        self.groups = groups
        self.ous = ous

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
        text = self.log_text.get("sel.first", "sel.last") if self.log_text.tag_ranges("sel") else self.log_text.get(
            "1.0", "end")
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
        self.ou_combobox = ttk.Combobox(self.tab_create, values=[ou[0] for ou in self.ous], state="readonly")
        self.ou_combobox.pack(pady=5, fill="x", padx=10)
        if self.ous:
            self.ou_combobox.current(0)

        tb.Label(self.tab_create, text="Добавить в группы:").pack(pady=5)
        self.groups_listbox = tk.Listbox(self.tab_create, selectmode="multiple", height=10)
        self.groups_listbox.pack(pady=5, fill="both", padx=10, expand=True)
        for grp_cn, _ in self.groups:
            self.groups_listbox.insert("end", grp_cn)

        # Чекбоксы (в строку)
        opts_frame = tb.Frame(self.tab_create)
        opts_frame.pack(pady=10, fill="x", padx=10)
        self.chk_wiki = tk.IntVar()
        self.chk_office = tk.IntVar()
        self.chk_owncloud = tk.IntVar()

        tk.Checkbutton(opts_frame, text="Создать в Wiki", variable=self.chk_wiki).grid(row=0, column=0, sticky="w",
                                                                                       padx=10)
        tk.Checkbutton(opts_frame, text="Залогинить в office.targem.ru", variable=self.chk_office).grid(row=0, column=1,
                                                                                                        sticky="w",
                                                                                                        padx=10)
        tk.Checkbutton(opts_frame, text="Добавить в OwnCloud (аутсорс)", variable=self.chk_owncloud).grid(row=0,
                                                                                                          column=2,
                                                                                                          sticky="w",
                                                                                                          padx=10)

        tb.Button(self.tab_create, text="Создать пользователя", bootstyle="success",
                  command=self.create_user_action).pack(pady=15)

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
        tk.Checkbutton(checks, text="Удалить почту", variable=self.chk_delete_mail).grid(row=0, column=0, sticky="w",
                                                                                         padx=10)
        tk.Checkbutton(checks, text="Блокировать почту", variable=self.chk_block_mail).grid(row=0, column=1, sticky="w",
                                                                                            padx=10)

        tb.Button(self.tab_delete, text="Удалить пользователя", bootstyle="danger",
                  command=self.delete_user_action).pack(pady=15)

    def logout(self):
        if self.conn:
            self.conn.unbind()
        self.root.destroy()
        self.root.master.deiconify()

    def create_user_action(self):
        selected_indices = self.groups_listbox.curselection()
        selected_groups_dn = [self.groups[i] for i in selected_indices]
        selected_ou_dn = None
        if self.ou_combobox.get():
            for ou_name, ou_dn in self.ous:
                if ou_name == self.ou_combobox.get():
                    selected_ou_dn = ou_dn
                    break

        success = user_operations.create_user(
            self.conn,
            self.base_dn,
            self.entry_fullname.get(),
            selected_groups_dn,
            selected_ou_dn,
            self.chk_wiki.get(),
            self.chk_office.get(),
            self.chk_owncloud.get(),
            self.log
        )

        if success:
            messagebox.showinfo("Успех", "Пользователь успешно создан")
        else:
            messagebox.showerror("Ошибка", "Не удалось создать пользователя")

    def delete_user_action(self):
        success = user_operations.delete_user(
            self.conn,
            self.base_dn,
            self.entry_delete.get(),
            self.chk_delete_mail.get(),
            self.chk_block_mail.get(),
            self.log
        )

        if success:
            messagebox.showinfo("Успех", "Пользователь успешно удален")
        else:
            messagebox.showerror("Ошибка", "Не удалось удалить пользователя")