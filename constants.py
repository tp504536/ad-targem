# Глобальные константы и настройки
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

SMTP_SERVER = "192.168.20.2"
SMTP_PORT = 25
MAIL_FROM = "noreply@office.targem.ru"
MAIL_TO = "it@office.targem.ru"