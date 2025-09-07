from ldap3 import Server, Connection, ALL
from constants import PROTECTED_GROUPS

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
        raise Exception(f"Ошибка подключения: {str(e)}")

def get_groups(conn, base_dn):
    if not conn:
        return []
    conn.search(search_base=base_dn, search_filter='(objectClass=group)',
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

def get_ous(conn, base_dn):
    if not conn:
        return []
    conn.search(search_base=base_dn, search_filter='(objectClass=organizationalUnit)',
                attributes=['ou', 'distinguishedName'])
    return [(entry.ou.value, entry.distinguishedName.value) for entry in conn.entries]