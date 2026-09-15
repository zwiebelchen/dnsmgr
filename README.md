# win2k-dienste-fuer-ice2k

Nachbauten der klassischen Windows-2000-Server-MMC-Snapins für
[ice2k](https://github.com/comdlg32/ice2k) -- gebaut mit demselben
FOX-Toolkit-Muster wie `mmc/devmgmt` im ice2k-Repo, mit dem Ziel, den
Windows-2000-Server-Funktionsumfang möglichst komplett auf Linux
nachzubilden.

Jeder Dienst ist ein eigenständiges Projekt mit eigenem Makefile im
jeweiligen Unterordner.

## Dienste

| Ordner | Dienst | Backend | Status |
|---|---|---|---|
| [`dnsmgr/`](dnsmgr/README.md) | DNS-Manager | BIND9 | umfangreich (Zonen, alle gängigen Record-Typen, Root via `i2ksudo`) |
| [`dhcpmgr/`](dhcpmgr/README.md) | DHCP-Manager | Kea DHCP | Bereiche, Reservierungen, Ausschlussbereiche, Bereichsoptionen, Root via `i2ksudo` |
| [`compmgmt/`](compmgmt/README.md) | Computerverwaltung (Lokale Benutzer und Gruppen, Freigegebene Ordner) | Linux-User/-Gruppen + Samba | Benutzer/Gruppen anlegen/bearbeiten/löschen; Freigaben anlegen/bearbeiten/aufheben, Sitzungen und geöffnete Dateien live aus `smbstatus`; Root via `i2ksudo` |
| [`dcpromo/`](dcpromo/README.md) | Assistent zum Installieren von Active Directory | Samba als AD-Domain-Controller | Neue Domäne (Windows-2000-kompatibel oder moderne BIND9-DLZ-Integration), Migration zwischen beiden |
| [`dsadmin/`](dsadmin/README.md) | Active Directory-Benutzer und -Computer | samba-tool (user/group/ou/gpo), LDAP, SYSVOL | Domänenkonten anlegen/löschen, Gruppenmitgliedschaften, GPOs anlegen/verknüpfen; vollständiger Gruppenrichtlinienobjekt-Editor (ADM-Vorlagen → `Registry.pol`) plus Softwareinstallation, Skripte und Ordnerumleitung |
| [`termsvc/`](termsvc/README.md) | Terminaldienstekonfiguration | xrdp + PAM/winbind | Terminaldienste aktivieren (Paketinstallation, Authentifizierung lokal/AD, Win2k-Anmeldebildschirm, Dienste starten) |

## Gemeinsame Bausteine

Alle Programme teilen sich denselben Grundaufbau:
- **FOX-Toolkit** für die GUI (Fenster/Menü/Toolbar/Baum-/Listenansicht
  im MMC-Look, Original-Icons aus `mmc/devmgmt`)
- **Root-Rechte via `i2ksudo`** (GUI-Passwortabfrage im Win2k-Stil, wie
  bei `sysdm`/`timedate` im ice2k-Repo) -- keine der GUIs läuft selbst
  als root, nur einzelne privilegierte Dateizugriffe/Befehle
- Root-Rechte werden beim Programmstart einmal angefragt; dank
  sudo-Timestamp-Caching reicht das i. d. R. für die ganze Sitzung

## Bauen

```sh
cd dnsmgr && make && ./dnsmgr
cd dhcpmgr && make && ./dhcpmgr
cd compmgmt && make && ./compmgmt
cd dcpromo && make && ./dcpromo
cd dsadmin && make && ./dsadmin
cd termsvc && make && ./termsvc
```

Voraussetzung: ein ice2k-Debian-13-System (stellt `fox-config`,
`reswrap` und `i2ksudo` bereit).
