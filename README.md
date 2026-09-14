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
| [`compmgmt/`](compmgmt/README.md) | Computerverwaltung (Lokale Benutzer und Gruppen) | Linux-User/-Gruppen + Samba | Benutzer/Gruppen anlegen/bearbeiten/löschen, Root via `i2ksudo`; Freigegebene Ordner folgen |
| [`dcpromo/`](dcpromo/README.md) | Assistent zum Installieren von Active Directory | Samba als AD-Domain-Controller | Neue Domäne (Windows-2000-kompatibel oder moderne BIND9-DLZ-Integration), Migration zwischen beiden |

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
```

Voraussetzung: ein ice2k-Debian-13-System (stellt `fox-config`,
`reswrap` und `i2ksudo` bereit).
