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
| [`services/`](services/README.md) | Dienste (services.msc) | systemd | Dienste auflisten, starten/beenden/neu starten, Starttyp, Konto, Wiederherstellung, Abhängigkeiten -- Ansicht aus `common/svc`, auch in `compmgmt` eingehängt |

## Stand gegenüber Windows 2000 Server

Gemessen an "Start → Programme → Verwaltung" eines Windows 2000 Servers
(plus den Werkzeugen, die dort nicht im Menü stehen). "teilweise" heißt:
nutzbar, aber noch nicht im vollen Umfang des Originals.

| Windows-2000-Programm | Hier | Stand |
|---|---|---|
| Active Directory-Benutzer und -Computer | `dsadmin/` | umgesetzt: Baum und Objektlisten, Benutzer (Allgemein, Adresse, Konto, Profil, Rufnummern, Organisation, Mitglied von), Gruppen (Allgemein, Mitglieder, Mitglied von, Verwaltet von), Organisationseinheiten und Domäne (Allgemein, Verwaltet von, Gruppenrichtlinie), Kontakte und freigegebene Ordner, Computer, Suchen, Verschieben/Umbenennen/Löschen, Werkzeugleiste und Menü "Vorgang" |
| Gruppenrichtlinienobjekt-Editor (in AD-Benutzer und -Computer) | `dsadmin/` | umgesetzt: Softwareinstallation, Skripts, Sicherheitseinstellungen (Kennwort-, Kontosperrungs-, Kerberos-, Überwachungs-, Ereignisprotokoll-Richtlinien, Benutzerrechte, Sicherheitsoptionen, eingeschränkte Gruppen, Systemdienste, Registrierung, Dateisystem), Administrative Vorlagen, Ordnerumleitung. Offen: Richtlinien öffentlicher Schlüssel, IP-Sicherheit, Internet Explorer-Wartung, Remoteinstallationsdienste |
| DNS | `dnsmgr/` | umgesetzt (Zonen, gängige Datensatztypen) |
| DHCP | `dhcpmgr/` | umgesetzt (Bereiche, Reservierungen, Ausschlüsse, Optionen) |
| Computerverwaltung | `compmgmt/` | teilweise: Lokale Benutzer und Gruppen, Freigegebene Ordner (Freigaben, Sitzungen, geöffnete Dateien), Dienste. Offen: Ereignisanzeige, Datenträgerverwaltung, Systeminformationen, Leistungsprotokolle |
| Dienste | `services/` | umgesetzt (auflisten, starten/beenden, Starttyp, Konto, Wiederherstellung, Abhängigkeiten) |
| Terminaldienstekonfiguration | `termsvc/` | teilweise: Terminaldienste einrichten (xrdp, Authentifizierung, Win2k-Anmeldebildschirm) |
| Active Directory installieren (dcpromo) | `dcpromo/` | umgesetzt (neue Domäne, Migration zwischen klassischer und BIND9-DLZ-Anbindung) |
| Domänencontroller-, Domänen- und lokale Sicherheitsrichtlinie | (über `dsadmin/`) | teilweise: dieselben Einstellungen über den Gruppenrichtlinien-Editor; eigene Snap-ins fehlen |
| Active Directory-Domänen und -Vertrauensstellungen | -- | offen |
| Active Directory-Standorte und -Dienste | -- | offen |
| Ereignisanzeige | -- | offen |
| Verteiltes Dateisystem (DFS) | -- | offen |
| Routing und RAS | -- | offen |
| Leistung | -- | offen |
| Terminaldienste-Manager | -- | offen |
| Konfigurieren des Servers / Serververwaltung | -- | offen |
| Internetdienste-Manager (IIS) | -- | offen |
| Komponentendienste, Lizenzierung, Terminaldienste-Lizenzierung, Telefondienste, Wechselmedien | -- | nicht geplant |

Geräte-Manager, Systemeigenschaften, Datums-/Zeiteinstellungen und
ähnliche Systemsteuerungs-Werkzeuge kommen aus ice2k selbst und sind
nicht Teil dieses Repos.

## Gemeinsame Bausteine

Unter [`common/`](common/) liegt Code, den mehrere Programme
gemeinsam benutzen, statt ihn doppelt zu pflegen:

| Ordner | Inhalt | benutzt von |
|---|---|---|
| [`common/svc/`](common/svc/) | Dienstverwaltung: GUI-freier systemd-Kern (`svccore`) plus fertige Ansicht als FOX-Widget (`svcpanel`) | `services`, `compmgmt` |
| [`common/svcprobe/`](common/svcprobe/) | Prüfung, ob der verwaltete Dienst läuft, samt einheitlichem Meldungstext | `dnsmgr`, `dhcpmgr`, `compmgmt` |

Alle Programme teilen sich denselben Grundaufbau:
- **FOX-Toolkit** für die GUI (Fenster/Menü/Toolbar/Baum-/Listenansicht
  im MMC-Look, Original-Icons aus `mmc/devmgmt`)
- **Root-Rechte via `i2ksudo`** (GUI-Passwortabfrage im Win2k-Stil, wie
  bei `sysdm`/`timedate` im ice2k-Repo) -- keine der GUIs läuft selbst
  als root, nur einzelne privilegierte Dateizugriffe/Befehle
- Root-Rechte werden beim Programmstart einmal angefragt; dank
  sudo-Timestamp-Caching reicht das i. d. R. für die ganze Sitzung
- **Hinweis, wenn der verwaltete Dienst nicht läuft**: Die Programme
  arbeiten über Konfigurationsdateien und Kommandozeilenwerkzeuge, die
  auch bei gestopptem Dienst noch Daten liefern. Damit die Anzeige nicht
  stillschweigend einen Zustand zeigt, den der Dienst gar nicht kennt,
  prüfen sie ihn aktiv (BIND über `rndc status`, Kea, Samba und der
  Verzeichnisdienst über ihre Unit bzw. eine LDAP-Abfrage) und melden
  den Ausfall in der Statuszeile und einmal als Dialog

## Bauen

```sh
cd dnsmgr && make && ./dnsmgr
cd dhcpmgr && make && ./dhcpmgr
cd compmgmt && make && ./compmgmt
cd dcpromo && make && ./dcpromo
cd dsadmin && make && ./dsadmin
cd termsvc && make && ./termsvc
cd services && make && ./services
```

Voraussetzung: ein ice2k-Debian-13-System (stellt `fox-config`,
`reswrap` und `i2ksudo` bereit).
