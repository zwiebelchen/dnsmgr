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
| [`rras/`](rras/README.md) | Routing und RAS | Linux-Kernel (IP-Weiterleitung) | Serverstatus, Aktivieren/Deaktivieren, Eigenschaften |
| [`srvcfg/`](srvcfg/README.md) | Konfiguration des Servers | Zustand aus smb.conf, systemd und /etc/ice2k | Startseite mit Verweisen auf die übrigen Programme |
| [`secpol/`](secpol/README.md) | Sicherheitsrichtlinien (Domäne, Domänencontroller, lokal) | dieselbe Quelle wie `dsadmin` (GPO-Sicherheitseinstellungen) | drei Konsolen über `--domain`, `--dc`, `--local` |
| [`services/`](services/README.md) | Dienste (services.msc) | systemd | Dienste auflisten, starten/beenden/neu starten, Starttyp, Konto, Wiederherstellung, Abhängigkeiten -- Ansicht aus `common/svc`, auch in `compmgmt` eingehängt |

## Stand gegenüber "Start → Programme → Verwaltung"

Alle Einträge des Verwaltungsmenüs eines Windows 2000 Servers, in der
Reihenfolge des Originalmenüs. "teilweise" heißt: nutzbar, aber noch
nicht im vollen Umfang des Originals.

**Diese Tabelle ist bei jeder Änderung mitzupflegen** -- sie ist der
Überblick über den Projektstand.

| # | Menüpunkt (Verwaltung) | Hier | Stand |
|---|---|---|---|
| 1 | Terminaldiensteclient | -- | nicht geplant (unter Linux ein gewöhnlicher RDP-Client, z.B. `xfreerdp`) |
| 2 | Active Directory-Benutzer und -Computer | [`dsadmin/`](dsadmin/README.md) | **umgesetzt**: Baum/Listen, Benutzer (Allgemein, Adresse, Konto, Profil, Rufnummern, Organisation, Mitglied von), Gruppen (Allgemein, Mitglieder, Mitglied von, Verwaltet von), OU/Domäne (Allgemein, Verwaltet von, Gruppenrichtlinie), Computer, Kontakte, freigegebene Ordner, Suchen, Verschieben/Umbenennen/Löschen, Werkzeugleiste und Menü "Vorgang"; darin der vollständige Gruppenrichtlinienobjekt-Editor (siehe unten) |
| 3 | Active Directory-Domänen und -Vertrauensstellungen | -- | offen (Backend: `samba-tool domain trust`) |
| 4 | Active Directory-Standorte und -Dienste | -- | offen (Backend: LDAP unter `CN=Sites,CN=Configuration`) |
| 5 | Clusterverwaltung | -- | nicht geplant |
| 6 | Computerverwaltung | [`compmgmt/`](compmgmt/README.md) | **teilweise**: Lokale Benutzer und Gruppen, Freigegebene Ordner (Freigaben, Sitzungen, geöffnete Dateien), Dienste und Anwendungen. Offen: Ereignisanzeige, Datenträgerverwaltung, Systeminformationen, Leistungsprotokolle, Geräte-Manager (kommt aus ice2k) |
| 7 | Datenquellen (ODBC) | -- | nicht geplant |
| 8 | DHCP | [`dhcpmgr/`](dhcpmgr/README.md) | **umgesetzt**: Bereiche, Reservierungen, Ausschlussbereiche, Bereichsoptionen (Kea DHCP) |
| 9 | Dienste | [`services/`](services/README.md) | **umgesetzt**: auflisten, starten/beenden/neu starten, Starttyp, Konto, Wiederherstellung, Abhängigkeiten (systemd) |
| 10 | DNS | [`dnsmgr/`](dnsmgr/README.md) | **umgesetzt**: Forward-/Reverse-Zonen, gängige Datensatztypen (BIND9) |
| 11 | Ereignisanzeige | -- | offen (Backend: `journalctl`) |
| 12 | Komponentendienste | -- | nicht geplant (COM+ hat unter Linux keine Entsprechung) |
| 13 | Konfiguration des Servers | [`srvcfg/`](srvcfg/README.md) | **umgesetzt**: Kopfbanner, Navigationsleiste und Inhaltsseiten wie im Original; jede Seite zeigt den Zustand des Dienstes und startet das passende Programm. Für Dienste ohne eigenes Programm (Druck, Web, Medien, Datenbank, E-Mail) nennt sie die Linux-Gegenstücke |
| 14 | Lizenzierung | -- | nicht geplant |
| 15 | Lokale Sicherheitsrichtlinie | [`secpol/`](secpol/README.md) `--local` | **umgesetzt**: bearbeitbar wie im Original, mit den Spalten "Lokale Einstellung" und "Effektive Einstellung" (lokale Werte, überschrieben von den wirksamen Gruppenrichtlinien). Lokale Werte werden gespeichert, aber noch nicht auf das Linux-System angewendet |
| 16 | Routing und RAS | [`rras/`](rras/README.md) | **teilweise**: Serverstatus, Aktivieren/Deaktivieren, Eigenschaften, Routingschnittstellen, statische Routen, **VPN-Server** (WireGuard, OpenVPN samt eigener Zertifizierungsstelle, strongSwan) mit Client-/Benutzerverwaltung und **Paketfilter** je Schnittstelle über nftables, alles über die Unit `ice2k-rras.service` neustartfest; Texte und Symbole aus `mprsnap.dll`/`rtrfiltr.dll`. Offen: Einwahl (Modem/ISDN), Adressumsetzung, Routingprotokolle |
| 17 | Systemmonitor | -- | offen |
| 18 | Telefonie | -- | nicht geplant |
| 19 | Telnetserververwaltung | -- | nicht geplant |
| 20 | Terminaldienste-Clientinstallation | -- | nicht geplant (verteilte die Windows-Clientdateien) |
| 21 | Terminaldienstekonfiguration | [`termsvc/`](termsvc/README.md) | **teilweise**: Terminaldienste einrichten (xrdp, Authentifizierung lokal/AD, Win2k-Anmeldebildschirm, Dienste starten). Offen: Verbindungseigenschaften, Sitzungsgrenzen, Berechtigungen |
| 22 | Terminaldienstelizenzierung | -- | nicht geplant |
| 23 | Terminaldiensteverwaltung | -- | offen (angemeldete Sitzungen anzeigen/trennen) |
| 24 | Verbindungs-Manager-Verwaltungskit | -- | nicht geplant |
| 25 | Verteiltes Dateisystem (DFS) | -- | offen (Backend: Samba `msdfs`) |
| 26 | WINS | -- | offen (Backend: Sambas WINS-Server `nmbd`) |
| 27 | Zertifizierungsstelle | -- | offen (Backend: z.B. `openssl`/`easy-rsa`) |
| 28 | Internetauthentifizierungsdienst | -- | offen (RADIUS, Backend: FreeRADIUS) |
| 29 | Internetdienste-Manager | -- | offen (Backend: Apache oder nginx) |
| 30 | QoS-Zugangssteuerung | -- | nicht geplant |
| 31 | Remotespeicher | -- | nicht geplant |
| 32 | Sicherheitsrichtlinie für Domänen | [`secpol/`](secpol/README.md) `--domain` | **umgesetzt**: Zweig "Sicherheitseinstellungen" der Default Domain Policy |
| 33 | Sicherheitsrichtlinie für Domänencontroller | [`secpol/`](secpol/README.md) `--dc` | **umgesetzt**: Zweig "Sicherheitseinstellungen" der Default Domain Controllers Policy |

Nicht im Verwaltungsmenü, aber Teil dieses Repos:

| Programm | Hier | Stand |
|---|---|---|
| Active Directory installieren (`dcpromo`) | [`dcpromo/`](dcpromo/README.md) | **umgesetzt**: neue Domäne (Windows-2000-kompatibel oder BIND9-DLZ), Migration zwischen beiden |
| Gruppenrichtlinienobjekt-Editor (aus AD-Benutzer und -Computer heraus) | [`dsadmin/`](dsadmin/README.md) | **umgesetzt**: Softwareinstallation, Skripts, Sicherheitseinstellungen (Kennwort-, Kontosperrungs-, Kerberos-, Überwachungs- und Ereignisprotokoll-Richtlinien, Benutzerrechte, Sicherheitsoptionen, eingeschränkte Gruppen, Systemdienste, Registrierung, Dateisystem), Administrative Vorlagen, Ordnerumleitung. Offen: Richtlinien öffentlicher Schlüssel, IP-Sicherheitsrichtlinien, Internet Explorer-Wartung, Remoteinstallationsdienste |

Geräte-Manager, Systemeigenschaften und ähnliche Systemsteuerungs-
Werkzeuge kommen aus ice2k selbst und sind nicht Teil dieses Repos.

## Gemeinsame Bausteine

Unter [`common/`](common/) liegt Code, den mehrere Programme
gemeinsam benutzen, statt ihn doppelt zu pflegen:

| Ordner | Inhalt | benutzt von |
|---|---|---|
| [`common/svc/`](common/svc/) | Dienstverwaltung: GUI-freier systemd-Kern (`svccore`) plus fertige Ansicht als FOX-Widget (`svcpanel`) | `services`, `compmgmt` |
| [`common/svcprobe/`](common/svcprobe/) | Prüfung, ob der verwaltete Dienst läuft, samt einheitlichem Meldungstext | `dnsmgr`, `dhcpmgr`, `compmgmt` |

### Offene Punkte für später

- **Ja/Nein-Rückfragen sind englisch beschriftet** ("Yes"/"No"): Die
  Beschriftung kommt aus FOX (`FXMessageBox`) und ist dort fest
  hinterlegt. Für eine deutsche Beschriftung braucht es einen eigenen
  Rückfragedialog, der dann in allen Programmen verwendet wird.

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
cd secpol && make && ./secpol --domain
cd rras && make && ./rras
cd srvcfg && make && ./srvcfg
```

Voraussetzung: ein ice2k-Debian-13-System (stellt `fox-config`,
`reswrap` und `i2ksudo` bereit).
