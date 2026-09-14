# compmgmt -- Computerverwaltung für ice2k

Ein Nachbau des Windows-2000-"Computerverwaltung"-Snapins (MMC) für
[ice2k](https://github.com/comdlg32/ice2k), Zweig **"Lokale Benutzer
und Gruppen"** ("Freigegebene Ordner" folgt als nächster Schritt).
Gebaut mit demselben FOX-Toolkit-Muster wie `dnsmgr`/`dhcpmgr`.
Backend: **echte Linux-Benutzer/-Gruppen**, parallel dazu **Samba**
(`smbpasswd`/`pdbedit`) synchron gehalten.

![Baumstruktur: Computerverwaltung -> Systemprogramme -> Lokale Benutzer und Gruppen -> Benutzer/Gruppen](../docs/compmgmt/screenshots/screenshot-baumstruktur.png)

## Warum Linux-User *und* Samba zusammen?

Samba kann keinen eigenständigen Benutzer ohne zugrundeliegenden
Unix-Account verwalten -- ein Samba-Konto ist technisch immer eine
Ergänzung zu einem echten Linux-User (Samba speichert zusätzlich nur
den NT-Passwort-Hash, den SMB für die Authentifizierung braucht und
der sich nicht aus dem Unix-`crypt()`-Hash berechnen lässt). Damit ein
Konto sich wie ein lokales Windows-2000-SAM-Konto verhält (eine
Anmeldung, gültig für Konsole **und** Netzwerkfreigaben), legt
`compmgmt` bei jeder Aktion **beides** synchron an:
- Linux-Seite: `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel`/`gpasswd`
- Samba-Seite: `chpasswd` + `smbpasswd`/`pdbedit`

## Funktionsumfang
- Fenster/Menü/Toolbar im MMC-Look, mit denselben Original-Icons wie
  `dnsmgr`/`dhcpmgr`
- Baumansicht wie im Original: Computerverwaltung (Lokal) ->
  Systemprogramme -> Lokale Benutzer und Gruppen -> **Benutzer** /
  **Gruppen**
- Root-Rechte beim Start über `i2ksudo` (identisches Muster wie
  `dnsmgr`/`dhcpmgr`)
- Benutzerliste zeigt **alle** Linux-Konten (auch Systemkonten wie
  `root`/`www-data`), mit erkanntem "(deaktiviert)"-Status aus
  `/etc/shadow`
- **Neuer Benutzer...**: Benutzername, Vollständiger Name,
  Beschreibung (beide im GECOS-Feld von `/etc/passwd`), Kennwort,
  Kennwort bestätigen, "Konto ist deaktiviert" -- "Hinzufügen"/
  "Schließen"-Muster wie im Original
- **Eigenschaften**: Vollständiger Name/Beschreibung/Deaktiviert
  editierbar (Benutzername bewusst read-only -- ein Unix-Account
  umzubenennen ist wegen Home-Verzeichnis/Dateibesitz heikel)
- **Kennwort festlegen...** als eigener Menüpunkt (wie im Original,
  nicht Teil der Eigenschaften). Setzt Unix- **und**
  Samba-Passwort synchron, ohne einen vorherigen Deaktiviert-Status
  zu verlieren.
- **Löschen** (`userdel -r` + `smbpasswd -x`)
- Gruppen: **Neue Gruppe...**, **Eigenschaften** mit Mitgliederliste
  (Hinzufügen/Entfernen, per `gpasswd -M` gespeichert), **Löschen**

## Bauen
```sh
cd compmgmt
make
./compmgmt
```
Voraussetzung: `samba`/`samba-common-bin` installiert (für
`smbpasswd`/`pdbedit`).

## Bekannte Grenzen / mögliche nächste Schritte
- Freigegebene Ordner (Freigaben, Sitzungen, Offene Dateien) fehlen
  noch komplett -- kommt als nächster Zweig.
- Kein "Benutzer muss Kennwort bei der nächsten Anmeldung ändern" /
  "Kennwort läuft nie ab" (chage-basierte Flags) -- nur "Konto ist
  deaktiviert" wird abgebildet.
- Benutzername lässt sich nicht nachträglich ändern (bewusst, siehe
  oben).
- Keine Prüfung, ob eine Gruppe noch die primäre Gruppe eines
  Benutzers ist, bevor sie gelöscht wird (schlägt dann einfach mit
  Fehlermeldung von `groupdel` fehl).
- Kein Sync über PAM (`pam_smbpass`) -- ändert ein Benutzer sein
  Passwort außerhalb von `compmgmt` (z.B. per `passwd`), läuft der
  Samba-Hash auseinander, bis er hier erneut gesetzt wird.
