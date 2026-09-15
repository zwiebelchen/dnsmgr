# Terminaldienstekonfiguration (termsvc)

Richtet Terminaldienste (Remotedesktop) für ice2k ein -- reines
Full-Desktop-RDP über `xrdp`, kein RemoteApp/RAIL (das konnte
Windows 2000 noch nicht).

## Funktionsweise

Ein Klick auf "Terminaldienste aktivieren":

1. **Paketprüfung**: prüft, ob `xrdp`, `xorgxrdp`, `libpam-winbind`
   und `libnss-winbind` installiert sind, und installiert fehlende
   Pakete automatisch nach (`apt-get update` + `apt-get install`).
2. **Authentifizierung einrichten**: aktiviert über `pam-auth-update`
   sowohl das `winbind`- als auch das `unix`-PAM-Profil. Das ergibt
   eine Kaskade in `/etc/pam.d/common-auth`, die zuerst lokale
   Linux-Konten und danach (falls vorhanden) Active-Directory-Konten
   über winbind probiert -- automatisch je nachdem, was eingerichtet
   ist, ganz ohne Sonderfall-Logik im Programm selbst. Ist keine
   Domäne vorhanden, läuft der winbind-Versuch einfach ins Leere und
   die lokale Anmeldung übernimmt.
3. **Erscheinungsbild**: versieht den xrdp-Anmeldebildschirm
   (`/etc/xrdp/xrdp.ini`, Abschnitt "configure login screen") mit
   einem an Windows 2000 angelehnten Aussehen -- klassisches
   Blaugrün als Fensterhintergrund, klassisches Dialog-Grau für die
   Box selbst, dazu ein eigenes, unabhängiges Logo (`ice2k-logo.bmp`,
   per ImageMagick erzeugt -- kein Microsoft-Material). Das Setzen
   der Werte ist zeilenbasiert und daher mehrfach anwendbar, ohne die
   Datei zu verstümmeln.
4. **Dienste aktivieren**: `systemctl enable --now winbind xrdp`.

## Bekannte Grenzen

- Es wird keine bestimmte Desktop-Umgebung für die eigentliche
  RDP-Sitzung mitinstalliert oder vorgegeben -- xrdp startet, was
  auch immer in `/etc/xrdp/startwm.sh` konfiguriert ist. Das
  eigentliche "Windows-2000-Aussehen" *innerhalb* der Sitzung ist
  Aufgabe der ice2k-Desktopumgebung selbst, nicht dieses Werkzeugs.
- Der Dienststatus (`systemctl is-active`) kann in Umgebungen ohne
  echtes systemd (z.B. Container ohne Init-System) nicht ermittelt
  werden -- betrifft nur die Statusanzeige, nicht die Einrichtung
  selbst.
