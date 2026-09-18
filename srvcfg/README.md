# srvcfg -- Konfiguration des Servers

Nachbau von "Windows 2000 Server konfigurieren" (Menüpunkt "Konfiguration
des Servers" in der Verwaltung).

## Aufbau

Wie im Original: oben das Kopfbanner, links die dunkelblaue
Navigationsleiste mit den aufklappbaren Gruppen, rechts die Inhaltsseite
mit Text und blauen Verweisen, unten rechts "Dialog beim Start anzeigen".

Die Punkte folgen dem Original: Startseite, Jetzt registrieren, Active
Directory, Dateiserver, Druckserver, Web-/Mediaserver (Webserver,
Medienserver), Netzwerk (DHCP, DNS, Remotezugriff, Routing),
Anwendungsserver (Komponentendienste, Terminaldienste, Datenbankserver,
E-Mail-Server) und Erweitert (Computerverwaltung, Sicherheitsrichtlinien).

## Was die Seiten tun

Jede Seite sagt zuerst, wie es um den Dienst auf diesem Server steht --
genau wie das Original ("Auf diesem Server ist DHCP installiert").
Ermittelt wird das aus `smb.conf` (Domänencontroller und Domäne), den
systemd-Units (Samba, BIND, Kea, CUPS, Apache/nginx, xrdp) und
`/etc/ice2k/rras.conf` (Routing und RAS).

Die Verweise starten die Programme dieses Projekts:

| Seite | Verweis startet |
|---|---|
| Active Directory | `dsadmin`, `dcpromo`, `secpol --domain` |
| Dateiserver | `compmgmt` |
| Webserver, Datenbankserver, E-Mail-Server | `services` |
| DHCP | `dhcpmgr` |
| DNS | `dnsmgr` |
| Remotezugriff, Routing | `rras` |
| Terminaldienste | `termsvc` |
| Computerverwaltung | `compmgmt`, `services` |
| Sicherheitsrichtlinien | `secpol --local`, `--domain`, `--dc` |

Fehlt ein Programm im Suchpfad, sagt das eine Meldung mit dem Namen des
Programms, statt still nichts zu tun.

## Abweichungen vom Original

- **Jetzt registrieren** entfällt inhaltlich: ice2k baut auf freier
  Software auf. Der Punkt bleibt an seinem Platz und erklärt das.
- **Druckserver** verweist auf CUPS, **Webserver** auf Apache oder nginx,
  **Medienserver**, **Komponentendienste**, **Datenbankserver** und
  **E-Mail-Server** nennen die Linux-Gegenstücke. Eigene
  Verwaltungsprogramme gibt es dafür (noch) nicht, und die Seiten sagen
  das.
- Die Symbole der Navigationsleiste sind noch einheitlich; das Original
  hat je Eintrag ein eigenes.

"Dialog beim Start anzeigen" merkt sich die Einstellung in
`~/.ice2k-srvcfg-off`; ausgewertet wird sie vom Autostart in ice2k.

## Bauen

```sh
cd srvcfg && make && ./srvcfg
```
