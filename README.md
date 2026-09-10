# dnsmgr -- DNS-Manager für ice2k

Ein Nachbau des Windows-2000-DNS-Manager-Snapins (MMC) für
[ice2k](https://github.com/comdlg32/ice2k), gebaut mit demselben
FOX-Toolkit-Muster wie `mmc/devmgmt` im ice2k-Repo.

![DNS-Manager im Win2k-Look](docs/screenshots/screenshot-demo-geschrieben.png)

## Funktionsumfang
- Fenster/Menü/Toolbar im MMC-Look, mit Original-Icons aus `mmc/devmgmt`
- Baumansicht: DNS -> Hostname -> Forward-/Reverse-Lookupzonen -> Zonen
- Liest echte BIND9-Zonen aus `/etc/bind/named.conf.local` + Zonendateien
  (SOA, NS, A, CNAME, MX, PTR)
- Root-Rechte beim Start über `i2ksudo` (GUI-Passwortabfrage im
  Win2k-Look, wie bei `sysdm`/`timedate` im ice2k-Repo). Dank
  sudo-Timestamp-Caching i. d. R. nur einmal pro Sitzung nötig.
- Legt automatisch eine Demo-Zone `zwiebelchen.org` unter `/etc/bind/`
  an, falls `named.conf.local` fehlt oder keine Zone enthält
- Kontextmenüs:
  - Rechtsklick auf "Forward-Lookupzonen" -> **Neue Zone...**
  - Rechtsklick auf eine Zone -> **Neuer Host (A)...** / **Löschen**
  - Rechtsklick auf einen Eintrag in der Listenansicht -> **Eigenschaften**
    (nur Host/A) / **Löschen**
- Toolbar "Löschen"/"Eigenschaften" wirken auf den markierten Eintrag
- Doppelklick auf einen Host-(A)-Eintrag öffnet den Eigenschaften-Dialog;
  IP-Änderungen werden in die Zonendatei geschrieben, `rndc reload`

Alle privilegierten Schreib-/Löschaktionen laufen über `i2ksudo`
(`runAsRoot()`/`writeFileAsRoot()` in `dnsmgr.cpp`) -- es läuft nie die
komplette GUI als root, nur die einzelnen Dateizugriffe.

## Bauen
Voraussetzung: ein ice2k-Debian-13-System (stellt `fox-config`, `reswrap`
und `i2ksudo` bereit, siehe [ice2k](https://github.com/comdlg32/ice2k)).

```sh
make
./dnsmgr
```

## Bekannte Grenzen / mögliche nächste Schritte
- "Neue Zone"/"Zone löschen" rufen `rndc reconfig` auf -- bei BIND9 mit
  AppArmor muss der Zonendatei-Ordner im `named`-Profil freigegeben sein.
- PTR-Erstellung ist best-effort: nur klassische `/24`-Reverse-Zonen
  (`c.b.a.in-addr.arpa`) werden erkannt; beim Löschen eines Hosts wird
  der zugehörige PTR-Eintrag noch nicht automatisch mitgelöscht.
- NS/CNAME/MX sind im Eigenschaften-Dialog noch nicht editierbar
  (Löschen funktioniert für alle Typen außer SOA).
- Kein Undo für Löschaktionen.
