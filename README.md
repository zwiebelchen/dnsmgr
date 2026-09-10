# dnsmgr -- DNS-Manager für ice2k

Ein Nachbau des Windows-2000-DNS-Manager-Snapins (MMC) für
[ice2k](https://github.com/comdlg32/ice2k), gebaut mit demselben
FOX-Toolkit-Muster wie `mmc/devmgmt` im ice2k-Repo.

![DNS-Manager im Win2k-Look](docs/screenshots/screenshot-demo-geschrieben.png)

## Funktionsumfang
- Fenster/Menü/Toolbar im MMC-Look, mit Original-Icons aus `mmc/devmgmt`
- Baumansicht: DNS -> Hostname -> Forward-/Reverse-Lookupzonen -> Zonen
- Record-Typ-Bezeichnungen exakt wie im Original ("Autoritätsursprung",
  "Namenserver", "Host", "Alias", "Mailaustausch", "Zeiger" -- ohne
  technische Abkürzungen in Klammern)
- Liest echte BIND9-Zonen aus `/etc/bind/named.conf.local` + Zonendateien
  (SOA, NS, A, CNAME, MX, PTR)
- Root-Rechte beim Start über `i2ksudo` (GUI-Passwortabfrage im
  Win2k-Look, wie bei `sysdm`/`timedate` im ice2k-Repo). Dank
  sudo-Timestamp-Caching i. d. R. nur einmal pro Sitzung nötig.
- Legt automatisch eine Demo-Zone `zwiebelchen.org` unter `/etc/bind/`
  an, falls `named.conf.local` fehlt oder keine Zone enthält
- **Zonen-Assistent** ("Neue Zone..."): Auswahl Forward-/
  Reverse-Lookupzone mit Live-Vorschau des berechneten
  `in-addr.arpa`-Namens, Button "Fertig stellen" wie im Original
- **Neuer-Host-, Neuer-Alias- (CNAME), Neuer-Mailserver- (MX) und
  Neuer-Zeiger-Dialog (PTR)**: legen Einträge per "... hinzufügen"
  sofort an und bleiben für weitere offen (mit Erfolgsmeldung,
  Felder-Reset), "Fertig stellen" schließt sie -- genauso wie im
  Original-Assistenten. Beim PTR-Dialog wird das Netzwerk-Präfix aus
  dem Zonennamen berechnet und vorangestellt, es muss nur noch das
  letzte Oktett eingegeben werden.
- Kontextmenüs wie im Original:
  - Rechtsklick auf "Forward-/Reverse-Lookupzonen" -> **Neue Zone...** /
    **Aktualisieren**
  - Rechtsklick auf eine Forward-Zone -> **Neuer Host (A)...** / **Neuer
    Alias (CNAME)...** / **Neuer Mailserver (MX)...** / **Aktualisieren**
    / **Eigenschaften** / **Löschen**
  - Rechtsklick auf eine Reverse-Zone -> **Neuer Zeiger (PTR)...** /
    **Aktualisieren** / **Eigenschaften** / **Löschen**
  - Rechtsklick auf einen Eintrag in der Listenansicht -> **Eigenschaften**
    (nur Host/A) / **Löschen**
- **Zonen-Eigenschaften**: zeigen Zonenname/-typ/-datei und die rohen
  SOA-Werte (Serial/Refresh/Retry/Expire/Minimum); bei Reverse-Zonen
  zusätzlich die berechnete Netzwerk-ID (z.B. `10.10.10.0/24`)
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
- "Liste exportieren..." (Export der Zone/Ansicht) ist noch offen -- geplant.
- "Neue Zone"/"Zone löschen" rufen `rndc reconfig` auf -- bei BIND9 mit
  AppArmor muss der Zonendatei-Ordner im `named`-Profil freigegeben sein.
- PTR-Erstellung beim Anlegen eines Hosts (Checkbox im Host-Dialog) ist
  weiterhin best-effort: nur klassische `/24`-Reverse-Zonen
  (`c.b.a.in-addr.arpa`) werden automatisch erkannt; beim Löschen eines
  Hosts wird der zugehörige PTR-Eintrag noch nicht automatisch
  mitgelöscht. Manuelles Anlegen über "Neuer Zeiger (PTR)..." funktioniert
  unabhängig davon immer.
- CNAME/MX sind im Eigenschaften-Dialog noch nicht editierbar, nur beim
  Anlegen setzbar (Löschen funktioniert für alle Typen außer SOA).
- Zonen-Eigenschaften sind nur eine Anzeige (SOA-Werte lassen sich noch
  nicht direkt darin bearbeiten).
- Kein Undo für Löschaktionen.
