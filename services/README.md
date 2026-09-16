# services -- Dienste für ice2k

Nachbau von `services.msc` für [ice2k](https://github.com/comdlg32/ice2k).
Backend: **systemd**.

Die eigentliche Ansicht steckt nicht in diesem Programm, sondern in
[`../common/svc`](../common/svc/) -- dieselbe Klasse benutzt auch die
Computerverwaltung in ihrem Zweig "Dienste und Anwendungen". Hier
drumherum liegt nur der MMC-Rahmen (Menü, Werkzeugleiste, Strukturbaum
mit "Dienste (Lokal)").

## Aufteilung

| Datei | Inhalt |
|---|---|
| `../common/svc/svccore.{h,cpp}` | Backend ohne jede GUI: Dienste auflisten, Eigenschaften lesen, starten/beenden, Starttyp setzen, Erweiterungsdatei schreiben |
| `../common/svc/svcpanel.{h,cpp}` | FOX-Widget: Liste im MMC-Look, Kontextmenü, Eigenschaften-Dialog mit vier Reitern |
| `../common/svc/test_svccore.cpp` | Tests der reinen Parser, ohne laufendes systemd |
| `services.cpp` | Nur der Fensterrahmen |

Der Kern kennt weder FOX noch Icons noch Ressourcen; das Widget bekommt
sein Icon vom Aufrufer übergeben. Dadurch hängt keins von beiden an den
`res/foxres.h` eines bestimmten Programms, und es gibt keine zweite
Umsetzung derselben Logik.

## Abbildung auf systemd

| Windows 2000 | systemd |
|---|---|
| Starttyp Automatisch | `systemctl enable` |
| Starttyp Manuell | `systemctl disable` (auch `static`/`indirect`) |
| Starttyp Deaktiviert | `systemctl mask` |
| Status "Gestartet" | `ActiveState=active` |
| Anmelden als | `User=` (leer bzw. `root` = "LocalSystem") |
| Wiederherstellen: Dienst neu starten | `Restart=on-failure` + `RestartSec=` |
| Fehlerzähler nach N Tagen zurücksetzen | `StartLimitIntervalSec=` |
| Abhängigkeiten (oben/unten) | `Requires=`/`Wants=` bzw. `RequiredBy=`/`WantedBy=` |

Alle Aufrufe lesen unprivilegiert; nur Schreibvorgänge laufen über
`i2ksudo` (`start`/`stop`/`restart`, `enable`/`disable`/`mask`/`unmask`,
das Anlegen des Drop-in-Verzeichnisses, das Schreiben selbst und
`daemon-reload`). Das Programm selbst läuft nie als root. Anders als die
übrigen Werkzeuge fragt es die Rechte **nicht beim Start** ab, sondern
erst bei der ersten schreibenden Aktion -- zum bloßen Ansehen der
Dienstliste braucht es keine.

Der Kontoname aus dem Reiter "Anmelden" wird vor dem Schreiben geprüft
(`isValidAccountName`). Sonst könnte ein Zeilenumbruch im Eingabefeld
beliebige weitere Direktiven in die Drop-in-Datei schreiben -- keine
Rechteausweitung, aber es würde die Unit unbemerkt verbiegen. Änderungen an Konto und Wiederherstellung landen als
Erweiterungsdatei in `/etc/systemd/system/<unit>.d/ice2k.conf` und
danach folgt ein `daemon-reload` -- mitgelieferte Unit-Dateien werden
nie angefasst. Die Datei wird bei jeder Änderung komplett neu
geschrieben, "Lokales Systemkonto" heißt also schlicht: keine
`User=`-Zeile, die Vorgabe der Unit gilt wieder.

## Welche Dienste in der Liste stehen

Die Liste zeigt **alle installierten** Dienste und wird bei jedem
Öffnen bzw. Aktualisieren neu eingelesen. Früher kam sie aus
`systemctl show '*.service'` -- ein solches Muster passt aber nur auf
Units, die systemd gerade im Speicher hat. Maskierte oder nie gestartete
Dienste fehlten dann, allen voran `samba-ad-dc`, das Debian bis zur
Einrichtung eines Domänencontrollers maskiert ausliefert.

Jetzt werden erst die Namen eingesammelt -- installierte Unit-Dateien
(`systemctl list-unit-files --type=service`) plus geladene Units ohne
eigene Datei, etwa aus Generatoren (`systemctl list-units --all
--type=service --plain`) -- und dann gezielt genau diese Namen per
`systemctl show` abgefragt (in Paketen von 150, damit die Befehlszeile
nicht zu lang wird).

## Wiederverwendung

`SvcPanel` nimmt optional einen `SvcPanelDelegate` entgegen: eigene
Spalten, eigener Zeileninhalt und eine eigene Aktion für Doppelklick
bzw. "Eigenschaften"; Starten/Beenden entfällt dann. So benutzt der
Knoten "Systemdienste" im Gruppenrichtlinienfenster von `dsadmin`
dieselbe Liste -- mit den Spalten Dienstname/Starttyp/Berechtigung.

## Bewusste Abweichungen vom Original

- **Anhalten/Fortsetzen** kennt systemd nicht. Die beiden Schaltflächen
  bleiben wie im Original vorhanden, aber dauerhaft inaktiv.
- **Erster/Zweiter/Weiterer Fehlschlag**: systemd hat nur eine Regel je
  Dienst. Das erste Feld ist bedienbar, die beiden anderen spiegeln es
  gesperrt. "Programm ausführen" und "Computer neu starten" fehlen.
- Die Wartezeit vor dem Neustart zählt systemd in **Sekunden**, das
  Original in Minuten -- das Feld ist deshalb mit Sekunden beschriftet.
- **Anzeigename und Beschreibung** sind schreibgeschützt: sie stammen
  aus `Description=` der Unit-Datei.
- **Kennwort, Datenaustausch mit dem Desktop und Hardwareprofile** aus
  dem Reiter "Anmelden" haben unter Linux keine Entsprechung.
- Instanz-Vorlagen (`getty@.service`) werden ausgeblendet, da sie keine
  startbaren Dienste sind.

## Bauen
```sh
cd services
make && ./services
make test_svccore && ./test_svccore
```

## Bekannte Grenzen
- Das Fenstersymbol ist vorerst das der Computerverwaltung, und die vier
  Wiedergabe-Schaltflächen der Original-Werkzeugleiste sind mangels
  passender Icons als Textschaltflächen ausgeführt.
- Nur Systemdienste (`--system`), keine Benutzerdienste (`--user`).
- Die Liste aktualisiert sich nicht von selbst, sondern über
  "Aktualisieren" bzw. nach jeder Aktion.
- Gegen ein laufendes systemd ist bisher nichts getestet: geprüft sind
  die Parser (siehe `test_svccore.cpp`) und dass beide Programme bauen
  und starten.
