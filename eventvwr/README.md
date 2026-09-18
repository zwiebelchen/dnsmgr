# eventvwr -- Ereignisanzeige

Nachbau von `eventvwr.msc` aus Windows 2000.

## Aufbau

Links der Baum mit "Ereignisanzeige (Lokal: <Rechner>)" und den drei
Protokollen **Anwendung**, **Sicherheit** und **System**, rechts die
Ereignisliste mit den Spalten des Originals: Typ, Datum, Zeit, Quelle,
Kategorie, Ereignis, Benutzer, Computer. Doppelklick öffnet die
**Ereigniseigenschaften** mit denselben Feldern, der Beschreibung sowie
den Pfeiltasten zum Blättern und "Kopieren" (legt das Ereignis im Format
des Originals in der Zwischenablage ab).

Menü "Vorgang": Alle Ereignisse löschen, Aktualisieren, Eigenschaften.
Menü "Ansicht": Filter (Ereignistypen, Quelle, Anzahl der Ereignisse).

## Woher die Ereignisse kommen

1. **systemd-Journal** über `journalctl -o json`. Daraus stammen
   Zeitstempel, Priorität, Quelle (`SYSLOG_IDENTIFIER`), Rechnername,
   Benutzer (`_UID`) und die Meldung.
2. Gibt es kein Journal, werden die klassischen Logdateien gelesen:
   `/var/log/syslog`, `/var/log/messages`, `/var/log/auth.log`,
   `/var/log/secure` und `/var/log/kern.log`. Die Statuszeile sagt, wenn
   diese Rückfallebene greift.

**Zuordnung zu den drei Protokollen:** über die Syslog-Facility --
auth/authpriv → Sicherheit, kern/daemon → System, alles Übrige →
Anwendung. In den Logdateien fehlt die Facility, dort entscheidet die
Quelle (kernel, systemd → System; sshd, sudo, su, login, polkitd →
Sicherheit).

**Ereignistyp:** aus der Priorität -- 0-3 Fehler, 4 Warnung, ab 5
Informationen. In den Logdateien wird nach "error", "failed" bzw. "warn"
im Text entschieden.

## Abweichungen vom Original

- **Ereigniskennung**: Windows hat je Meldung eine feste Nummer aus der
  Meldungstabelle des Herstellers. Unter Linux gibt es das nicht; die
  Spalte zeigt deshalb die Prozesskennung (PID) bzw. "-".
- **Kategorie** ist immer "Keine".
- **Alle Ereignisse löschen** leert das ganze Journal
  (`journalctl --rotate` und `--vacuum-time=1s`), nicht nur das gewählte
  Protokoll -- journald kennt diese Trennung nicht. Die Rückfrage sagt
  das ausdrücklich. Bei der Rückfallebene über die Logdateien passiert
  nichts, die verwaltet logrotate.
- Die Symbole für Fehler, Warnung und Informationen sind eigene
  Nachbauten.
- Noch nicht umgesetzt: Protokolleigenschaften (Größe, Überschreiben),
  Speichern unter, Sortieren nach Spalten, Suchen.

## Gemeinsam mit der Computerverwaltung

Das Einsammeln der Ereignisse (`common/evt/evtcore`) und die Liste samt
Eigenschaften- und Filterdialog (`common/evt/evtpanel`) liegen in
`common/`, wie bei der Dienstverwaltung. Die Computerverwaltung zeigt
dieselbe Ansicht in ihrem Zweig "Systemprogramme → Ereignisanzeige";
Korrekturen wirken damit in beiden Programmen.

## Bauen

```sh
cd eventvwr && make && ./eventvwr
```
