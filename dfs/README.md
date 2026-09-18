# dfs -- Verteiltes Dateisystem

Nachbau des Snap-Ins "Verteiltes Dateisystem" (DFS) aus Windows 2000
Server.

## Aufbau

Links der Baum mit "Verteiltes Dateisystem", darunter die DFS-Stämme
dieses Servers und je Stamm seine Verknüpfungen. Rechts die Liste --
je nach Auswahl die Stämme, die Verknüpfungen eines Stammes oder die
Verweisziele einer Verknüpfung. Angelegt, geändert und gelöscht wird
über das Kontextmenü und das Menü "Vorgang".

## Unterbau

Samba bildet DFS vollständig ab:

| Windows | Hier |
|---|---|
| DFS-Stamm | Freigabe in der `smb.conf` mit `msdfs root = yes` |
| DFS-Verknüpfung | Symlink im Verzeichnis dieser Freigabe mit dem Ziel `msdfs:server\freigabe` |
| Replikat einer Verknüpfung | weiteres Ziel im selben Symlink, durch Komma getrennt |

- **Neuer DFS-Stamm** legt das Verzeichnis an, ergänzt die Freigabe in
  der `smb.conf` und lädt die Konfiguration neu
  (`smbcontrol all reload-config`, ersatzweise `systemctl reload-or-restart`).
- **Stamm entfernen** nimmt nur die Freigabe aus der Konfiguration; das
  Verzeichnis und die Verknüpfungen darin bleiben erhalten. Die Rückfrage
  sagt das.
- **Neue DFS-Verknüpfung** und **Neues Replikat** schreiben den Symlink;
  eingegeben wird das Ziel als UNC-Pfad (`\\server\freigabe`).
- `host msdfs = yes` ist Samba-Vorgabe und wird vorausgesetzt.

## Abweichungen vom Original

- Windows kennt neben eigenständigen auch **domänenbasierte** DFS-Stämme
  (im Verzeichnisdienst veröffentlicht, mehrere Stammserver). Hier gibt
  es bisher nur eigenständige Stämme auf diesem Server.
- **Replikation**: Windows hält die Replikate mit dem Dateireplikations-
  dienst (FRS) gleich. Samba tut das nicht -- die Ziele einer
  Verknüpfung sind Alternativen, deren Inhalte selbst gleichgehalten
  werden müssen (z.B. mit rsync). Der Dialog sagt das ausdrücklich.
- **Status** ist immer "Aktiviert"; es wird nicht geprüft, ob das Ziel
  erreichbar ist.
- Verknüpfungen haben keinen Kommentar und keinen Zwischenspeicher-Wert
  (Timeout), weil ein Symlink dafür keinen Platz bietet.
- Beschriftungen und Symbole sind eigene; sobald `dfsgui.dll` vorliegt,
  werden sie wie in den anderen Programmen angeglichen.

## Bauen

```sh
cd dfs && make && ./dfs
```
