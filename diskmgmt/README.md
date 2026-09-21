# diskmgmt -- Datenträgerverwaltung

Nachbau von `diskmgmt.msc` aus Windows 2000. Dieselbe Ansicht zeigt die
Computerverwaltung unter "Datenspeicher → Datenträgerverwaltung"; beide
nutzen den Baustein `common/disk`.

## Aufbau

Wie im Original: oben die Volumeliste mit den Spalten Datenträger,
Layout, Typ, Dateisystem, Status, Kapazität, Freier Speicher, % frei,
Fehlertoleranz und Overhead; unten die grafische Ansicht mit einem Block
je Datenträger ("Datenträger 0 / Basis / 256 MB / Online") und farbigen
Balken je Abschnitt, darunter die Legende. Eine Auswahl in der Liste
markiert den Abschnitt in der Grafik und umgekehrt.

## Abbildung auf Linux

| Windows 2000 | Hier |
|---|---|
| Basisdatenträger | Platte mit klassischer Partitionstabelle (MBR oder GPT) |
| Primäre Partition, erweiterte Partition, logisches Laufwerk | dieselben Begriffe bei MBR; bei GPT sind alle Partitionen primär |
| Freier Speicherplatz | Lücke innerhalb der erweiterten Partition |
| Nicht zugeordnet | Lücke außerhalb von Partitionen bzw. freier Bereich eines LVM-PV |
| Dynamischer Datenträger | Platte (oder Partition), die ein LVM-PV trägt |
| Einfacher / übergreifender Datenträger | lineares LV auf einem / mehreren PVs |
| Stripeset-, gespiegelter, RAID-5-Datenträger | LV mit `striped`, `raid1`, `raid5` |
| Fehlerfrei (System) | Dateisystem ist unter `/` eingehängt |

Die Volumes heißen nach ihrer Bezeichnung und dem Mountpunkt, etwa
"SYSTEM (/)"; Laufwerkbuchstaben gibt es nicht.

## Woher die Angaben kommen

`lsblk -J -b` (Platten, Größe, Wechselmedium, Mountpunkte),
`parted -m ... unit B print` (Partitionstabelle mit Start und Größe),
`blkid -p` (Dateisystem und Bezeichnung -- ohne udev zuverlässiger als die
entsprechenden lsblk-Spalten), `df -B1` (Belegung) sowie
`lvs`/`pvs --segments` im JSON-Format für LVM. Lücken unter 1 MB
(Ausrichtungsreste) werden nicht gezeigt. Geräte, auf die kein Zugriff
möglich ist, erscheinen wie im Original als "Nicht lesbar".

Die LVM-Auswertung prüft ein Unit-Test gegen Beispielausgaben aller fünf
Volumetypen (`common/disk/test_diskcore.cpp`), weil sich LVs ohne
Device-Mapper -- etwa in Containern -- nicht anlegen lassen.

## Abgleich mit dem Original

Spalten, Legende, Plattentypen und Zustände stammen wortgleich aus der
deutschen `dmdskres.dll` (Windows 2000 SP4; Texte 5002, 6002, 6005/6006,
53288/53289, 53355/53357, 53381-53389). `dmdlgs.dll` und `dmview.ocx`
enthalten keine verwertbaren Texte. Die Farben der Legende folgen dem
Original.

## Basisdatenträger ändern

Rechtsklick in der grafischen Ansicht, Menütexte wortgleich aus
`dmdskres.dll`:

| Stelle | Befehle |
|---|---|
| Plattenblock einer leeren Platte | Signatur schreiben (MBR oder GPT) |
| Nicht zugeordneter Bereich | Partition erstellen... |
| Freier Speicherplatz einer erweiterten Partition | Logisches Laufwerk erstellen..., Erweiterte Partition löschen... (wenn leer) |
| Partition bzw. logisches Laufwerk | Laufwerkbuchstaben und -pfad ändern..., Formatieren..., Partition als aktiv markieren (MBR), Partition löschen... |
| überall | Festplatten neu einlesen |

Der **Assistent zum Erstellen von Partitionen** hat die Seiten des
Originals: Willkommen, Partitionstyp, Größe, Laufwerkpfad, Formatieren,
Fertigstellen. Nicht mögliche Typen sind gesperrt (bei GPT nur primär,
logische Laufwerke nur in einer erweiterten Partition, höchstens vier
primäre bei MBR).

**Laufwerkpfad** heißt hier Mountpunkt: Der Eintrag kommt per UUID in die
`/etc/fstab` (mit `nofail` und dem Kommentar "ice2k
Datenträgerverwaltung"), der Ordner wird angelegt und das Dateisystem
eingehängt. Laufwerkbuchstaben gibt es nicht.

**Formatieren** bietet die Dateisysteme an, für die ein `mkfs.*`
vorhanden ist (ext4, xfs, btrfs, FAT32, NTFS ...); QuickFormat wirkt bei
NTFS, bei den übrigen ist ohnehin schnell.

### Sicherheit

- Jede Aktion wird als Liste von Befehlen geplant (`common/disk/diskops`)
  und **vor der Ausführung angezeigt**; ausgeführt wird erst nach "Ja".
  Dazu stehen die Warntexte des Originals ("Alle Daten auf ... werden
  verloren gehen", "WARNUNG: Alle Daten auf diesem Datenträger werden
  durch die Formatierung gelöscht").
- Die Systempartition (`/`) lässt sich weder löschen noch formatieren
  noch umhängen; eingehängte Partitionen müssen zuerst ausgehängt werden;
  LVM-PVs sind hier gesperrt.
- Eine Signatur lässt sich nur auf eine leere Platte ohne
  Partitionstabelle schreiben.
- Schlägt ein Schritt fehl, bricht die Ausführung ab und zeigt das
  vollständige Protokoll.

Die Prüfungen stecken im GUI-freien Kern, nicht in der Oberfläche, und
sind mit Image-Dateien als Loop-Geräte getestet: logisches Laufwerk
anlegen, formatieren, einhängen, aushängen, löschen; Signatur auf eine
leere Platte; Ablehnen bei eingehängter und bei Systempartition.

Bewusst **nicht** vorgesehen: Verkleinern und Verschieben von
Partitionen.

## Noch offen

Dynamische Datenträger (LVM): in dynamische Festplatte umwandeln, die
fünf Volumetypen anlegen, Datenträger erweitern.

Benötigt: `parted` und `util-linux` (`partx`), für LVM zusätzlich
`lvm2`.

## Bauen

```sh
cd diskmgmt && make && ./diskmgmt
```
