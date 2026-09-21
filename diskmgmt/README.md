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

## Stand

Nur Anzeige. Geplant in eigenen Schritten:

1. Basisdatenträger: Partitionstabelle anlegen, Partition erstellen und
   löschen, formatieren, Mountpunkt zuweisen, als aktiv markieren.
2. Dynamische Datenträger (LVM): umwandeln, die fünf Volumetypen anlegen,
   erweitern.

Verkleinern und Verschieben von Partitionen sind bewusst nicht
vorgesehen.

Benötigt: `parted`, für LVM zusätzlich `lvm2`.

## Bauen

```sh
cd diskmgmt && make && ./diskmgmt
```
