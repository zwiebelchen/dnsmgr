// diskcore.h -- Datenträger, Partitionen und LVM einsammeln.
//
// Ohne FOX-Abhängigkeit (wie common/svc und common/evt), damit der Kern
// mit Beispielausgaben getestet werden kann (test_diskcore).
//
// Quellen:
//   lsblk -J -b     Platten, Größe, Modell, Wechselmedium, Mountpunkte
//   sfdisk -J       Partitionstabelle mit Start, Größe und Typ
//   blkid -p        Dateisystem und Bezeichnung (ohne udev zuverlässiger
//                   als die entsprechenden lsblk-Spalten)
//   df -B1          Belegung eingehängter Dateisysteme
//   pvs/lvs         LVM -- Windows 2000 nennt das "dynamische Datenträger"
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace disk {

// Art eines Abschnitts in der grafischen Ansicht -- die Farben und Namen
// der Legende im Original (dmdskres.dll).
enum SegmentKind {
	SEG_UNALLOCATED = 0,  // Nicht zugeordnet (schwarz)
	SEG_PRIMARY,          // Primäre Partition
	SEG_EXTENDED,         // Erweiterte Partition (Rahmen um die logischen)
	SEG_FREE,             // Freier Speicherplatz (innerhalb der erweiterten)
	SEG_LOGICAL,          // Logisches Laufwerk
	SEG_SIMPLE,           // Einfacher Datenträger (LVM linear, ein PV)
	SEG_SPANNED,          // Übergreifender Datenträger (linear über mehrere PVs)
	SEG_STRIPED,          // Stripesetdatenträger
	SEG_MIRRORED,         // Gespiegelter Datenträger (raid1)
	SEG_RAID5             // RAID-5-Datenträger
};

struct Segment {
	SegmentKind kind = SEG_UNALLOCATED;
	uint64_t start = 0, size = 0;   // Bytes
	std::string device;             // /dev/sda1 bzw. /dev/vg/lv
	std::string fstype, label, mountpoint;
	std::string lvName, vgName;     // nur LVM
	bool isPv = false;              // Partition trägt ein LVM-PV
	int number = 0;                 // Partitionsnummer (parted), 0 = keine
	bool bootFlag = false;          // "aktiv" (MBR-Startkennzeichen)
};

struct Disk {
	std::string name;       // sda
	std::string path;       // /dev/sda
	std::string model;
	uint64_t size = 0;
	bool removable = false;
	bool cdrom = false;
	bool dynamic = false;   // ganze Platte oder eine Partition ist LVM-PV
	bool unreadable = false;// "Nicht lesbar" -- kein Zugriff auf das Gerät
	std::string table;      // "dos", "gpt" oder leer
	std::vector<Segment> segments;   // nach Start sortiert, mit Lücken
};

// Eine Zeile der Volumeliste (Spalten wie dmdskres.dll, Text 5002).
struct Volume {
	std::string name;       // "SYSTEM (/)" usw.
	std::string device;
	std::string layout;     // Partition, Einfach, Übergreifend, ...
	std::string type;       // Basis oder Dynamisch
	std::string fstype;
	std::string status;     // Fehlerfrei, Fehlerfrei (System) ...
	uint64_t capacity = 0;
	int64_t freeBytes = -1; // -1 = unbekannt (nicht eingehängt)
	bool faultTolerant = false;
	int overheadPercent = 0;
};

struct Snapshot {
	std::vector<Disk> disks;
	std::vector<Volume> volumes;
	std::string error;      // leer, wenn alles geklappt hat
};

// Befehlsausführung austauschbar, damit der Test Beispielausgaben
// einspielen kann.
typedef int (*Runner)(const std::vector<std::string>& args, std::string& out);

Snapshot collect(Runner run);

// Hilfsfunktionen, auch für die Oberfläche.
std::string formatSize(uint64_t bytes);          // "96 MB", "19,99 GB"
const char* kindName(SegmentKind k);             // Legende
bool kindIsDynamic(SegmentKind k);

// Einzeln testbar:
struct LvInfo {
	std::string name, vg, segtype, path;
	uint64_t size = 0;
	int stripes = 1;
	std::vector<std::string> devices;   // PVs
};
std::vector<LvInfo> parseLvs(const std::string& json);
struct PvSegment {
	std::string pv, lv, vg;
	uint64_t start = 0, size = 0;       // Bytes
};
std::vector<PvSegment> parsePvSegments(const std::string& json);
SegmentKind lvKind(const LvInfo& lv);

} // namespace disk
