// diskops.h -- Änderungen an Basisdatenträgern.
//
// Jede Aktion wird als Liste von Befehlen geplant, bevor irgendetwas
// passiert. Die Oberfläche zeigt diese Liste zur Bestätigung an und führt
// sie erst dann aus. Die Prüfungen, was überhaupt erlaubt ist (keine
// eingehängte oder Systempartition löschen usw.), stecken hier und nicht
// in der Oberfläche, damit sie für jede Oberfläche gelten.
#pragma once

#include "diskcore.h"
#include <string>
#include <vector>

namespace disk {

// Ein Schritt: Befehl samt Argumenten (ohne Shell) oder eine eingebaute
// Aktion für die fstab.
struct Step {
	std::vector<std::string> argv;   // leer bei fstab-Schritten
	std::string description;         // was der Schritt tut, für die Anzeige
	// fstab: Eintrag für device (UUID wird zur Laufzeit ermittelt) setzen
	// bzw. entfernen.
	enum Kind { COMMAND, FSTAB_SET, FSTAB_REMOVE, WAIT_DEVICE } kind = COMMAND;
	std::string device, mountpoint, fstype;
	std::string disk;                // WAIT_DEVICE: Platte, auf der partx nachschaut
};

struct Plan {
	std::vector<Step> steps;
	std::string error;               // gesetzt, wenn die Aktion nicht erlaubt ist
	std::string warning;             // Warntext des Originals
	bool ok() const { return error.empty(); }
	std::string preview() const;     // Befehle als Text für die Bestätigung
};

// Welche Dateisysteme sich anlegen lassen (mkfs.* vorhanden).
std::vector<std::string> availableFilesystems(Runner run);

// "Signatur schreiben": leere Platte mit Partitionstabelle versehen.
Plan planCreateTable(const Disk& d, const std::string& table /* msdos|gpt */);

enum PartType { PART_PRIMARY, PART_EXTENDED, PART_LOGICAL };
struct NewPartition {
	PartType type = PART_PRIMARY;
	uint64_t start = 0, size = 0;    // Bytes; start ist der Anfang der Lücke
	bool format = true;
	std::string fstype = "ext4", label;
	bool quick = true;
	std::string mountpoint;          // leer = keinen Pfad zuweisen
};
Plan planCreatePartition(const Disk& d, const Segment& gap, const NewPartition& p);

Plan planDeletePartition(const Disk& d, const Segment& s);
Plan planFormat(const Disk& d, const Segment& s, const std::string& fstype, const std::string& label, bool quick);
Plan planSetMountpoint(const Segment& s, const std::string& newMountpoint);
Plan planSetActive(const Disk& d, const Segment& s);

// Führt die Schritte nacheinander aus und bricht beim ersten Fehler ab.
// log bekommt Befehle und Ausgaben.
bool execute(const Plan& plan, Runner run, std::string& log);

} // namespace disk
