// regpol.h
//
// Lesen/Schreiben des "Registry.pol"-Binaerformats, das Windows fuer
// Gruppenrichtlinien-Registry-Einstellungen verwendet (liegt im GPO
// unter Machine/Registry.pol bzw. User/Registry.pol in SYSVOL). Ein
// echter Windows-Client liest genau diese Datei beim Anmelden/beim
// Gruppenrichtlinien-Update.
//
// Format (alle Mehrbyte-Werte little-endian):
//   Kopf:    DWORD Signatur ("PReg" als 4 Rohbytes 50 52 65 67,
//            als kleine-Endian-DWORD gelesen 0x67655250)
//            DWORD Version (immer 1)
//   Danach beliebig viele Eintraege, jeweils:
//     WCHAR '['
//     WCHAR[]  Schluesselname (nullterminierte UTF-16LE-Zeichenkette)
//     WCHAR ';'
//     WCHAR[]  Wertname (nullterminiert, kann leer sein)
//     WCHAR ';'
//     DWORD    Typ (REG_SZ=1, REG_BINARY=3, REG_DWORD=4, REG_MULTI_SZ=7 ...)
//               -- als ROHE 4 Bytes, NICHT als Text!
//     WCHAR ';'
//     DWORD    Groesse der Daten in Bytes -- ebenfalls roh, nicht als Text
//     WCHAR ';'
//     BYTE[]   Daten (Format haengt vom Typ ab)
//     WCHAR ']'
//
// Loeschkonvention (von echtem Windows/gpedit verwendet, damit ein
// deaktivierter Wert beim naechsten Gruppenrichtlinien-Update wieder
// entfernt wird): Wertname wird "**del.<eigentlicherName>" vorangestellt,
// Typ REG_SZ, leere Daten.

#ifndef REGPOL_H
#define REGPOL_H

#include <string>
#include <vector>
#include <cstdint>

enum RegValueType {
	REG_TYPE_NONE = 0,
	REG_TYPE_SZ = 1,
	REG_TYPE_EXPAND_SZ = 2,
	REG_TYPE_BINARY = 3,
	REG_TYPE_DWORD = 4,
	REG_TYPE_MULTI_SZ = 7,
};

struct RegPolEntry {
	std::string key;         // z.B. "Software\\Policies\\IceTest" (UTF-8, wird beim Schreiben nach UTF-16LE gewandelt)
	std::string valuename;   // Wertname, "" fuer einen reinen Schluessel-Eintrag
	uint32_t type = REG_TYPE_SZ;
	std::vector<uint8_t> data; // rohe Daten, wie sie in die Datei geschrieben werden
};

// Hilfsfunktionen zum Erzeugen typischer Eintraege.
RegPolEntry makeRegSzEntry(const std::string& key, const std::string& valuename, const std::string& text);
RegPolEntry makeRegDwordEntry(const std::string& key, const std::string& valuename, uint32_t value);
RegPolEntry makeRegMultiSzEntry(const std::string& key, const std::string& valuename, const std::vector<std::string>& lines);
RegPolEntry makeDeleteValueEntry(const std::string& key, const std::string& valuename);
RegPolEntry makeKeyOnlyEntry(const std::string& key); // legt nur den Schluessel an, ohne Wert

// Serialisiert eine Liste von Eintraegen zu den rohen Bytes der Datei.
std::vector<uint8_t> buildRegPolFile(const std::vector<RegPolEntry>& entries);

// Schreibt die Datei (unprivilegiert -- root-Rechte muss der Aufrufer
// selbst herstellen, z.B. ueber unsere runAsRoot-Helfer, indem er erst
// in eine temporaere Datei schreibt und diese dann als root verschiebt).
bool writeRegPolFile(const std::string& path, const std::vector<RegPolEntry>& entries, std::string& errorMsg);

// Liest eine registry.pol-Datei zurueck ein (fuer Rundlauf-Tests und
// spaeter, um ein bestehendes GPO-Registry.pol vor dem Bearbeiten
// einzulesen).
struct RegPolFile {
	std::vector<RegPolEntry> entries;
	std::string parseError;
};
RegPolFile parseRegPolBytes(const std::vector<uint8_t>& bytes);
RegPolFile parseRegPolFile(const std::string& path);

#endif
