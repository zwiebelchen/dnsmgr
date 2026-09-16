// aas.cpp
#include "aas.h"
#include <fstream>
#include <ctime>
#include <cstring>

// ---------------------------------------------------------------------
// UTF-8 -> UTF-16LE (fuer Unicode-Stringargumente). Bewusst eine
// eigene, minimale Kopie statt eines gemeinsamen Moduls mit regpol.cpp
// -- beide Dateien sollen unabhaengig bleiben (kein GUI, keine
// Kreuzabhaengigkeiten).
// ---------------------------------------------------------------------
static std::vector<uint16_t> utf8ToUtf16Units(const std::string& s) {
	std::vector<uint16_t> out;
	size_t i = 0, n = s.size();
	while (i < n) {
		unsigned char c = s[i];
		uint32_t cp = 0;
		int len = 1;
		if ((c & 0x80) == 0) { cp = c; len = 1; }
		else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
		else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
		else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
		else { i++; continue; }
		if (i + len > n) break;
		bool ok = true;
		for (int k = 1; k < len; k++) {
			unsigned char cc = s[i + k];
			if ((cc & 0xC0) != 0x80) { ok = false; break; }
			cp = (cp << 6) | (cc & 0x3F);
		}
		if (!ok) { i++; continue; }
		i += len;
		if (cp <= 0xFFFF) {
			out.push_back((uint16_t)cp);
		} else {
			cp -= 0x10000;
			out.push_back((uint16_t)(0xD800 + (cp >> 10)));
			out.push_back((uint16_t)(0xDC00 + (cp & 0x3FF)));
		}
	}
	return out;
}

// ---------------------------------------------------------------------
// Record-/Argument-Schreiber nach [MS-GPSI] 2.2.4.1.
// ---------------------------------------------------------------------
namespace {

class AasWriter {
public:
	std::vector<uint8_t> buf;

	void u16(uint16_t v) {
		buf.push_back((uint8_t)(v & 0xFF));
		buf.push_back((uint8_t)((v >> 8) & 0xFF));
	}
	void u32(uint32_t v) {
		buf.push_back((uint8_t)(v & 0xFF));
		buf.push_back((uint8_t)((v >> 8) & 0xFF));
		buf.push_back((uint8_t)((v >> 16) & 0xFF));
		buf.push_back((uint8_t)((v >> 24) & 0xFF));
	}
	void record(uint8_t opcode, uint8_t argCount) {
		// "Das erste 16-Bit-Wort eines Datensatzes enthaelt den Opcode im
		// unteren, die Argumentanzahl im oberen Byte."
		u16((uint16_t)opcode | ((uint16_t)argCount << 8));
	}
	// Typ/Laenge-Kodierung: oberste 2 Bits = Typ-Tag (00=ASCII, 01=Ganzzahl,
	// 10=Binaerstrom, 11=Unicode), untere 14 Bit = Laenge (max 16383) --
	// fuer laengere Werte gaebe es "Extended size", hier nicht gebraucht.
	void argInt32(int32_t v) {
		u16(0x4000);
		u32((uint32_t)v);
	}
	void argAsciiString(const std::string& s) {
		u16((uint16_t)(s.size() & 0x3FFF)); // Typ-Tag 00
		buf.insert(buf.end(), s.begin(), s.end());
	}
	void argNullString() {
		u16(0x0000); // leerer ASCII-String, keine Daten
	}
	void argUnicodeString(const std::string& utf8) {
		auto units = utf8ToUtf16Units(utf8);
		u16((uint16_t)(0xC000 | (units.size() & 0x3FFF)));
		for (auto u : units) { buf.push_back((uint8_t)(u & 0xFF)); buf.push_back((uint8_t)((u >> 8) & 0xFF)); }
	}
	void argNull() {
		u16(0x8000); // "Null argument" -- leerer Binaerstrom
	}
};

// Wandelt "A.B.C" in (A<<24)|(B<<16)|C, wie von [MS-GPSI] 2.2.4.2.2 gefordert.
static uint32_t encodeVersion(const std::string& v) {
	int a = 0, b = 0, c = 0;
	std::sscanf(v.c_str(), "%d.%d.%d", &a, &b, &c);
	if (a > 0xFF) a = 0xFF;
	if (b > 0xFF) b = 0xFF;
	if (c > 0xFFFF) c = 0xFFFF;
	return ((uint32_t)a << 24) | ((uint32_t)b << 16) | (uint32_t)c;
}

// DOS-Datum/Zeit fuer den Header-Zeitstempel, aus der aktuellen
// lokalen Zeit ([MS-GPSI] 2.2.4.2.1).
static uint32_t currentDosTimestamp() {
	time_t t = time(NULL);
	struct tm lt;
	localtime_r(&t, &lt);
	uint16_t dosDate = (uint16_t)((lt.tm_mday & 0x1F) | (((lt.tm_mon + 1) & 0xF) << 5) | (((lt.tm_year + 1900 - 1980) & 0x7F) << 9));
	uint16_t dosTime = (uint16_t)(((lt.tm_sec / 2) & 0x1F) | ((lt.tm_min & 0x3F) << 5) | ((lt.tm_hour & 0x1F) << 11));
	return ((uint32_t)dosDate << 16) | dosTime;
}

// Trennt eine volle UNC-Pfad-Angabe in Verzeichnis (mit
// abschliessendem Backslash) und Dateiname.
static void splitUncPath(const std::string& full, std::string& dir, std::string& filename) {
	size_t pos = full.find_last_of('\\');
	if (pos == std::string::npos) { dir = ""; filename = full; return; }
	dir = full.substr(0, pos + 1);
	filename = full.substr(pos + 1);
}

} // namespace

// ---------------------------------------------------------------------
// Aufbau der Datei.
//
// Die Reihenfolge und die Argumentzahl jedes Datensatzes stammen nicht
// aus einer Auslegung der Spezifikation, sondern aus dem Vergleich mit
// zwei .aas-Dateien, die ein echter Windows-2000-Server erzeugt hat.
// Die frueheren, aus [MS-GPSI] abgeleiteten Annahmen waren an mehreren
// Stellen falsch: Produkt- und Dateiname schreibt Windows als ASCII
// (nicht Unicode), ProductInfo hat 13 statt 16 Argumente, der Header
// traegt 200 statt 400 -- und vor allem fehlten die Datensaetze, die
// die Features des Pakets veroeffentlichen. Ohne die weiss der Windows
// Installer nicht, was er installieren soll.
// ---------------------------------------------------------------------
std::vector<uint8_t> buildAasFile(const AasPackageInfo& info) {
	AasWriter w;
	std::string dir, filename;
	splitUncPath(info.msiUncPath, dir, filename);

	// --- Header (Opcode 0x02, 9 Argumente) ---
	w.record(0x02, 9);
	w.argInt32(1397708873);           // "IXOS"
	w.argInt32(200);                  // Version (Windows 2000 schreibt 200)
	w.argInt32((int32_t)currentDosTimestamp());
	w.argInt32((int32_t)info.langId);
	w.argInt32(0);
	w.argInt32(3);                    // ScriptType
	w.argInt32(21);                   // ScriptMajorVersion
	w.argInt32(4);                    // ScriptMinorVersion
	w.argInt32(0);                    // ScriptAttributes

	// --- ProductInfo (Opcode 0x04, 13 Argumente) ---
	w.record(0x04, 13);
	w.argAsciiString(info.productCodeGuid);
	w.argAsciiString(info.productName);      // ASCII, nicht Unicode
	w.argAsciiString(filename);              // ASCII, nicht Unicode
	w.argInt32((int32_t)info.langId);
	w.argInt32((int32_t)encodeVersion(info.versionString));
	w.argInt32(info.assignedPerMachine ? 1 : 0);
	w.argInt32(0);
	w.argNull();
	w.argNull();
	w.argAsciiString(info.packageCodeGuid);
	w.argNull();
	w.argNull();
	w.argInt32(0);

	// --- Sprache/Produktname (Opcode 0x05) ---
	w.record(0x05, 3);
	w.argInt32(0);
	w.argInt32((int32_t)info.langId);
	w.argInt32(0);

	w.record(0x05, 2);
	w.argInt32(1);
	w.argAsciiString(info.productName);

	// --- Rollback-Aktionstexte (Opcode 0x06) -- feste Zeichenketten,
	// die Windows unveraendert in jedes Skript schreibt.
	w.record(0x06, 7);
	w.argNull();
	w.argAsciiString("Rollback");
	w.argAsciiString("Rolling back action:");
	w.argAsciiString("[1]");
	w.argAsciiString("RollbackCleanup");
	w.argAsciiString("Removing backup files");
	w.argAsciiString("File: [1]");

	// --- Features veroeffentlichen (Opcode 0x08 + je ein 0x41) ---
	w.record(0x08, 3);
	w.argAsciiString("PublishFeatures");
	w.argAsciiString("Publishing Product Features");
	w.argAsciiString("Feature: [1]");

	for (const auto& f : info.features) {
		w.record(0x41, 3);
		w.argAsciiString(f.name);
		if (f.parent.empty()) w.argNull(); else w.argAsciiString(f.parent);
		w.argInt32(1);
	}

	// --- Produkt veroeffentlichen (Opcode 0x08) ---
	w.record(0x08, 3);
	w.argAsciiString("PublishProduct");
	w.argAsciiString("Publishing product information");
	w.argNull();

	// --- PackageCode und UpgradeCode ---
	w.record(0x10, 1);
	w.argAsciiString(info.packageCodeGuid);

	if (!info.upgradeCodeGuid.empty()) {
		w.record(0x62, 1);
		w.argAsciiString(info.upgradeCodeGuid);
	}

	// --- Quellenliste (Opcode 0x09, 9 Argumente) ---
	// Bemerkenswert: der volle Pfad zur .msi steht hier NICHT drin, nur
	// das Quellverzeichnis. Den Dateinamen holt der Client aus
	// msiFileList am packageRegistration-Objekt in AD.
	w.record(0x09, 9);
	w.argNull();
	w.argNull();
	w.argNull();
	w.argNull();
	w.argInt32(1);
	w.argInt32(1);
	w.argNull();
	w.argNull();
	w.argAsciiString(dir);

	w.record(0x12, 2);
	w.argNull();
	w.argNull();

	// --- Ende (Opcode 0x03, 2 Argumente) ---
	w.record(0x03, 2);
	w.argInt32(0);
	w.argInt32(0);

	return w.buf;
}

bool writeAasFile(const std::string& path, const AasPackageInfo& info, std::string& errorMsg) {
	auto bytes = buildAasFile(info);
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	if (!out.is_open()) { errorMsg = "Konnte Datei nicht zum Schreiben oeffnen: " + path; return false; }
	out.write((const char*)bytes.data(), (std::streamsize)bytes.size());
	if (!out.good()) { errorMsg = "Schreibfehler bei " + path; return false; }
	return true;
}
