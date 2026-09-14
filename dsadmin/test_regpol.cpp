// test_regpol.cpp -- reines Kommandozeilen-Testprogramm, keine GUI.
#include "regpol.h"
#include <iostream>
#include <iomanip>

static int failures = 0;

static void check(bool cond, const std::string& what) {
	if (cond) {
		std::cout << "OK:   " << what << "\n";
	} else {
		std::cout << "FAIL: " << what << "\n";
		failures++;
	}
}

static void hexDump(const std::vector<uint8_t>& bytes, size_t maxLen) {
	for (size_t i = 0; i < bytes.size() && i < maxLen; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << " ";
	}
	std::cout << std::dec << "\n";
}

int main() {
	std::vector<RegPolEntry> entries;
	entries.push_back(makeKeyOnlyEntry("Software\\Policies\\IceTest"));
	entries.push_back(makeRegDwordEntry("Software\\Policies\\IceTest", "SimpleOnOff", 1));
	entries.push_back(makeRegSzEntry("Software\\Policies\\IceTest", "SomeText", "Ein Testwert mit Umlauten: äöüß"));
	entries.push_back(makeRegDwordEntry("Software\\Policies\\IceTest", "SomeNumber", 42));
	entries.push_back(makeRegMultiSzEntry("Software\\Policies\\IceTest", "SomeList", { "Erste Zeile", "Zweite Zeile", "Dritte Zeile" }));
	entries.push_back(makeDeleteValueEntry("Software\\Policies\\IceTest", "AlterWert"));

	auto bytes = buildRegPolFile(entries);

	std::cout << "=== Kopf (erste 12 Bytes) ===\n";
	hexDump(bytes, 12);
	check(bytes.size() >= 8, "Datei hat mindestens einen Kopf");
	check(bytes[0] == 'P' && bytes[1] == 'R' && bytes[2] == 'e' && bytes[3] == 'g', "Signatur ist 'PReg'");
	check(bytes[4] == 1 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0, "Version ist 1 (little-endian DWORD)");

	std::string errorMsg;
	bool wrote = writeRegPolFile("/tmp/test-registry.pol", entries, errorMsg);
	check(wrote, "Datei erfolgreich geschrieben (" + errorMsg + ")");

	RegPolFile parsed = parseRegPolFile("/tmp/test-registry.pol");
	check(parsed.parseError.empty(), "Datei fehlerfrei wieder eingelesen (" + parsed.parseError + ")");
	check(parsed.entries.size() == entries.size(), "Anzahl Eintraege stimmt (" + std::to_string(parsed.entries.size()) + " von " + std::to_string(entries.size()) + ")");

	if (parsed.entries.size() == entries.size()) {
		for (size_t i = 0; i < entries.size(); i++) {
			auto& orig = entries[i];
			auto& read = parsed.entries[i];
			check(orig.key == read.key, "Eintrag " + std::to_string(i) + ": Schluessel stimmt (\"" + read.key + "\")");
			check(orig.valuename == read.valuename, "Eintrag " + std::to_string(i) + ": Wertname stimmt (\"" + read.valuename + "\")");
			check(orig.type == read.type, "Eintrag " + std::to_string(i) + ": Typ stimmt (" + std::to_string(read.type) + ")");
			check(orig.data == read.data, "Eintrag " + std::to_string(i) + ": Daten stimmen byte-genau ueberein");
		}
	}

	// Inhaltliche Stichproben (nicht nur Byte-Vergleich, sondern auch
	// dass die Werte nach dem Rundlauf tatsaechlich das Erwartete
	// bedeuten):
	if (parsed.entries.size() >= 4) {
		uint32_t dw = (uint32_t)parsed.entries[3].data[0] | ((uint32_t)parsed.entries[3].data[1] << 8)
		            | ((uint32_t)parsed.entries[3].data[2] << 16) | ((uint32_t)parsed.entries[3].data[3] << 24);
		check(dw == 42, "SomeNumber liest sich nach dem Rundlauf korrekt als 42");
	}
	if (parsed.entries.size() >= 6) {
		check(parsed.entries[5].valuename == "**del.AlterWert", "Loesch-Eintrag hat korrektes '**del.'-Praefix");
	}

	// Umlaut-Kodierung gezielt pruefen (nicht nur Rundlauf-Konsistenz,
	// sondern dass die UTF-16LE-Bytes tatsaechlich den erwarteten
	// Unicode-Codepunkten entsprechen).
	{
		std::cout << "\n=== Hex-Dump von Eintrag 2 (SomeText mit Umlauten) ===\n";
		hexDump(entries[2].data, entries[2].data.size());
		auto containsBytes = [&](uint8_t b0, uint8_t b1) {
			auto& d = entries[2].data;
			for (size_t i = 0; i + 1 < d.size(); i++) if (d[i] == b0 && d[i + 1] == b1) return true;
			return false;
		};
		check(containsBytes(0xE4, 0x00), "'ä' (U+00E4) korrekt als E4 00 kodiert");
		check(containsBytes(0xF6, 0x00), "'ö' (U+00F6) korrekt als F6 00 kodiert");
		check(containsBytes(0xFC, 0x00), "'ü' (U+00FC) korrekt als FC 00 kodiert");
		check(containsBytes(0xDF, 0x00), "'ß' (U+00DF) korrekt als DF 00 kodiert");
	}

	std::cout << "\n" << (failures == 0 ? "Alle Tests erfolgreich." : (std::to_string(failures) + " Test(s) fehlgeschlagen.")) << "\n";
	return failures == 0 ? 0 : 1;
}
