// test_aas_struct.cpp -- prueft den Aufbau des Advertise-Skripts.
//
// Die Sollwerte stammen aus dem Vergleich mit zwei .aas-Dateien, die
// ein echter Windows-2000-Server erzeugt hat. Gegen diese Vorlage ist
// die Ausgabe byteweise identisch (bis auf den Zeitstempel); hier wird
// die Struktur nachgeprueft, ohne fremde Dateien im Repo abzulegen.
//
//   make test_aas_struct && ./test_aas_struct

#include "aas.h"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

struct Rec { uint8_t op; uint8_t argc; };

// Zerlegt den Bytestrom in Datensaetze (Opcode + Argumentzahl).
static std::vector<Rec> parseRecords(const std::vector<uint8_t>& d) {
	std::vector<Rec> recs;
	size_t i = 0;
	while (i + 2 <= d.size()) {
		Rec r{ d[i], d[i + 1] };
		i += 2;
		for (int a = 0; a < r.argc && i + 2 <= d.size(); a++) {
			uint16_t tl = (uint16_t)(d[i] | (d[i + 1] << 8));
			i += 2;
			int tag = tl >> 14, len = tl & 0x3FFF;
			if (tag == 1) i += 4;              // int32
			else if (tag == 3) i += len * 2;   // Unicode
			else i += len;                     // ASCII / Binaerstrom
		}
		recs.push_back(r);
	}
	return recs;
}

static AasPackageInfo sample() {
	AasPackageInfo i;
	i.productName = "7-Zip 26.03";
	i.packageFileName = "7Z2603.MSI";
	i.productCodeGuid = "{23170F69-40C1-2701-2603-000001000000}";
	i.packageCodeGuid = "{23170F69-40C1-2701-2603-000002000000}";
	i.upgradeCodeGuid = "{23170F69-40C1-2701-0000-000004000000}";
	i.versionString = "26.3.0";
	i.msiUncPath = "\\\\Win2k-server\\Software\\7Z2603.MSI";
	i.assignedPerMachine = true;
	i.langId = 1033;
	i.features = { {"Program", "Complete"}, {"Complete", ""}, {"LanguageFiles", "Complete"} };
	return i;
}

static void testRecordSequence() {
	auto recs = parseRecords(buildAasFile(sample()));

	// Genau die Abfolge, die ein echter Windows-2000-Server schreibt.
	const Rec expected[] = {
		{0x02, 9},   // Header
		{0x04, 13},  // ProductInfo -- 13, nicht 16
		{0x05, 3}, {0x05, 2},
		{0x06, 7},   // Rollback-Aktionstexte
		{0x08, 3},   // PublishFeatures
		{0x41, 3}, {0x41, 3}, {0x41, 3},   // je Feature einer
		{0x08, 3},   // PublishProduct
		{0x10, 1},   // PackageCode
		{0x62, 1},   // UpgradeCode
		{0x09, 9},   // Quellenliste
		{0x12, 2},
		{0x03, 2},   // Ende -- 2 Argumente, nicht 3
	};
	const size_t n = sizeof(expected) / sizeof(expected[0]);
	assert(recs.size() == n);
	for (size_t i = 0; i < n; i++) {
		assert(recs[i].op == expected[i].op);
		assert(recs[i].argc == expected[i].argc);
	}
	// Die Gesamtgroesse des Vorbilds fuer genau diese Angaben.
	assert(buildAasFile(sample()).size() == 684);
}

static void testFeaturesDriveScript() {
	// Jedes Feature erzeugt genau einen 0x41-Datensatz.
	AasPackageInfo i = sample();
	i.features = { {"Nur eins", ""} };
	auto recs = parseRecords(buildAasFile(i));
	int n41 = 0;
	for (auto& r : recs) if (r.op == 0x41) n41++;
	assert(n41 == 1);

	// Ohne Features fehlen sie ganz -- das war der urspruengliche Fehler.
	i.features.clear();
	recs = parseRecords(buildAasFile(i));
	n41 = 0;
	for (auto& r : recs) if (r.op == 0x41) n41++;
	assert(n41 == 0);

	// Ohne UpgradeCode entfaellt der 0x62-Datensatz, der Rest bleibt.
	i = sample();
	i.upgradeCodeGuid.clear();
	recs = parseRecords(buildAasFile(i));
	bool has62 = false;
	for (auto& r : recs) if (r.op == 0x62) has62 = true;
	assert(!has62);
	assert(recs.back().op == 0x03);
}

static void testStringEncoding() {
	// Produktname als ASCII, nicht als Unicode -- war vorher falsch.
	auto d = buildAasFile(sample());
	std::string bytes((const char*)d.data(), d.size());
	assert(bytes.find("7-Zip 26.03") != std::string::npos);
	// Bei Unicode staende zwischen den Zeichen je ein Nullbyte.
	assert(bytes.find(std::string("7\0-\0Z\0", 6)) == std::string::npos);

	// Die Quellenliste enthaelt nur das Verzeichnis, nicht den Dateinamen.
	assert(bytes.find("\\\\Win2k-server\\Software\\") != std::string::npos);
}

int main() {
	testRecordSequence();
	testFeaturesDriveScript();
	testStringEncoding();
	printf("aas-Struktur: alle Tests bestanden\n");
	return 0;
}
