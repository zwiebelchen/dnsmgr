// test_aas.cpp -- reines Kommandozeilen-Testprogramm, keine GUI.
// Liest die selbst erzeugten .aas-Bytes wieder ein (unabhaengiger
// Mini-Parser, nur fuer diesen Test) und prueft Opcodes, Argument-
// anzahlen und ausgewaehlte Werte gegen die MS-GPSI-Spezifikation.
#include "aas.h"
#include <iostream>
#include <iomanip>
#include <cstring>

static int failures = 0;
static void check(bool cond, const std::string& what) {
	if (cond) std::cout << "OK:   " << what << "\n";
	else { std::cout << "FAIL: " << what << "\n"; failures++; }
}

struct Reader {
	const std::vector<uint8_t>& b;
	size_t pos = 0;
	Reader(const std::vector<uint8_t>& b_) : b(b_) {}
	uint16_t u16() { uint16_t v = b[pos] | (b[pos+1] << 8); pos += 2; return v; }
	uint32_t u32() { uint32_t v = b[pos] | (b[pos+1]<<8) | (b[pos+2]<<16) | (b[pos+3]<<24); pos += 4; return v; }
	// Liest ein Argument, gibt dessen dekodierten Wert als String zurueck
	// (fuer Ganzzahlen als Dezimalzahl, fuer Strings als Text).
	std::string arg(bool* isInt = nullptr) {
		uint16_t tl = u16();
		uint16_t typeTag = tl & 0xC000;
		uint16_t len = tl & 0x3FFF;
		if (isInt) *isInt = false;
		if (tl == 0x0000) return ""; // Null-String
		if (typeTag == 0x4000) { if (isInt) *isInt = true; int32_t v = (int32_t)u32(); return std::to_string(v); }
		if (typeTag == 0x8000) { std::string s; for (int i=0;i<len;i++) s += (char)b[pos++]; return "<binary:" + std::to_string(len) + ">"; }
		if (typeTag == 0xC000) {
			std::string out;
			int i = 0;
			while (i < len) {
				uint16_t u = b[pos] | (b[pos+1]<<8); pos += 2; i++;
				uint32_t cp = u;
				if (u >= 0xD800 && u <= 0xDBFF && i < len) {
					uint16_t lo = b[pos] | (b[pos+1]<<8);
					if (lo >= 0xDC00 && lo <= 0xDFFF) { pos += 2; i++; cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00); }
				}
				if (cp <= 0x7F) out += (char)cp;
				else if (cp <= 0x7FF) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
				else if (cp <= 0xFFFF) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
				else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
			}
			return out;
		}
		// ASCII string (typeTag == 0x0000, len > 0)
		std::string s;
		for (int i = 0; i < len; i++) s += (char)b[pos++];
		return s;
	}
};

int main() {
	AasPackageInfo info;
	info.productName = "Ice2K Testprodukt äöü";
	info.packageFileName = "test.msi";
	info.productCodeGuid = "{12345678-1234-1234-1234-123456789ABC}";
	info.packageCodeGuid = "{ABCDEF01-ABCD-ABCD-ABCD-ABCDEF012345}";
	info.versionString = "1.2.3";
	info.msiUncPath = "\\\\server\\share\\apps\\test.msi";
	info.assignedPerMachine = true;
	info.langId = 1031;

	auto bytes = buildAasFile(info);
	std::cout << "Gesamtgroesse: " << bytes.size() << " Bytes\n\n";

	Reader r(bytes);

	// --- Header ---
	uint16_t rec = r.u16();
	uint8_t opcode = rec & 0xFF, argCount = (rec >> 8) & 0xFF;
	check(opcode == 2, "Header-Opcode ist 2");
	check(argCount == 9, "Header hat 9 Argumente");
	std::string sig = r.arg();
	check(sig == "1397708873", "Signature ist 1397708873 (laut Spezifikation fest)");
	r.arg(); // Version
	r.arg(); // Timestamp
	std::string langId = r.arg();
	check(langId == "1031", "LangId ist 1031 (Deutsch)");
	r.arg(); // Platform
	std::string scriptType = r.arg();
	check(scriptType == "3", "ScriptType ist 3 (laut Spezifikation fest)");
	std::string scriptMajor = r.arg();
	check(scriptMajor == "21", "ScriptMajorVersion ist 21 (laut Spezifikation fest)");
	std::string scriptMinor = r.arg();
	check(scriptMinor == "4", "ScriptMinorVersion ist 4 (laut Spezifikation fest)");
	r.arg(); // ScriptAttributes

	// --- ProductInfo ---
	rec = r.u16();
	opcode = rec & 0xFF; argCount = (rec >> 8) & 0xFF;
	check(opcode == 4, "ProductInfo-Opcode ist 4");
	check(argCount == 16, "ProductInfo hat 16 Argumente");
	std::string productKey = r.arg();
	check(productKey == info.productCodeGuid, "ProductKey stimmt mit ProductCode überein");
	std::string productName = r.arg();
	check(productName == info.productName, "ProductName (inkl. Umlaute) stimmt exakt überein: \"" + productName + "\"");
	std::string packageName = r.arg();
	check(packageName == "test.msi", "PackageName ist der reine Dateiname (\"test.msi\")");
	r.arg(); // Language
	std::string version = r.arg();
	check(version == std::to_string((1<<24)|(2<<16)|3), "Version 1.2.3 korrekt kodiert als (1<<24)|(2<<16)|3");
	std::string assignment = r.arg();
	check(assignment == "1", "Assignment ist 1 (Computer-Zuweisung)");
	r.arg(); // ObsoleteArg
	r.arg(); // ProductIcon
	r.arg(); // PackageMediaPath
	std::string packageCode = r.arg();
	check(packageCode == info.packageCodeGuid, "PackageCode stimmt überein");
	r.arg(); // null1
	r.arg(); // null2
	r.arg(); // InstanceType
	r.arg(); // LUASetting
	r.arg(); // RemoteURTInstalls
	std::string deployFlags = r.arg();
	check(deployFlags == "1", "ProductDeploymentFlags ist 1 (MSIDEPLOYFLAGS_GPDEPLOY)");

	// --- SourceListPublish ---
	rec = r.u16();
	opcode = rec & 0xFF; argCount = (rec >> 8) & 0xFF;
	check(opcode == 9, "SourceListPublish-Opcode ist 9");
	check(argCount == 9, "SourceListPublish hat 9 Argumente (5 + 3*1 Datenträger + 1)");
	r.arg(); // PatchCode
	r.arg(); // PatchPackageName
	r.arg(); // DiskPromptTemplate
	std::string packagePath = r.arg();
	check(packagePath == info.msiUncPath, "PackagePath ist der volle UNC-Pfad");
	std::string numDisks = r.arg();
	check(numDisks == "1", "NumberOfDisks ist 1");
	r.arg(); // DiskId
	r.arg(); // VolumeName
	r.arg(); // DiskPrompt
	std::string launchPath = r.arg();
	check(launchPath == "\\\\server\\share\\apps\\", "LaunchPath ist das Verzeichnis ohne Dateinamen");

	// --- ProductPublish ---
	rec = r.u16();
	opcode = rec & 0xFF; argCount = (rec >> 8) & 0xFF;
	check(opcode == 16, "ProductPublish-Opcode ist 16");
	check(argCount == 1, "ProductPublish hat 1 Argument");
	std::string packageKey = r.arg();
	check(packageKey == info.packageCodeGuid, "PackageKey stimmt überein");

	// --- End ---
	rec = r.u16();
	opcode = rec & 0xFF; argCount = (rec >> 8) & 0xFF;
	check(opcode == 3, "End-Opcode ist 3");
	check(argCount == 3, "End hat 3 Argumente");
	std::string checksum = r.arg();
	check(checksum == "0", "Checksum ist 0");
	r.arg(); // ProgressTotalHDWord
	r.arg(); // ProgressTotalLDWord

	check(r.pos == bytes.size(), "Datei ist nach dem letzten Datensatz vollständig konsumiert (keine Restbytes)");
	std::cout << "  (gelesen: " << r.pos << " von " << bytes.size() << " Bytes)\n";

	std::cout << "\n" << (failures == 0 ? "Alle Tests erfolgreich." : (std::to_string(failures) + " Test(s) fehlgeschlagen.")) << "\n";
	return failures == 0 ? 0 : 1;
}
