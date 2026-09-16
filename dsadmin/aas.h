// aas.h
//
// Schreibt "Application Advertise Script"-Dateien (.aas), wie sie die
// Gruppenrichtlinien-Softwareinstallation fuer jedes bereitgestellte
// Paket in SYSVOL ablegt (Applications-Ordner des GPOs). Ein echter
// Windows-Client liest genau diese Datei, um eine Anwendung
// zuzuweisen/zu veroeffentlichen.
//
// Format nach [MS-GPSI] Abschnitt 2.2.4 (oeffentlich von Microsoft
// dokumentiert, im Gegensatz zum Geruecht, das sei unmoeglich zu
// implementieren): eine feste Folge von Opcode-Datensaetzen
// (Header/ProductInfo/SourceListPublish/ProductPublish/End), jeweils
// ein 16-Bit-Wort (Opcode im unteren, Argumentanzahl im oberen Byte)
// gefolgt von den Argumenten. Jedes Argument hat ein 16-Bit
// Typ+Laenge-Wort, dann die Daten (ASCII-String/Unicode-String/
// Binaerstrom/32-Bit-Ganzzahl).

#ifndef AAS_H
#define AAS_H

#include <string>
#include <vector>
#include <cstdint>

// Ein Eintrag der Feature-Tabelle der MSI. Ohne diese Datensaetze
// veroeffentlicht das Skript keine Features -- und der Windows
// Installer weiss dann nicht, was er installieren soll.
struct AasFeature {
	std::string name;    // Feature-Spalte der MSI ("Program", "Complete", ...)
	std::string parent;  // Feature_Parent, leer bei der Wurzel
};

struct AasPackageInfo {
	std::string productName;     // z.B. "Ice2K Testprodukt" (aus der .msi, Property ProductName)
	std::string packageFileName; // z.B. "test.msi" (nur der Dateiname, aus der .msi PackageName-Konvention)
	std::string productCodeGuid; // "{XXXXXXXX-...}" -- aus der .msi, Property ProductCode
	std::string packageCodeGuid; // "{XXXXXXXX-...}" -- Package Code (kann bei Bedarf = ProductCode)
	std::string versionString;   // "A.B.C" -- aus der .msi, Property ProductVersion
	std::string msiUncPath;      // volle UNC-Pfad-Angabe, z.B. "\\\\server\\share\\apps\\test.msi"
	bool assignedPerMachine = true; // true = Computer-Zuweisung, false = Benutzer (zugewiesen ODER veroeffentlicht)
	uint32_t langId = 1031;      // LCID, Standard Deutsch (Deutschland)
	std::string upgradeCodeGuid; // Property UpgradeCode der .msi
	std::vector<AasFeature> features; // Feature-Tabelle der .msi, in Tabellenreihenfolge
};

// Baut die rohen Bytes einer .aas-Datei fuer ein einzelnes Paket.
std::vector<uint8_t> buildAasFile(const AasPackageInfo& info);

// Schreibt die Datei (unprivilegiert -- root-Rechte stellt der
// Aufrufer selbst her, analog zu regpol.h).
bool writeAasFile(const std::string& path, const AasPackageInfo& info, std::string& errorMsg);

#endif
