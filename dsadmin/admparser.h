// admparser.h
//
// Parser fuer klassische Gruppenrichtlinien-Vorlagen (.adm-Dateien),
// wie sie Windows 2000/XP/2003 verwenden (nicht das spaetere ADMX/ADML-
// Format). Reine Datenstrukturen + Parser, keine GUI-Abhaengigkeiten --
// der GUI-Editor in dsadmin baut den Richtlinienbaum aus dem Ergebnis.
//
// Abgedeckte Grammatik (Kernumfang, wie er in system.adm/inetres.adm/
// conf.adm/wuau.adm tatsaechlich vorkommt):
//   CLASS MACHINE|USER
//   CATEGORY !!ref ... END CATEGORY   (beliebig verschachtelt)
//   POLICY !!ref ... END POLICY
//     KEYNAME "..."
//     EXPLAIN !!ref | EXPLAIN "..."
//     VALUENAME "..." / VALUEON .. / VALUEOFF ..
//     PART !!ref TYP ... END PART
//       (TYP: CHECKBOX, EDITTEXT, NUMERIC, DROPDOWNLIST, COMBOBOX, TEXT, LISTBOX)
//       VALUENAME, DEFAULT, MIN, MAX, MAXLEN, REQUIRED, SPIN
//       ITEMLIST ... END ITEMLIST  (fuer DROPDOWNLIST/COMBOBOX)
//         NAME !!ref VALUE NUMERIC|"..." n
//   [strings] Abschnitt: key=Wert  (fuer !!ref-Aufloesung)
//
// Bewusst NICHT unterstuetzt (kommt in den Kern-Dateien praktisch nicht
// vor, wuerde den Parser unnoetig aufblaehen): #if version-Bedingungen,
// ACTIONLIST/ACTIONLISTOFF, SUPPORTED-Versionsbedingungen im Detail
// (der Text wird nur roh mitgefuehrt, nicht ausgewertet).

#ifndef ADMPARSER_H
#define ADMPARSER_H

#include <string>
#include <vector>
#include <map>
#include <memory>

enum AdmPartType {
	ADMPART_CHECKBOX,
	ADMPART_EDITTEXT,
	ADMPART_NUMERIC,
	ADMPART_DROPDOWNLIST,
	ADMPART_COMBOBOX,
	ADMPART_TEXT,
	ADMPART_LISTBOX,
	ADMPART_UNKNOWN
};

struct AdmItem {
	std::string label;      // aufgeloester Anzeigename (aus !!ref oder woertlich)
	std::string value;      // Wert als String (auch fuer NUMERIC -- Anzeige/Registry als Text)
	bool isNumeric = false;
};

struct AdmPart {
	std::string label;
	AdmPartType type = ADMPART_UNKNOWN;
	std::string valuename;      // Registry-Wertname (falls abweichend von der Policy-eigenen VALUENAME)
	std::string defaultValue;
	bool hasDefault = false;
	long minValue = 0, maxValue = 0;
	bool hasMinMax = false;
	int maxLen = 0;
	std::vector<AdmItem> items; // fuer DROPDOWNLIST/COMBOBOX
};

struct AdmPolicy {
	std::string label;          // aufgeloester Anzeigename
	std::string explainText;    // aufgeloester Erklaerungstext
	std::string keyname;        // eigener Schluessel (falls von der Kategorie abweichend), sonst leer
	std::string valuename;      // fuer einfache An/Aus-Richtlinien ohne PART
	std::string valueOn, valueOff;
	bool hasValueOnOff = false;
	std::vector<AdmPart> parts;
};

struct AdmCategory {
	std::string label;
	std::string keyname;
	std::vector<AdmCategory> subCategories;
	std::vector<AdmPolicy> policies;
};

struct AdmClass {
	std::string classType; // "MACHINE" oder "USER"
	std::vector<AdmCategory> topCategories;
};

struct AdmFile {
	std::vector<AdmClass> classes;
	std::string parseError; // leer, wenn erfolgreich geparst
};

// Parst eine .adm-Datei (bereits eingelesener Inhalt als String, damit
// der Aufrufer frei waehlen kann, ob root-Leserechte noetig sind).
AdmFile parseAdmContent(const std::string& content);

// Bequemlichkeitsfunktion: liest die Datei direkt (fuer unprivilegiert
// lesbare Pfade, z.B. unser eigenes ADM_DIR).
AdmFile parseAdmFile(const std::string& path);

#endif
