// test_admparser.cpp -- reines Kommandozeilen-Testprogramm, keine GUI.
#include "admparser.h"
#include <iostream>
#include <string>

static void printIndent(int n) { for (int i = 0; i < n; i++) std::cout << "  "; }

static void printPart(const AdmPart& part, int indent) {
	printIndent(indent);
	const char* typeName = "UNKNOWN";
	switch (part.type) {
		case ADMPART_CHECKBOX: typeName = "CHECKBOX"; break;
		case ADMPART_EDITTEXT: typeName = "EDITTEXT"; break;
		case ADMPART_NUMERIC: typeName = "NUMERIC"; break;
		case ADMPART_DROPDOWNLIST: typeName = "DROPDOWNLIST"; break;
		case ADMPART_COMBOBOX: typeName = "COMBOBOX"; break;
		case ADMPART_TEXT: typeName = "TEXT"; break;
		case ADMPART_LISTBOX: typeName = "LISTBOX"; break;
		default: break;
	}
	std::cout << "PART \"" << part.label << "\" [" << typeName << "] VALUENAME=" << part.valuename;
	if (part.hasDefault) std::cout << " DEFAULT=" << part.defaultValue;
	if (part.hasMinMax) std::cout << " MIN=" << part.minValue << " MAX=" << part.maxValue;
	if (part.maxLen) std::cout << " MAXLEN=" << part.maxLen;
	std::cout << "\n";
	for (auto& item : part.items) {
		printIndent(indent + 1);
		std::cout << "ITEM \"" << item.label << "\" = " << item.value << (item.isNumeric ? " (numeric)" : "") << "\n";
	}
}

static void printPolicy(const AdmPolicy& pol, int indent) {
	printIndent(indent);
	std::cout << "POLICY \"" << pol.label << "\"\n";
	printIndent(indent + 1);
	std::cout << "EXPLAIN: " << pol.explainText << "\n";
	if (!pol.valuename.empty()) {
		printIndent(indent + 1);
		std::cout << "VALUENAME=" << pol.valuename;
		if (pol.hasValueOnOff) std::cout << " VALUEON=" << pol.valueOn << " VALUEOFF=" << pol.valueOff;
		std::cout << "\n";
	}
	for (auto& part : pol.parts) printPart(part, indent + 1);
}

static void printCategory(const AdmCategory& cat, int indent) {
	printIndent(indent);
	std::cout << "CATEGORY \"" << cat.label << "\"";
	if (!cat.keyname.empty()) std::cout << " KEYNAME=" << cat.keyname;
	std::cout << "\n";
	for (auto& sub : cat.subCategories) printCategory(sub, indent + 1);
	for (auto& pol : cat.policies) printPolicy(pol, indent + 1);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <datei.adm>\n";
		return 1;
	}
	AdmFile file = parseAdmFile(argv[1]);
	if (!file.parseError.empty()) {
		std::cerr << "Fehler: " << file.parseError << "\n";
		return 1;
	}
	for (auto& cls : file.classes) {
		std::cout << "CLASS " << cls.classType << "\n";
		for (auto& cat : cls.topCategories) printCategory(cat, 1);
	}
	return 0;
}
