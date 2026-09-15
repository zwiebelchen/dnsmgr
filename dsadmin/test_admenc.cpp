// test_admenc.cpp -- prueft die Kodierungserkennung des ADM-Parsers.
//
// Hintergrund: ADM-Dateien liefert Microsoft sowohl in ANSI als auch in
// UTF-16 aus. Byteweise gelesen steht in einer UTF-16-Datei hinter jedem
// Zeichen ein Nullbyte, der Tokenizer findet kein einziges CATEGORY und
// der Editor zeigt stillschweigend einen leeren Baum -- so ist einem
// Nutzer die komplette system.adm abhanden gekommen.
//
//   make test_admenc && ./test_admenc

#include "admparser.h"
#include <cassert>
#include <cstdio>
#include <string>

static std::string toUtf16le(const std::string& ascii, bool withBom) {
	std::string out;
	if (withBom) { out += (char)0xFF; out += (char)0xFE; }
	for (char c : ascii) { out += c; out += (char)0x00; }
	return out;
}

static std::string toUtf16be(const std::string& ascii, bool withBom) {
	std::string out;
	if (withBom) { out += (char)0xFE; out += (char)0xFF; }
	for (char c : ascii) { out += (char)0x00; out += c; }
	return out;
}

static const std::string ADM =
	"CLASS MACHINE\n"
	"CATEGORY !!Desktop\n"
	"  KEYNAME \"Software\\\\Test\"\n"
	"  POLICY !!NoNetHood\n"
	"    VALUENAME \"NoNetHood\"\n"
	"  END POLICY\n"
	"END CATEGORY\n"
	"[strings]\n"
	"Desktop=\"Desktop\"\n"
	"NoNetHood=\"Symbol Netzwerkumgebung ausblenden\"\n";

static void testConversion() {
	// ANSI bleibt unangetastet
	assert(admToUtf8(ADM) == ADM);

	// UTF-16 in allen vier Spielarten
	assert(admToUtf8(toUtf16le(ADM, true)) == ADM);
	assert(admToUtf8(toUtf16le(ADM, false)) == ADM);  // ohne Markierung
	assert(admToUtf8(toUtf16be(ADM, true)) == ADM);
	assert(admToUtf8(toUtf16be(ADM, false)) == ADM);

	// UTF-8-Markierung wird abgeschnitten
	assert(admToUtf8("\xEF\xBB\xBF" + ADM) == ADM);

	// Leere und winzige Eingaben duerfen nicht abstuerzen
	assert(admToUtf8("").empty());
	assert(admToUtf8("A") == "A");

	// Umlaute ueberleben den Weg durch UTF-16
	const std::string uml = "CATEGORY \"Gr\xC3\xB6\xC3\x9F\x65\"\n";
	std::string wide;
	wide += (char)0xFF; wide += (char)0xFE;
	const unsigned short units[] = { 'C','A','T','E','G','O','R','Y',' ','"','G','r',0x00F6,0x00DF,'e','"','\n' };
	for (unsigned short u : units) { wide += (char)(u & 0xFF); wide += (char)(u >> 8); }
	assert(admToUtf8(wide) == uml);
}

static void testParsingIsIdentical() {
	AdmFile ansi = parseAdmContent(ADM);
	AdmFile wide = parseAdmContent(toUtf16le(ADM, true));

	// Vor der Korrektur lieferte die UTF-16-Fassung hier schlicht nichts.
	assert(ansi.classes.size() == 1);
	assert(wide.classes.size() == 1);
	assert(!wide.classes[0].topCategories.empty());
	assert(ansi.classes[0].topCategories.size() == wide.classes[0].topCategories.size());

	const AdmCategory& cat = wide.classes[0].topCategories[0];
	assert(cat.label == "Desktop");                      // aus [strings] aufgeloest
	assert(cat.policies.size() == 1);
	assert(cat.policies[0].label == "Symbol Netzwerkumgebung ausblenden");
}

int main() {
	testConversion();
	testParsingIsIdentical();
	printf("admparser-Kodierung: alle Tests bestanden\n");
	return 0;
}
