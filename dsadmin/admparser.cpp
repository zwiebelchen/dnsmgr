// admparser.cpp
#include "admparser.h"
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cctype>
#include <algorithm>

// ---------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------
enum TokType { TOK_WORD, TOK_STRINGREF, TOK_QSTRING, TOK_NUMBER, TOK_EOF };
struct Token { TokType type; std::string text; };

static std::vector<Token> tokenize(const std::string& s) {
	std::vector<Token> out;
	size_t i = 0, n = s.size();
	while (i < n) {
		char c = s[i];
		if (std::isspace((unsigned char)c)) { i++; continue; }
		if (c == ';') { // Kommentar bis Zeilenende
			while (i < n && s[i] != '\n') i++;
			continue;
		}
		if (c == '"') {
			i++;
			std::string val;
			while (i < n && s[i] != '"') {
				if (s[i] == '\\' && i + 1 < n && s[i + 1] == '"') { val += '"'; i += 2; }
				else { val += s[i]; i++; }
			}
			if (i < n) i++; // schliessendes Anfuehrungszeichen
			out.push_back({ TOK_QSTRING, val });
			continue;
		}
		if (c == '!' && i + 1 < n && s[i + 1] == '!') {
			i += 2;
			std::string val;
			while (i < n && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) { val += s[i]; i++; }
			out.push_back({ TOK_STRINGREF, val });
			continue;
		}
		if (std::isdigit((unsigned char)c) || (c == '-' && i + 1 < n && std::isdigit((unsigned char)s[i + 1]))) {
			std::string val;
			if (c == '-') { val += c; i++; }
			while (i < n && std::isdigit((unsigned char)s[i])) { val += s[i]; i++; }
			out.push_back({ TOK_NUMBER, val });
			continue;
		}
		{
			std::string val;
			while (i < n && !std::isspace((unsigned char)s[i]) && s[i] != '"' && s[i] != ';') { val += s[i]; i++; }
			if (!val.empty()) out.push_back({ TOK_WORD, val });
			else i++;
		}
	}
	out.push_back({ TOK_EOF, "" });
	return out;
}

static std::string trimStr(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	size_t b = s.find_last_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	return s.substr(a, b - a + 1);
}

static std::string toUpperCopy(const std::string& s) {
	std::string u = s;
	std::transform(u.begin(), u.end(), u.begin(), [](unsigned char c) { return std::toupper(c); });
	return u;
}

// ---------------------------------------------------------------------
// [strings]-Abschnitt: einfache "Key"="Wert"-Zeilen.
// ---------------------------------------------------------------------
static std::map<std::string, std::string> parseStringsSection(const std::string& s) {
	std::map<std::string, std::string> out;
	std::istringstream iss(s);
	std::string line;
	while (std::getline(iss, line)) {
		size_t semi = line.find(';');
		if (semi != std::string::npos) line = line.substr(0, semi);
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		std::string key = trimStr(line.substr(0, eq));
		if (key.empty()) continue;
		std::string val = line.substr(eq + 1);
		size_t qa = val.find('"');
		size_t qb = val.rfind('"');
		std::string valStr;
		if (qa != std::string::npos && qb != std::string::npos && qb > qa) {
			valStr = val.substr(qa + 1, qb - qa - 1);
		} else {
			valStr = trimStr(val);
		}
		out[key] = valStr;
	}
	return out;
}

// ---------------------------------------------------------------------
// Rekursiver Abstieg.
// ---------------------------------------------------------------------
class AdmParserImpl {
public:
	std::vector<Token> tokens;
	size_t pos = 0;
	std::map<std::string, std::string> strings;

	bool atEnd() const { return tokens[pos].type == TOK_EOF; }
	std::string peekWordUpper() const {
		if (tokens[pos].type != TOK_WORD) return "";
		return toUpperCopy(tokens[pos].text);
	}
	Token advance() {
		Token t = tokens[pos];
		if (pos < tokens.size() - 1) pos++;
		return t;
	}
	std::string resolve(const Token& t) const {
		if (t.type == TOK_STRINGREF) {
			auto it = strings.find(t.text);
			return it != strings.end() ? it->second : ("!!" + t.text);
		}
		return t.text;
	}
	std::string parseValueSpec(bool* isNumericOut = nullptr) {
		if (peekWordUpper() == "NUMERIC") {
			advance();
			Token t = advance();
			if (isNumericOut) *isNumericOut = true;
			return t.text;
		}
		Token t = advance();
		if (isNumericOut) *isNumericOut = false;
		return resolve(t);
	}
	long parseNumberValue() {
		Token t = advance();
		try { return std::stol(t.text); } catch (...) { return 0; }
	}
	static AdmPartType mapPartType(const std::string& w) {
		if (w == "CHECKBOX") return ADMPART_CHECKBOX;
		if (w == "EDITTEXT") return ADMPART_EDITTEXT;
		if (w == "NUMERIC") return ADMPART_NUMERIC;
		if (w == "DROPDOWNLIST") return ADMPART_DROPDOWNLIST;
		if (w == "COMBOBOX") return ADMPART_COMBOBOX;
		if (w == "TEXT") return ADMPART_TEXT;
		if (w == "LISTBOX") return ADMPART_LISTBOX;
		return ADMPART_UNKNOWN;
	}

	void parseItemList(AdmPart& part) {
		advance(); // ITEMLIST
		while (!atEnd() && peekWordUpper() != "END") {
			if (peekWordUpper() == "NAME") {
				advance();
				Token labelTok = advance();
				AdmItem item;
				item.label = resolve(labelTok);
				if (peekWordUpper() == "VALUE") {
					advance();
					item.value = parseValueSpec(&item.isNumeric);
				}
				part.items.push_back(item);
			} else {
				advance();
			}
		}
		if (!atEnd()) advance(); // END
		if (!atEnd()) advance(); // ITEMLIST
	}

	AdmPart parsePart() {
		AdmPart part;
		advance(); // PART
		Token labelTok = advance();
		part.label = resolve(labelTok);
		std::string typeWord = peekWordUpper();
		advance(); // Typwort
		part.type = mapPartType(typeWord);
		while (!atEnd() && peekWordUpper() != "END") {
			std::string w = peekWordUpper();
			if (w == "VALUENAME") { advance(); part.valuename = advance().text; }
			else if (w == "DEFAULT") { advance(); part.defaultValue = parseValueSpec(); part.hasDefault = true; }
			else if (w == "MIN") { advance(); part.minValue = parseNumberValue(); part.hasMinMax = true; }
			else if (w == "MAX") { advance(); part.maxValue = parseNumberValue(); part.hasMinMax = true; }
			else if (w == "MAXLEN") { advance(); part.maxLen = (int)parseNumberValue(); }
			else if (w == "ITEMLIST") { parseItemList(part); }
			else { advance(); }
		}
		if (!atEnd()) advance(); // END
		if (!atEnd()) advance(); // PART
		return part;
	}

	void skipUnknownBlock(const std::string& closer) {
		while (!atEnd()) {
			if (peekWordUpper() == "END") {
				advance();
				std::string next = peekWordUpper();
				if (next == closer) { advance(); return; }
			} else {
				advance();
			}
		}
	}

	AdmPolicy parsePolicy() {
		AdmPolicy pol;
		advance(); // POLICY
		Token labelTok = advance();
		pol.label = resolve(labelTok);
		while (!atEnd() && peekWordUpper() != "END") {
			std::string w = peekWordUpper();
			if (w == "EXPLAIN") { advance(); pol.explainText = resolve(advance()); }
			else if (w == "KEYNAME") { advance(); pol.keyname = advance().text; }
			else if (w == "VALUENAME") { advance(); pol.valuename = advance().text; }
			else if (w == "VALUEON") { advance(); pol.valueOn = parseValueSpec(); pol.hasValueOnOff = true; }
			else if (w == "VALUEOFF") { advance(); pol.valueOff = parseValueSpec(); pol.hasValueOnOff = true; }
			else if (w == "PART") { pol.parts.push_back(parsePart()); }
			else if (w == "SUPPORTED") { advance(); if (!atEnd()) advance(); }
			else if (w == "ACTIONLISTON" || w == "ACTIONLISTOFF") { advance(); skipUnknownBlock("ACTIONLIST"); }
			else { advance(); }
		}
		if (!atEnd()) advance(); // END
		if (!atEnd()) advance(); // POLICY
		return pol;
	}

	AdmCategory parseCategory() {
		AdmCategory cat;
		advance(); // CATEGORY
		Token labelTok = advance();
		cat.label = resolve(labelTok);
		while (!atEnd() && peekWordUpper() != "END") {
			std::string w = peekWordUpper();
			if (w == "KEYNAME") { advance(); cat.keyname = advance().text; }
			else if (w == "CATEGORY") { cat.subCategories.push_back(parseCategory()); }
			else if (w == "POLICY") { cat.policies.push_back(parsePolicy()); }
			else { advance(); }
		}
		if (!atEnd()) advance(); // END
		if (!atEnd()) advance(); // CATEGORY
		return cat;
	}

	AdmFile parse() {
		AdmFile file;
		while (!atEnd()) {
			std::string w = peekWordUpper();
			if (w == "CLASS") {
				advance();
				AdmClass cls;
				cls.classType = toUpperCopy(advance().text);
				while (!atEnd()) {
					std::string w2 = peekWordUpper();
					if (w2 == "CATEGORY") cls.topCategories.push_back(parseCategory());
					else if (w2 == "CLASS") break;
					else advance();
				}
				file.classes.push_back(cls);
			} else {
				advance();
			}
		}
		return file;
	}
};

// ---------------------------------------------------------------------
// ADM-Dateien kommen in ANSI und in UTF-16 vor -- Microsoft liefert
// beides aus. Byteweise gelesen steht in einer UTF-16-Datei hinter jedem
// Zeichen ein Nullbyte; der Tokenizer findet dann kein einziges
// CATEGORY und liefert stillschweigend einen leeren Baum. Genau so ist
// bei einem Nutzer die komplette system.adm (Desktop, Startmenue,
// Systemsteuerung, System, Netzwerk, Drucker) aus dem Editor
// verschwunden, waehrend die ANSI-kodierte inetres.adm sauber durchlief.
//
// Erkennung ueber die Bytereihenfolge-Markierung, ersatzweise ueber
// Nullbytes an gerader/ungerader Position -- nicht jede Datei hat eine
// Markierung.
// ---------------------------------------------------------------------
enum AdmEncoding { ADMENC_ANSI, ADMENC_UTF16LE, ADMENC_UTF16BE };

static AdmEncoding detectEncoding(const std::string& raw, size_t& skipBytes) {
	skipBytes = 0;
	if (raw.size() >= 2) {
		unsigned char b0 = (unsigned char)raw[0], b1 = (unsigned char)raw[1];
		if (b0 == 0xFF && b1 == 0xFE) { skipBytes = 2; return ADMENC_UTF16LE; }
		if (b0 == 0xFE && b1 == 0xFF) { skipBytes = 2; return ADMENC_UTF16BE; }
		if (b0 == 0xEF && b1 == 0xBB && raw.size() >= 3 && (unsigned char)raw[2] == 0xBF) { skipBytes = 3; return ADMENC_ANSI; }
	}
	// Ohne Markierung: in den ersten Kilobytes zaehlen, wo die Nullbytes
	// sitzen. Bei UTF-16LE ist jedes zweite Byte 0 (ungerade Position).
	size_t limit = raw.size() < 1024 ? raw.size() : 1024;
	size_t zeroOdd = 0, zeroEven = 0;
	for (size_t i = 0; i < limit; i++) {
		if (raw[i] != 0) continue;
		if (i % 2) zeroOdd++; else zeroEven++;
	}
	if (zeroOdd > limit / 4 && zeroEven == 0) return ADMENC_UTF16LE;
	if (zeroEven > limit / 4 && zeroOdd == 0) return ADMENC_UTF16BE;
	return ADMENC_ANSI;
}

static std::string utf16ToUtf8(const std::string& raw, size_t offset, bool bigEndian) {
	std::string out;
	for (size_t i = offset; i + 1 < raw.size(); i += 2) {
		unsigned char lo = (unsigned char)raw[i], hi = (unsigned char)raw[i + 1];
		uint32_t cp = bigEndian ? ((uint32_t)lo << 8 | hi) : ((uint32_t)hi << 8 | lo);

		// Ersatzzeichenpaare zusammensetzen (in ADM-Dateien praktisch nie,
		// aber wir wollen daran nicht scheitern).
		if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < raw.size()) {
			unsigned char lo2 = (unsigned char)raw[i + 2], hi2 = (unsigned char)raw[i + 3];
			uint32_t low = bigEndian ? ((uint32_t)lo2 << 8 | hi2) : ((uint32_t)hi2 << 8 | lo2);
			if (low >= 0xDC00 && low <= 0xDFFF) {
				cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
				i += 2;
			}
		}

		if (cp < 0x80) {
			out += (char)cp;
		} else if (cp < 0x800) {
			out += (char)(0xC0 | (cp >> 6));
			out += (char)(0x80 | (cp & 0x3F));
		} else if (cp < 0x10000) {
			out += (char)(0xE0 | (cp >> 12));
			out += (char)(0x80 | ((cp >> 6) & 0x3F));
			out += (char)(0x80 | (cp & 0x3F));
		} else {
			out += (char)(0xF0 | (cp >> 18));
			out += (char)(0x80 | ((cp >> 12) & 0x3F));
			out += (char)(0x80 | ((cp >> 6) & 0x3F));
			out += (char)(0x80 | (cp & 0x3F));
		}
	}
	return out;
}

// Wandelt den Rohinhalt einer ADM-Datei in UTF-8 um, egal wie er
// kodiert war. ANSI-Dateien bleiben unveraendert (eine
// Codepage-Umsetzung waere hier nur geraten; Umlaute in Beschriftungen
// kommen ohnehin aus dem [strings]-Abschnitt).
std::string admToUtf8(const std::string& raw) {
	size_t skip = 0;
	switch (detectEncoding(raw, skip)) {
		case ADMENC_UTF16LE: return utf16ToUtf8(raw, skip, false);
		case ADMENC_UTF16BE: return utf16ToUtf8(raw, skip, true);
		default: return skip ? raw.substr(skip) : raw;
	}
}

AdmFile parseAdmContent(const std::string& rawContent) {
	const std::string content = admToUtf8(rawContent);
	// [strings]-Abschnitt finden (eigene Zeile, Gross-/Kleinschreibung egal).
	size_t stringsPos = std::string::npos;
	{
		std::istringstream iss(content);
		std::string line;
		size_t offset = 0;
		while (std::getline(iss, line)) {
			if (toUpperCopy(trimStr(line)) == "[STRINGS]") {
				stringsPos = offset + line.size() + 1;
				break;
			}
			offset += line.size() + 1;
		}
	}

	std::string mainPart = (stringsPos == std::string::npos) ? content : content.substr(0, stringsPos);
	std::string stringsPart = (stringsPos == std::string::npos) ? "" : content.substr(stringsPos);

	AdmParserImpl p;
	p.tokens = tokenize(mainPart);
	p.strings = parseStringsSection(stringsPart);
	return p.parse();
}

AdmFile parseAdmFile(const std::string& path) {
	std::ifstream in(path, std::ios::binary);
	if (!in.is_open()) {
		AdmFile f;
		f.parseError = "Datei konnte nicht geoeffnet werden: " + path;
		return f;
	}
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	return parseAdmContent(content);
}
