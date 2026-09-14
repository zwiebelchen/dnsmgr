// regpol.cpp
#include "regpol.h"
#include <fstream>
#include <cstring>

// ---------------------------------------------------------------------
// UTF-8 <-> UTF-16LE -- einfache, aber korrekte Umsetzung inklusive
// Ersatzpaaren (surrogate pairs) fuer Codepunkte ausserhalb der Basic
// Multilingual Plane (in der Praxis fuer Registry-Schluessel-/Wertnamen
// und deutsche Umlaute in Textwerten nicht gebraucht, aber schadet
// nicht, es sauber zu machen).
// ---------------------------------------------------------------------
static std::vector<uint8_t> utf8ToUtf16LE(const std::string& s, bool nullTerminate) {
	std::vector<uint8_t> out;
	size_t i = 0, n = s.size();
	auto pushU16 = [&](uint16_t v) {
		out.push_back((uint8_t)(v & 0xFF));
		out.push_back((uint8_t)((v >> 8) & 0xFF));
	};
	while (i < n) {
		unsigned char c = s[i];
		uint32_t cp = 0;
		int len = 1;
		if ((c & 0x80) == 0) { cp = c; len = 1; }
		else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
		else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
		else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
		else { i++; continue; } // ungueltiges Startbyte ueberspringen
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
			pushU16((uint16_t)cp);
		} else {
			cp -= 0x10000;
			uint16_t hi = (uint16_t)(0xD800 + (cp >> 10));
			uint16_t lo = (uint16_t)(0xDC00 + (cp & 0x3FF));
			pushU16(hi);
			pushU16(lo);
		}
	}
	if (nullTerminate) pushU16(0);
	return out;
}

static std::string utf16LEToUtf8(const uint8_t* data, size_t byteLen) {
	std::string out;
	size_t i = 0;
	while (i + 1 < byteLen + 1 && i + 2 <= byteLen) {
		uint16_t u = (uint16_t)data[i] | ((uint16_t)data[i + 1] << 8);
		i += 2;
		uint32_t cp = u;
		if (u >= 0xD800 && u <= 0xDBFF && i + 2 <= byteLen) {
			uint16_t lo = (uint16_t)data[i] | ((uint16_t)data[i + 1] << 8);
			if (lo >= 0xDC00 && lo <= 0xDFFF) {
				cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
				i += 2;
			}
		}
		if (cp == 0) break; // Nullterminierung
		if (cp <= 0x7F) {
			out += (char)cp;
		} else if (cp <= 0x7FF) {
			out += (char)(0xC0 | (cp >> 6));
			out += (char)(0x80 | (cp & 0x3F));
		} else if (cp <= 0xFFFF) {
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

static void appendU32(std::vector<uint8_t>& out, uint32_t v) {
	out.push_back((uint8_t)(v & 0xFF));
	out.push_back((uint8_t)((v >> 8) & 0xFF));
	out.push_back((uint8_t)((v >> 16) & 0xFF));
	out.push_back((uint8_t)((v >> 24) & 0xFF));
}

static uint32_t readU32(const uint8_t* p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// ---------------------------------------------------------------------
// Hilfsfunktionen zum Erzeugen typischer Eintraege.
// ---------------------------------------------------------------------
RegPolEntry makeRegSzEntry(const std::string& key, const std::string& valuename, const std::string& text) {
	RegPolEntry e;
	e.key = key;
	e.valuename = valuename;
	e.type = REG_TYPE_SZ;
	e.data = utf8ToUtf16LE(text, true);
	return e;
}

RegPolEntry makeRegDwordEntry(const std::string& key, const std::string& valuename, uint32_t value) {
	RegPolEntry e;
	e.key = key;
	e.valuename = valuename;
	e.type = REG_TYPE_DWORD;
	appendU32(e.data, value);
	return e;
}

RegPolEntry makeRegMultiSzEntry(const std::string& key, const std::string& valuename, const std::vector<std::string>& lines) {
	RegPolEntry e;
	e.key = key;
	e.valuename = valuename;
	e.type = REG_TYPE_MULTI_SZ;
	for (auto& line : lines) {
		auto enc = utf8ToUtf16LE(line, true);
		e.data.insert(e.data.end(), enc.begin(), enc.end());
	}
	e.data.push_back(0); e.data.push_back(0); // abschliessender Leerstring
	return e;
}

RegPolEntry makeDeleteValueEntry(const std::string& key, const std::string& valuename) {
	RegPolEntry e;
	e.key = key;
	e.valuename = "**del." + valuename;
	e.type = REG_TYPE_SZ;
	e.data = utf8ToUtf16LE("", true); // leerer String, nur Nullterminierung
	return e;
}

RegPolEntry makeKeyOnlyEntry(const std::string& key) {
	RegPolEntry e;
	e.key = key;
	e.valuename = "";
	e.type = REG_TYPE_SZ;
	e.data = utf8ToUtf16LE("", true);
	return e;
}

// ---------------------------------------------------------------------
// Serialisierung.
// ---------------------------------------------------------------------
static void appendWChar(std::vector<uint8_t>& out, char c) {
	out.push_back((uint8_t)c);
	out.push_back(0);
}

std::vector<uint8_t> buildRegPolFile(const std::vector<RegPolEntry>& entries) {
	std::vector<uint8_t> out;
	// Kopf: Signatur "PReg" als Rohbytes, dann Version = 1.
	out.push_back('P'); out.push_back('R'); out.push_back('e'); out.push_back('g');
	appendU32(out, 1);

	for (auto& e : entries) {
		appendWChar(out, '[');
		auto keyEnc = utf8ToUtf16LE(e.key, true);
		out.insert(out.end(), keyEnc.begin(), keyEnc.end());
		appendWChar(out, ';');
		auto valEnc = utf8ToUtf16LE(e.valuename, true);
		out.insert(out.end(), valEnc.begin(), valEnc.end());
		appendWChar(out, ';');
		appendU32(out, e.type);
		appendWChar(out, ';');
		appendU32(out, (uint32_t)e.data.size());
		appendWChar(out, ';');
		out.insert(out.end(), e.data.begin(), e.data.end());
		appendWChar(out, ']');
	}
	return out;
}

bool writeRegPolFile(const std::string& path, const std::vector<RegPolEntry>& entries, std::string& errorMsg) {
	auto bytes = buildRegPolFile(entries);
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	if (!out.is_open()) { errorMsg = "Konnte Datei nicht zum Schreiben oeffnen: " + path; return false; }
	out.write((const char*)bytes.data(), (std::streamsize)bytes.size());
	if (!out.good()) { errorMsg = "Schreibfehler bei " + path; return false; }
	return true;
}

// ---------------------------------------------------------------------
// Deserialisierung (fuer Rundlauf-Tests und spaeteres Einlesen
// bestehender GPOs).
// ---------------------------------------------------------------------
RegPolFile parseRegPolBytes(const std::vector<uint8_t>& bytes) {
	RegPolFile result;
	if (bytes.size() < 8) { result.parseError = "Datei zu kurz fuer den Kopf."; return result; }
	if (!(bytes[0] == 'P' && bytes[1] == 'R' && bytes[2] == 'e' && bytes[3] == 'g')) {
		result.parseError = "Ungueltige Signatur (kein 'PReg'-Kopf).";
		return result;
	}
	uint32_t version = readU32(&bytes[4]);
	if (version != 1) { result.parseError = "Unbekannte Versionsnummer: " + std::to_string(version); return result; }

	size_t pos = 8;
	auto readWChar = [&]() -> int {
		if (pos + 2 > bytes.size()) return -1;
		int c = bytes[pos];
		pos += 2;
		return c;
	};
	auto readWString = [&]() -> std::string {
		size_t start = pos;
		while (pos + 2 <= bytes.size()) {
			uint16_t u = (uint16_t)bytes[pos] | ((uint16_t)bytes[pos + 1] << 8);
			pos += 2;
			if (u == 0) break;
		}
		return utf16LEToUtf8(&bytes[start], pos - start);
	};

	while (pos < bytes.size()) {
		// Ueberspringe evtl. Fuellbytes/Whitespace zwischen Eintraegen (sollte
		// bei korrekt erzeugten Dateien nicht vorkommen, aber schadet nicht).
		if (readWChar() != '[') { result.parseError = "Erwartetes '[' nicht gefunden bei Offset " + std::to_string(pos); return result; }
		RegPolEntry e;
		e.key = readWString();
		if (readWChar() != ';') { result.parseError = "Erwartetes ';' nach Schluesselname fehlt."; return result; }
		e.valuename = readWString();
		if (readWChar() != ';') { result.parseError = "Erwartetes ';' nach Wertname fehlt."; return result; }
		if (pos + 4 > bytes.size()) { result.parseError = "Datei endet unerwartet (Typ)."; return result; }
		e.type = readU32(&bytes[pos]); pos += 4;
		if (readWChar() != ';') { result.parseError = "Erwartetes ';' nach Typ fehlt."; return result; }
		if (pos + 4 > bytes.size()) { result.parseError = "Datei endet unerwartet (Groesse)."; return result; }
		uint32_t size = readU32(&bytes[pos]); pos += 4;
		if (readWChar() != ';') { result.parseError = "Erwartetes ';' nach Groesse fehlt."; return result; }
		if (pos + size > bytes.size()) { result.parseError = "Datenblock ueberschreitet Dateiende."; return result; }
		e.data.assign(bytes.begin() + pos, bytes.begin() + pos + size);
		pos += size;
		if (readWChar() != ']') { result.parseError = "Erwartetes ']' am Ende des Eintrags fehlt."; return result; }
		result.entries.push_back(e);
	}
	return result;
}

RegPolFile parseRegPolFile(const std::string& path) {
	std::ifstream in(path, std::ios::binary);
	if (!in.is_open()) {
		RegPolFile r;
		r.parseError = "Datei konnte nicht geoeffnet werden: " + path;
		return r;
	}
	std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	return parseRegPolBytes(bytes);
}
