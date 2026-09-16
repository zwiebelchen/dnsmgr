// dsadmin.cpp
//
// "Active Directory-Benutzer und -Computer" fuer ice2k -- Nachbau des
// echten dsa.msc-Snapins. Backend: Samba-AD-Domaene via samba-tool
// (user/group/ou/computer/gpo).
//
// Ergaenzt compmgmt (das nach der AD-Installation nur noch fuer
// eigenstaendige Server zustaendig ist) um die Verwaltung von
// Domaenenkonten. Enthaelt ausserdem den "Gruppenrichtlinie"-Reiter
// (GPOs anlegen/verknuepfen -- der eigentliche Editor der
// Administrativen Vorlagen ist ein eigener, spaeterer Baustein).

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "admparser.h"
#include "regpol.h"
#include "aas.h"
#include "../common/svc/svcpanel.h"
#include <algorithm>
#include <map>
#include <tuple>

// ---------------------------------------------------------------------
// Richtlinienzustand aus einem bestehenden Registry.pol ableiten --
// hier schon vor den Dialog-Klassen definiert, da PolicyEditDialog
// (weiter unten) den Typ PolicyState in seiner Konstruktor-Signatur
// braucht.
// ---------------------------------------------------------------------
enum PolicyState { POLSTATE_NOT_CONFIGURED, POLSTATE_ENABLED, POLSTATE_DISABLED };

struct RegLookup {
	// Schluessel: (Registrierungsschluessel in Kleinbuchstaben, Wertname in
	// Kleinbuchstaben) -- fuer verlaessliche Gross-/Kleinschreibungs-
	// unabhaengige Suche, genau wie die echte Registrierung es handhabt.
	std::map<std::pair<std::string, std::string>, RegPolEntry> values;
};

static std::string lowerCopy(const std::string& s) {
	std::string r = s;
	std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return std::tolower(c); });
	return r;
}

// Sortierung wie im deutschen Windows: Umlaute zaehlen als Grundbuchstabe
// (Ä wie A, ß wie ss), Gross-/Kleinschreibung egal -- unabhaengig davon,
// welche Sprache der Prozess eingestellt hat.
static std::string germanSortKey(const std::string& s) {
	std::string out;
	for (size_t i = 0; i < s.size(); i++) {
		unsigned char c = s[i];
		if (c == 0xC3 && i + 1 < s.size()) {
			unsigned char d = s[i + 1];
			const char* rep = nullptr;
			switch (d) {
				case 0x84: case 0xA4: rep = "a"; break;   // Ä ä
				case 0x96: case 0xB6: rep = "o"; break;   // Ö ö
				case 0x9C: case 0xBC: rep = "u"; break;   // Ü ü
				case 0x9F: rep = "ss"; break;             // ß
			}
			if (rep) { out += rep; i++; continue; }
		}
		out += (char)std::tolower(c);
	}
	return out;
}

static bool germanLess(const std::string& a, const std::string& b) {
	std::string ka = germanSortKey(a), kb = germanSortKey(b);
	if (ka != kb) return ka < kb;
	return a < b; // nur bei Gleichstand ("Mull" / "Müll") entscheidet der Umlaut
}

static RegLookup buildRegLookup(const RegPolFile& file) {
	RegLookup lk;
	for (auto& e : file.entries) {
		lk.values[{ lowerCopy(e.key), lowerCopy(e.valuename) }] = e;
	}
	return lk;
}

// Ermittelt den fuer eine Richtlinie tatsaechlich zustaendigen
// Registrierungsschluessel: eigener KEYNAME, sonst der naechste in der
// Kategorie-Kette definierte.
static std::string resolveEffectiveKey(const AdmPolicy& pol, const std::vector<const AdmCategory*>& categoryChain) {
	if (!pol.keyname.empty()) return pol.keyname;
	for (auto it = categoryChain.rbegin(); it != categoryChain.rend(); ++it) {
		if (!(*it)->keyname.empty()) return (*it)->keyname;
	}
	return "";
}

static PolicyState determinePolicyState(const AdmPolicy& pol, const std::string& effectiveKey, const RegLookup& lk) {
	if (pol.hasValueOnOff) {
		auto it = lk.values.find({ lowerCopy(effectiveKey), lowerCopy(pol.valuename) });
		if (it == lk.values.end()) return POLSTATE_NOT_CONFIGURED;
		// Wert vorhanden -- vergleiche den Dateninhalt mit VALUEON/VALUEOFF.
		if (it->second.type == REG_TYPE_DWORD && it->second.data.size() >= 4) {
			uint32_t v = (uint32_t)it->second.data[0] | ((uint32_t)it->second.data[1] << 8)
			           | ((uint32_t)it->second.data[2] << 16) | ((uint32_t)it->second.data[3] << 24);
			if (std::to_string(v) == pol.valueOn) return POLSTATE_ENABLED;
			if (std::to_string(v) == pol.valueOff) return POLSTATE_DISABLED;
		}
		return POLSTATE_ENABLED; // Wert vorhanden, aber nicht eindeutig zuordenbar -- als aktiviert werten
	}
	if (!pol.parts.empty()) {
		for (auto& part : pol.parts) {
			std::string vn = !part.valuename.empty() ? part.valuename : pol.valuename;
			if (lk.values.count({ lowerCopy(effectiveKey), lowerCopy(vn) })) return POLSTATE_ENABLED;
		}
		return POLSTATE_NOT_CONFIGURED;
	}
	return POLSTATE_NOT_CONFIGURED;
}

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <fstream>
#include <ctime>
#include <sstream>
#include <algorithm>

FXApp* app;
static bool g_haveRoot = false;

// ---------------------------------------------------------------------
// Root-Rechte ueber i2ksudo -- identisches Muster wie in den anderen
// ice2k-Tools.
// ---------------------------------------------------------------------
static int runAsRoot(const std::vector<FXString>& args) {
	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	for (auto& a : args) argv.push_back((char*)a.text());
	argv.push_back(NULL);

	pid_t pid = fork();
	if (pid == 0) {
		execvp("i2ksudo", argv.data());
		_exit(127);
	} else if (pid > 0) {
		int status = 0;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) return WEXITSTATUS(status);
		return -1;
	}
	return -1;
}

static int runAsRootCaptured(const std::vector<FXString>& args, std::string& output) {
	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	for (auto& a : args) argv.push_back((char*)a.text());
	argv.push_back(NULL);

	int pipefd[2];
	if (pipe(pipefd) != 0) return -1;

	pid_t pid = fork();
	if (pid == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execvp("i2ksudo", argv.data());
		_exit(127);
	} else if (pid > 0) {
		close(pipefd[1]);
		char buf[4096];
		ssize_t n;
		while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) output.append(buf, n);
		close(pipefd[0]);
		int status = 0;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) return WEXITSTATUS(status);
		return -1;
	}
	return -1;
}

// Fuehrt ein Kommando als root aus, schickt "input" auf dessen
// Standardeingabe (z.B. ein Kennwort zweimal fuer "samba-tool user
// setpassword", das interaktiv abgefragt wird, statt es unsicher als
// Kommandozeilenargument zu uebergeben) UND liefert die Ausgabe
// zurueck, um Erfolg/Fehler zu erkennen.
static int runAsRootCapturedWithStdin(const std::vector<FXString>& args, const std::string& input, std::string& output) {
	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	for (auto& a : args) argv.push_back((char*)a.text());
	argv.push_back(NULL);

	int inPipe[2], outPipe[2];
	if (pipe(inPipe) != 0) return -1;
	if (pipe(outPipe) != 0) return -1;

	pid_t pid = fork();
	if (pid == 0) {
		dup2(inPipe[0], STDIN_FILENO);
		dup2(outPipe[1], STDOUT_FILENO);
		dup2(outPipe[1], STDERR_FILENO);
		close(inPipe[0]); close(inPipe[1]);
		close(outPipe[0]); close(outPipe[1]);
		execvp("i2ksudo", argv.data());
		_exit(127);
	} else if (pid > 0) {
		close(inPipe[0]);
		close(outPipe[1]);
		ssize_t written = write(inPipe[1], input.data(), input.size());
		(void)written;
		close(inPipe[1]);
		char buf[4096];
		ssize_t n;
		while ((n = read(outPipe[0], buf, sizeof(buf))) > 0) output.append(buf, n);
		close(outPipe[0]);
		int status = 0;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) return WEXITSTATUS(status);
		return -1;
	}
	return -1;
}

static std::vector<std::string> splitLines(const std::string& s) {
	std::vector<std::string> out;
	std::istringstream iss(s);
	std::string line;
	while (std::getline(iss, line)) {
		if (!line.empty() && line.back() == '\r') line.pop_back();
		out.push_back(line);
	}
	return out;
}

static std::string trimStr(const std::string& s) {
	size_t a = s.find_first_not_of(" \t");
	size_t b = s.find_last_not_of(" \t");
	if (a == std::string::npos) return "";
	return s.substr(a, b - a + 1);
}

// ---------------------------------------------------------------------
// Domaenenstatus -- liest realm/Basis-DN aus smb.conf (unprivilegiert,
// die Datei ist nach der Provisionierung 644, wie schon bei dcpromo).
// ---------------------------------------------------------------------
static std::string readFileUnprivileged(const char* path) {
	std::ifstream in(path);
	if (!in.is_open()) return "";
	return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static FXString smbConfValue(const std::string& conf, const char* key) {
	for (auto& line : splitLines(conf)) {
		size_t p = line.find('=');
		if (p == std::string::npos) continue;
		std::string k = trimStr(line.substr(0, p));
		if (k != key) continue;
		return FXString(trimStr(line.substr(p + 1)).c_str());
	}
	return "";
}

struct DomainInfo {
	bool isDC = false;
	FXString realm;      // z.B. ZWIEBELCHEN.ORG
	FXString baseDN;     // z.B. DC=zwiebelchen,DC=org
};

static DomainInfo detectDomain() {
	DomainInfo di;
	std::string conf = readFileUnprivileged("/etc/samba/smb.conf");
	if (conf.empty()) return di;
	FXString role = smbConfValue(conf, "server role");
	if (role.find("domain controller") < 0) return di;
	di.isDC = true;
	di.realm = smbConfValue(conf, "realm");
	FXString lower = di.realm;
	lower.lower();
	FXString dn;
	int start = 0;
	for (;;) {
		int dot = lower.find('.', start);
		FXString part = (dot >= 0) ? lower.mid(start, dot - start) : lower.mid(start, lower.length() - start);
		if (part.empty()) break;
		if (!dn.empty()) dn += ",";
		dn += "DC=" + part;
		if (dot < 0) break;
		start = dot + 1;
	}
	di.baseDN = dn;
	return di;
}

// ---------------------------------------------------------------------
// Container/OU-Baum und Objektlisten -- ueber samba-tool, mit den
// bekannten Einschraenkungen einer Kommandozeilen-Bruecke (etwas
// langsamer als direktes LDAP, aber konsistent mit allen anderen
// ice2k-Tools und ohne zusaetzliche Bibliotheksabhaengigkeit).
// ---------------------------------------------------------------------
enum ObjType { OBJ_OU, OBJ_USER, OBJ_GROUP, OBJ_COMPUTER, OBJ_CONTAINER, OBJ_OTHER };

struct DirObject {
	FXString name;        // Anzeigename (CN), z.B. "Max Mustermann"
	FXString accountName; // sAMAccountName -- fuer Loeschen/Umbenennen etc. (bei
	                       // Benutzern/Gruppen/Computern; sonst leer)
	FXString dn;          // volle relative DN (ohne Basis-DN), z.B. "CN=Max Mustermann,CN=Users"
	ObjType type;
	FXString description;
	long groupType = 0;   // AD-Attribut groupType (nur bei Gruppen), 0 = unbekannt
	bool advancedOnly = false; // showInAdvancedViewOnly -- nur unter "Ansicht -> Erweiterte Funktionen" sichtbar
	FXString objectClass;      // speziellste Objektklasse (letzter objectClass-Wert)
};

// "Ansicht -> Erweiterte Funktionen" -- blendet Objekte mit
// showInAdvancedViewOnly=TRUE ein (System, LostAndFound, Program Data ...).
static bool g_advancedView = false;

static std::vector<FXString> listNames(const std::vector<FXString>& args) {
	std::string out;
	runAsRootCaptured(args, out);
	std::vector<FXString> names;
	for (auto& l : splitLines(out)) {
		FXString n = trimStr(l).c_str();
		if (!n.empty()) names.push_back(n);
	}
	return names;
}

// Listet alle direkten Kind-Container/OUs ab einer gegebenen relativen
// DN (leer = Domaenenwurzel). Nur die klassifizierbaren Standard-
// Container werden im Baum gezeigt (Users/Computers/Builtin/Domain
// Controllers) plus alle echten OUs -- weitere technische Container
// (Program Data, System, ...) blenden wir bewusst aus, wie im
// Original auch nur nach Aktivieren der erweiterten Ansicht sichtbar.
static const std::set<std::string> VISIBLE_TOP_CONTAINERS = {
	"CN=Users", "CN=Computers", "CN=Builtin", "OU=Domain Controllers"
};

static std::vector<FXString> listTopContainers() {
	std::vector<FXString> out;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("listobjects"), FXString("") }, raw);
	for (auto& l : splitLines(raw)) {
		FXString n = trimStr(l).c_str();
		if (n.empty()) continue;
		if (VISIBLE_TOP_CONTAINERS.count(n.text()) || n.left(3) == "OU=") out.push_back(n);
	}
	std::sort(out.begin(), out.end());
	return out;
}

// ---------------------------------------------------------------------
// Kleine DN-Helfer fuer den Baum. Sie arbeiten auf relativen DNs
// ("OU=Kind,OU=Eltern") und zerlegen nur an Kommas -- ein in einem RDN
// maskiertes Komma ("OU=Meier\, Hans") kommt bei
// Organisationseinheiten praktisch nicht vor.
// ---------------------------------------------------------------------
static int dnComponentCount(const FXString& dn) {
	int n = 1;
	for (FXint i = 0; i < dn.length(); i++) if (dn[i] == ',') n++;
	return n;
}

static FXString dnParent(const FXString& dn) {
	FXint p = dn.find(',');
	if (p < 0) return "";
	return dn.mid(p + 1, dn.length() - p - 1);
}

static FXString dnLeafLabel(const FXString& dn) {
	FXint p = dn.find(',');
	FXString first = (p < 0) ? dn : dn.left(p);
	if (first.left(3) == "CN=" || first.left(3) == "OU=") first = first.mid(3, first.length() - 3);
	return first;
}

// Alle Organisationseinheiten der Domaene als relative DNs -- ein
// einziger samba-tool-Aufruf fuer den ganzen Baum, statt pro Ebene
// erneut "ou listobjects" aufzurufen. Je nach samba-Version enthaelt
// die Ausgabe die Domaenenwurzel oder nicht, deshalb schneiden wir eine
// eventuell vorhandene Basis-DN selbst ab.
static std::vector<FXString> listAllOURelDNs(const DomainInfo& domain) {
	std::vector<FXString> out;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("list") }, raw);
	FXString suffix = FXString(",") + domain.baseDN;
	FXString suffixLower = suffix; suffixLower.lower();
	for (auto& l : splitLines(raw)) {
		FXString dn = trimStr(l).c_str();
		if (dn.empty()) continue;
		FXString dnLower = dn; dnLower.lower();
		if (dn.length() > suffix.length() && dnLower.right(suffixLower.length()) == suffixLower)
			dn = dn.left(dn.length() - suffix.length());
		if (dn.left(3) != "OU=") continue;
		out.push_back(dn);
	}
	return out;
}

// Objekte innerhalb eines Containers (relative DN, z.B. "CN=Users"),
// mit Typklassifizierung per Abgleich gegen die jeweiligen
// samba-tool-*-list-Ausgaben.
// Baut eine Abbildung von relativer DN -> sAMAccountName fuer einen
// Objekttyp, ueber Positions-Abgleich zwischen einem normalen
// samba-tool-*-list-Aufruf und demselben Aufruf mit --full-dn (beide
// liefern die Objekte in derselben Reihenfolge). Robuster als ein
// Namensabgleich, da der CN einer Person haeufig ihr voller Name ist
// (z.B. "Max Mustermann"), nicht der Anmeldename (z.B. "mmustermann").
static std::map<std::string, FXString> buildDnToSamMap(const char* subcmd, const FXString& baseDN) {
	std::map<std::string, FXString> out;
	std::vector<FXString> plain = listNames({ FXString("samba-tool"), FXString(subcmd), FXString("list") });
	std::vector<FXString> dns = listNames({ FXString("samba-tool"), FXString(subcmd), FXString("list"), FXString("--full-dn") });
	size_t n = std::min(plain.size(), dns.size());
	FXString suffix = "," + baseDN;
	for (size_t i = 0; i < n; i++) {
		FXString rel = dns[i];
		if (rel.right(suffix.length()) == suffix) rel = rel.left(rel.length() - suffix.length());
		out[rel.text()] = plain[i];
	}
	return out;
}

static std::vector<DirObject> listContainerObjects(const FXString& containerRelDN, const DomainInfo& domain) {
	std::vector<DirObject> out;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("listobjects"), containerRelDN }, raw);

	auto userMap = buildDnToSamMap("user", domain.baseDN);
	auto groupMap = buildDnToSamMap("group", domain.baseDN);
	auto computerMap = buildDnToSamMap("computer", domain.baseDN);

	for (auto& l : splitLines(raw)) {
		FXString full = trimStr(l).c_str();
		if (full.empty()) continue;
		// Nur direkte Kinder dieses Containers (kein "," nach dem ersten Segment
		// ausser dem Container selbst) -- listobjects liefert leider auch
		// tiefer verschachtelte Objekte, die wir hier ausfiltern.
		int firstComma = full.find(',');
		FXString rest = (firstComma >= 0) ? full.mid(firstComma + 1, full.length() - firstComma - 1) : FXString("");
		if (rest != containerRelDN) continue;

		FXString cnPart = (firstComma >= 0) ? full.left(firstComma) : full;
		FXString name = cnPart;
		if (name.left(3) == "CN=") name = name.mid(3, name.length() - 3);
		else if (name.left(3) == "OU=") name = name.mid(3, name.length() - 3);

		DirObject obj;
		obj.name = name;
		obj.dn = full;
		obj.type = OBJ_OTHER;
		// Bekannte technische Container zuerst abfangen -- sonst kann z.B.
		// der Container "CN=Users" faelschlich mit der GLEICHNAMIGEN
		// eingebauten Gruppe "Users" (in Builtin) verwechselt werden.
		static const std::set<std::string> KNOWN_CONTAINERS = {
			"Users", "Computers", "Builtin", "System", "Program Data",
			"ForeignSecurityPrincipals", "Infrastructure", "Keys",
			"LostAndFound", "Managed Service Accounts", "NTDS Quotas",
			"TPM Devices"
		};
		if (cnPart.left(3) == "OU=") obj.type = OBJ_OU;
		else if (KNOWN_CONTAINERS.count(name.text())) obj.type = OBJ_CONTAINER;
		else if (computerMap.count(full.text())) { obj.type = OBJ_COMPUTER; obj.accountName = computerMap[full.text()]; }
		else if (groupMap.count(full.text())) { obj.type = OBJ_GROUP; obj.accountName = groupMap[full.text()]; }
		else if (userMap.count(full.text())) { obj.type = OBJ_USER; obj.accountName = userMap[full.text()]; }
		out.push_back(obj);
	}
	std::sort(out.begin(), out.end(), [](const DirObject& a, const DirObject& b) {
		if (a.type != b.type) return a.type < b.type;
		return a.name < b.name;
	});
	return out;
}

// ---------------------------------------------------------------------
// CRUD-Hüllen um samba-tool.
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// samba-tool schreibt vor der eigentlichen Meldung seitenweise
// Rauschen: registrierte GENSEC-Backends, lmhosts-Versuche,
// Schema-Hinweise, dazu die Warnung ueber Kennwoerter auf der
// Kommandozeile. In einem Fehlerdialog erschlaegt das die eine Zeile,
// auf die es ankommt. Hier bleiben nur die aussagekraeftigen Zeilen
// uebrig; findet sich keine, geben wir die Ausgabe ungefiltert zurueck,
// damit nie etwas verlorengeht.
// ---------------------------------------------------------------------
static std::string condenseSambaToolError(const std::string& raw) {
	static const char* noise[] = {
		"GENSEC backend", "resolve_lmhosts:", "debug_lookup_classname",
		"WARNING: Using passwords on command line", "Installing the setproctitle",
		"registered", "Attempting lmhosts lookup"
	};
	std::string result;
	for (auto& line : splitLines(raw)) {
		std::string l = trimStr(line);
		if (l.empty()) continue;
		bool skip = false;
		for (auto* n : noise) if (l.find(n) != std::string::npos) { skip = true; break; }
		if (skip) continue;
		result += l + "\n";
	}
	return result.empty() ? raw : result;
}

static bool createUser(const FXString& username, const FXString& password, const FXString& fullName,
                        const FXString& ouRelDN, FXString& errorMsg) {
	std::vector<FXString> args = { FXString("samba-tool"), FXString("user"), FXString("create"), username, password };
	if (!fullName.empty()) { args.push_back(FXString("--given-name=") + fullName); }
	if (!ouRelDN.empty()) { args.push_back(FXString("--userou=") + ouRelDN); }
	std::string out;
	int rc = runAsRootCaptured(args, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool deleteUser(const FXString& username, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("delete"), username }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool createGroup(const FXString& groupname, const FXString& ouRelDN, FXString& errorMsg) {
	std::vector<FXString> args = { FXString("samba-tool"), FXString("group"), FXString("add"), groupname };
	if (!ouRelDN.empty()) args.push_back(FXString("--groupou=") + ouRelDN);
	std::string out;
	int rc = runAsRootCaptured(args, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool deleteGroup(const FXString& groupname, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("delete"), groupname }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}


static bool createOU(const FXString& ouDN, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("add"), ouDN }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool deleteOU(const FXString& ouDN, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("delete"), ouDN }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// ---------------------------------------------------------------------
// GPOs -- fuer den "Gruppenrichtlinie"-Reiter.
// ---------------------------------------------------------------------



// ---------------------------------------------------------------------
// GPOs anlegen/verknuepfen/loesen sind LDAP-Schreibzugriffe auf einen
// besonders geschuetzten Container (CN=Policies,CN=System) -- root
// bzw. das Maschinenkonto des DC reichen dafuer NICHT aus (genau wie im
// echten AD: nur Domain Admins duerfen GPOs anlegen). Lesen (listall/
// getlink) funktioniert dagegen problemlos als root. Deshalb fragen wir
// fuer die paar schreibenden GPO-Aktionen einmalig echte Administrator-
// Anmeldedaten ab und cachen sie fuer die laufende Sitzung.
static FXString g_adminUser, g_adminPass;
static bool g_haveAdminCreds = false;

class AdminCredsDialog : public FXDialogBox {
	FXDECLARE(AdminCredsDialog)
private:
	FXTextField *userField, *pwField;
protected:
	AdminCredsDialog() {}
public:
	AdminCredsDialog(FXWindow* owner)
		: FXDialogBox(owner, "Administrator-Anmeldedaten", DECOR_TITLE | DECOR_BORDER, 0,0,360,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Für diese Änderung werden Domain-Admin-\nAnmeldedaten benötigt (z.B. bei geschützten\nGruppen wie \"Domain Admins\" oder GPOs):");
		new FXLabel(main, "Benutzername:");
		userField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		userField->setText("administrator");
		new FXLabel(main, "Kennwort:");
		pwField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getUser() const { return userField->getText(); }
	FXString getPassword() const { return pwField->getText(); }
	virtual ~AdminCredsDialog() {}
};
FXIMPLEMENT(AdminCredsDialog, FXDialogBox, NULL, 0)

// Gibt bei Erfolg "-U user%pass" als einzelnes Argument zurueck, sonst leer.
static FXString ensureAdminCreds(FXWindow* owner) {
	if (g_haveAdminCreds) return FXString("-U") + g_adminUser + "%" + g_adminPass;
	AdminCredsDialog dlg(owner);
	if (!dlg.execute(PLACEMENT_OWNER)) return "";
	g_adminUser = dlg.getUser();
	g_adminPass = dlg.getPassword();
	g_haveAdminCreds = true;
	return FXString("-U") + g_adminUser + "%" + g_adminPass;
}

static bool addGroupMember(FXWindow* owner, const FXString& groupname, const FXString& member, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("addmembers"), groupname, member }, out);
	if (rc != 0) {
		// Manche besonders geschuetzte Gruppen (z.B. "Domain Admins")
		// brauchen echte Administrator-Anmeldedaten, root/Maschinenkonto
		// reichen nicht -- genau wie bei GPOs.
		FXString cred = ensureAdminCreds(owner);
		if (cred.empty()) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
		out.clear();
		rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("addmembers"), groupname, member, cred }, out);
		if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	}
	return true;
}

static bool removeGroupMember(FXWindow* owner, const FXString& groupname, const FXString& member, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("removemembers"), groupname, member }, out);
	if (rc != 0) {
		FXString cred = ensureAdminCreds(owner);
		if (cred.empty()) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
		out.clear();
		rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("removemembers"), groupname, member, cred }, out);
		if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	}
	return true;
}

static bool createGpo(FXWindow* owner, const FXString& displayName, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann kein GPO angelegt werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("create"), displayName, cred }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}


static bool linkGpo(FXWindow* owner, const FXString& guid, const FXString& containerFullDN, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann kein GPO verknüpft werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("setlink"), containerFullDN, guid, cred }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// Loescht ein GPO vollstaendig: AD-Objekt und SYSVOL-Verzeichnis.
// "Entfernen" im Reiter loest dagegen nur die Verknuepfung -- so haelt
// es auch das Original, was aber dazu fuehrt, dass sich mit der Zeit
// verwaiste GPOs ansammeln.
static bool deleteGpoCompletely(FXWindow* owner, const FXString& guid, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann das Gruppenrichtlinienobjekt nicht gelöscht werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("del"), guid, cred }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool unlinkGpo(FXWindow* owner, const FXString& guid, const FXString& containerFullDN, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann die Verknüpfung nicht entfernt werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("dellink"), containerFullDN, guid, cred }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// ---------------------------------------------------------------------
// Dialog "Neuer Benutzer"
// ---------------------------------------------------------------------
static const char* ADM_DIR = "/usr/local/share/ice2k/adm";

static bool haveAdmFiles() {
	FXString path = FXString(ADM_DIR) + "/system.adm";
	return access(path.text(), F_OK) == 0;
}

static bool haveMsiextract() {
	return access("/usr/bin/msiextract", F_OK) == 0;
}

static bool installMsiextract(std::string& log, FXString& errorMsg) {
	log += "Installiere msitools (zum Entpacken der .msi-Datei)...\n";
	runAsRootCaptured({ FXString("apt-get"), FXString("update") }, log);
	std::string out;
	int rc = runAsRootCaptured({ FXString("env"), FXString("DEBIAN_FRONTEND=noninteractive"),
	                              FXString("apt-get"), FXString("install"), FXString("-y"),
	                              FXString("-o"), FXString("Dpkg::Options::=--force-confold"),
	                              FXString("msitools") }, out);
	log += out + "\n";
	if (rc != 0 || !haveMsiextract()) {
		errorMsg = "Installation von msitools ist fehlgeschlagen (siehe Protokoll).";
		return false;
	}
	log += "msitools erfolgreich installiert.\n";
	return true;
}

// Versucht das .msi automatisch herunterzuladen. Da die Microsoft-
// Downloadseite ihren tatsaechlichen Dateilink per JavaScript erzeugt,
// ist dieser direkte Link ohne Garantie -- schlaegt er fehl, wird auf
// den manuellen Weg zurueckgefallen (siehe downloadAndExtractAdmFiles).
static bool tryAutoDownloadMsi(const FXString& destPath, std::string& log) {
	log += "Versuche automatischen Download von " + std::string(destPath.text()) + "...\n";
	std::string out;
	int rc = runAsRootCaptured({ FXString("wget"), FXString("-q"), FXString("-O"), destPath,
	                              FXString("https://download.microsoft.com/download/f/0/0/f00b6d78-011f-42d5-b2e5-2f5e0f2e6b0c/2000admsetup.msi") }, out);
	log += out + "\n";
	if (rc != 0 || access(destPath.text(), F_OK) != 0) {
		runAsRoot({ FXString("rm"), FXString("-f"), destPath });
		return false;
	}
	return true;
}

static bool extractAdmFromMsi(const FXString& msiPath, std::string& log, FXString& errorMsg) {
	log += "Entpacke ADM-Dateien aus " + std::string(msiPath.text()) + "...\n";
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(ADM_DIR) });
	FXString tmpDir = "/tmp/ice2k-adm-extract";
	runAsRoot({ FXString("rm"), FXString("-rf"), tmpDir });
	runAsRoot({ FXString("mkdir"), FXString("-p"), tmpDir });

	std::string out;
	int rc = runAsRootCaptured({ FXString("msiextract"), FXString("-C"), tmpDir, msiPath }, out);
	log += out + "\n";
	if (rc != 0) { errorMsg = "msiextract ist fehlgeschlagen (siehe Protokoll)."; return false; }

	// Die .adm-Dateien liegen im MSI ueblicherweise direkt im Wurzel-
	// verzeichnis oder einem Unterordner -- wir suchen rekursiv und
	// kopieren alle Fundstellen in unser ADM-Verzeichnis.
	out.clear();
	rc = runAsRootCaptured({ FXString("bash"), FXString("-c"),
		FXString("find '") + tmpDir + "' -iname '*.adm' -exec cp {} " + FXString(ADM_DIR) + "/ \\;" }, out);
	runAsRoot({ FXString("rm"), FXString("-rf"), tmpDir });

	if (!haveAdmFiles()) {
		errorMsg = "Nach dem Entpacken wurden keine .adm-Dateien in " + FXString(ADM_DIR) + " gefunden.";
		return false;
	}
	log += "ADM-Dateien erfolgreich nach " + std::string(ADM_DIR) + " kopiert.\n";
	return true;
}

// Kompletter Ablauf: Werkzeuge pruefen/installieren, Download versuchen,
// bei Fehlschlag manuell nachfragen (Datei-Auswahldialog fuer ein
// bereits von Hand heruntergeladenes .msi), dann entpacken.
static bool downloadAndExtractAdmFiles(FXWindow* owner, std::string& log, FXString& errorMsg) {
	if (!haveMsiextract()) {
		if (!installMsiextract(log, errorMsg)) return false;
	}

	FXString msiPath = "/tmp/2000admsetup.msi";
	runAsRoot({ FXString("rm"), FXString("-f"), msiPath });

	if (!tryAutoDownloadMsi(msiPath, log)) {
		log += "Automatischer Download nicht erfolgreich.\n";
		FXMessageBox::information(owner, MBOX_OK, "Manueller Download nötig",
			"Der automatische Download hat nicht funktioniert.\n\n"
			"Bitte lade das Paket \"2000admsetup.msi\" manuell von\n"
			"https://www.microsoft.com/en-us/download/details.aspx?id=18664\n"
			"herunter und wähle es im nächsten Dialog aus.");
		FXString picked = FXFileDialog::getOpenFilename(owner, "2000admsetup.msi auswählen", FXSystem::getHomeDirectory(), "MSI-Dateien (*.msi)");
		if (picked.empty()) { errorMsg = "Kein Download und keine Datei ausgewählt."; return false; }
		std::string out;
		runAsRootCaptured({ FXString("cp"), picked, msiPath }, out);
	}

	bool ok = extractAdmFromMsi(msiPath, log, errorMsg);
	runAsRoot({ FXString("rm"), FXString("-f"), msiPath });
	return ok;
}

// ---------------------------------------------------------------------
// Softwareinstallation (GPO-Erweiterung) -- legt ein
// PackageRegistration-Objekt in Active Directory an und schreibt die
// zugehoerige .aas-Datei nach SYSVOL, nach [MS-GPSI]. Die noetigen
// AD-Objektklassen (Package-Registration, Class-Store) sind Teil des
// Standard-AD-Schemas und liegen auch bei Samba bereits vor.
// ---------------------------------------------------------------------
// Alle vier Werte stammen aus echten Objekten eines
// Windows-2000-Servers -- keiner davon ist abgeleitet oder geraten.
// Bemerkenswert: Computer- und Benutzerzuweisung unterscheiden sich
// nicht nur im Zweig, sondern auch in den Flags (Computer hat 0x4000,
// Benutzer dafuer 0x200 und 0x40000).
static const uint32_t PACKAGE_FLAGS_ASSIGNED_MACHINE = 0xA0084C70;
static const uint32_t PACKAGE_FLAGS_ASSIGNED_USER    = 0xA00C0E70;
static const uint32_t PACKAGE_FLAGS_PUBLISHED        = 0xA0080878;
static const uint32_t PACKAGE_FLAGS_REMOVE           = 0xA0080110;

static const char* GPSI_CSE_GUID = "{C6DC5466-785A-11D2-84D0-00C04FB169F7}";
static const char* GPSI_TOOL_GUID_USER = "{BACF5C8A-A3C7-11D1-A760-00C04FB9603F}";
static const char* GPSI_TOOL_GUID_MACHINE = "{942A8E4F-A261-11D1-A760-00C04FB9603F}";

// ---------------------------------------------------------------------
// ldapadd/ldapmodify/ldapsearch stecken im Paket "ldap-utils", das auf
// einem frischen Debian nicht vorinstalliert ist. Ohne diese Pruefung
// scheitert die erste GPO-Aenderung mit einer nichtssagenden
// env-Fehlermeldung ("ldapadd: Datei oder Verzeichnis nicht gefunden")
// -- genau so ist es einem Nutzer passiert.
// ---------------------------------------------------------------------
static bool g_ldapToolsOk = false;

static bool ensureLdapTools(FXWindow* owner) {
	if (g_ldapToolsOk) return true;

	const char* tools[] = { "/usr/bin/ldapadd", "/usr/bin/ldapmodify", "/usr/bin/ldapsearch" };
	bool complete = true;
	for (auto* t : tools) if (access(t, X_OK) != 0) complete = false;
	if (complete) { g_ldapToolsOk = true; return true; }

	if (FXMessageBox::question(owner, MBOX_YES_NO, "Fehlendes Paket",
		"Für diese Änderung werden die LDAP-Werkzeuge (ldapadd, ldapmodify,\n"
		"ldapsearch) benötigt. Sie stecken im Paket \"ldap-utils\", das auf\n"
		"diesem System noch nicht installiert ist.\n\n"
		"Jetzt installieren?") != MBOX_CLICKED_YES) return false;

	std::string out;
	runAsRootCaptured({ FXString("apt-get"), FXString("update") }, out);
	out.clear();
	int rc = runAsRootCaptured({
		FXString("env"), FXString("DEBIAN_FRONTEND=noninteractive"),
		FXString("apt-get"), FXString("install"), FXString("-y"),
		FXString("-o"), FXString("Dpkg::Options::=--force-confold"),
		FXString("ldap-utils")
	}, out);

	complete = true;
	for (auto* t : tools) if (access(t, X_OK) != 0) complete = false;
	if (rc != 0 || !complete) {
		FXMessageBox::error(owner, MBOX_OK, "Installation fehlgeschlagen",
			"Das Paket \"ldap-utils\" konnte nicht installiert werden.\n\n%s",
			out.empty() ? "apt-get meldete einen Fehler." : out.c_str());
		return false;
	}
	g_ldapToolsOk = true;
	return true;
}

// Fuehrt ldapadd/ldapmodify mit einer LDIF-Datei gegen den lokalen
// Samba-AD-DC aus. Admin-Anmeldedaten wie bei GPOs/geschuetzten
// Gruppen -- root reicht fuer diese LDAP-Schreibzugriffe nicht.
static bool runLdapChange(FXWindow* owner, const FXString& realm, const std::string& ldif, bool isAdd, std::string& log, FXString& errorMsg) {
	if (!ensureLdapTools(owner)) { errorMsg = "Ohne die LDAP-Werkzeuge (Paket \"ldap-utils\") ist diese Änderung nicht möglich."; return false; }
	if (ensureAdminCreds(owner).empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann nichts in AD angelegt werden."; return false; }

	FXString ldifPath = "/tmp/ice2k-ldapchange.ldif";
	std::ofstream out(ldifPath.text());
	out << ldif;
	out.close();
	runAsRoot({ FXString("chmod"), FXString("666"), ldifPath });

	std::string cmdOut;
	int rc = runAsRootCaptured({
		FXString("env"), FXString("LDAPTLS_REQCERT=never"),
		FXString(isAdd ? "ldapadd" : "ldapmodify"),
		FXString("-H"), FXString("ldap://127.0.0.1"), FXString("-Z"), FXString("-x"),
		FXString("-D"), g_adminUser + "@" + realm,
		FXString("-w"), g_adminPass,
		FXString("-f"), ldifPath
	}, cmdOut);
	log += cmdOut + "\n";
	runAsRoot({ FXString("rm"), FXString("-f"), ldifPath });
	// "Already exists" ist fuer unsere idempotenten Create-Aufrufe kein
	// Fehler -- der Aufrufer entscheidet selbst, ob das in Ordnung ist.
	if (rc != 0 && cmdOut.find("Already exists") == std::string::npos) {
		// Die betroffene DN mit ausgeben -- bei einer Folge von Aufrufen
		// (Class Store, Packages, packageRegistration ...) ist sonst nicht
		// erkennbar, welcher davon gescheitert ist, und im Protokoll steht
		// womoeglich nur die harmlose Meldung des vorherigen.
		std::string dnLine = "unbekannt";
		size_t p = ldif.find("dn: ");
		if (p != std::string::npos) {
			size_t e = ldif.find('\n', p);
			dnLine = ldif.substr(p + 4, (e == std::string::npos ? ldif.size() : e) - p - 4);
		}
		errorMsg = FXString("LDAP-Änderung fehlgeschlagen bei:\n") + dnLine.c_str() +
		           "\n\n" + (cmdOut.empty() ? "(keine Ausgabe)" : cmdOut.c_str());
		return false;
	}
	return true;
}

// Liest den Wert eines einzelnen Attributs eines AD-Objekts (leerer
// String, wenn nicht vorhanden oder bei Fehler).
static std::string readLdapAttribute(FXWindow* owner, const FXString& realm, const std::string& dn, const std::string& attr) {
	if (!ensureLdapTools(owner)) return "";
	if (ensureAdminCreds(owner).empty()) return "";
	std::string out;
	// "-o ldif-wrap=no -LLL" ist entscheidend -- ohne das bricht ldapsearch
	// lange Werte ueber mehrere Zeilen um, und ein einfaches grep der
	// ersten Zeile wuerde den Wert (z.B. gPCMachineExtensionNames mit
	// mehreren GUID-Paaren) mitten im Text abschneiden.
	runAsRootCaptured({
		FXString("bash"), FXString("-c"),
		FXString("LDAPTLS_REQCERT=never ldapsearch -H ldap://127.0.0.1 -Z -x -o ldif-wrap=no -LLL -D '") + g_adminUser + "@" + realm +
			"' -w '" + g_adminPass + "' -b '" + dn.c_str() + "' -s base '(objectClass=*)' " + attr.c_str() + " 2>/dev/null | grep '^" + attr.c_str() + ":' | sed 's/^" + attr.c_str() + ": //'"
	}, out);
	while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
	return out;
}

// ---------------------------------------------------------------------
// Verknuepfungsreihenfolge (gPLink). samba-tool kennt dafuer keinen
// Befehl -- "gpo setlink" haengt nur an, "gpo dellink" entfernt. Also
// lesen wir das Attribut direkt per LDAP, ordnen die Bloecke um und
// schreiben es komplett zurueck. Jeder Block behaelt dabei seine
// eigenen Optionsflags (";0", ";1" ...) unveraendert.
// ---------------------------------------------------------------------
static std::vector<std::string> parseGpLinkBlocks(const std::string& raw) {
	std::vector<std::string> out;
	size_t i = 0;
	while (i < raw.size()) {
		size_t a = raw.find('[', i);
		if (a == std::string::npos) break;
		size_t b = raw.find(']', a);
		if (b == std::string::npos) break;
		out.push_back(raw.substr(a, b - a + 1));
		i = b + 1;
	}
	return out;
}


static std::string base64Encode(const std::vector<uint8_t>& data) {
	static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;
	size_t i = 0;
	while (i + 3 <= data.size()) {
		uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
		out += tbl[(n >> 18) & 0x3F]; out += tbl[(n >> 12) & 0x3F]; out += tbl[(n >> 6) & 0x3F]; out += tbl[n & 0x3F];
		i += 3;
	}
	size_t rem = data.size() - i;
	if (rem == 1) {
		uint32_t n = (uint32_t)data[i] << 16;
		out += tbl[(n >> 18) & 0x3F]; out += tbl[(n >> 12) & 0x3F]; out += "==";
	} else if (rem == 2) {
		uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
		out += tbl[(n >> 18) & 0x3F]; out += tbl[(n >> 12) & 0x3F]; out += tbl[(n >> 6) & 0x3F]; out += "=";
	}
	return out;
}

// Wandelt eine geschweift geklammerte GUID-Zeichenkette in die base64-
// kodierte 16-Byte-Binaerform, wie sie AD fuer Octet-String-Attribute
// wie "productCode" erwartet (Data1/2/3 little-endian, Data4 wie im
// String -- das uebliche Windows-GUID-Binaerformat). Ohne diese
// Kodierung lehnt Samba/AD den Wert mit "Invalid syntax" ab, da das
// Schema fuer productCode attributeSyntax 2.5.5.10 (Octet String)
// vorschreibt, keine Textform.
static std::string guidStringToBase64Binary(const std::string& guidStr) {
	std::string hex;
	for (char c : guidStr) if (isxdigit((unsigned char)c)) hex += c;
	if (hex.size() < 32) return "";
	auto hexVal = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; return tolower(c) - 'a' + 10; };
	auto byteAt = [&](size_t pos) -> uint8_t { return (uint8_t)((hexVal(hex[pos]) << 4) | hexVal(hex[pos + 1])); };
	std::vector<uint8_t> b(16);
	b[0] = byteAt(6);  b[1] = byteAt(4);  b[2] = byteAt(2);  b[3] = byteAt(0);   // Data1, little-endian
	b[4] = byteAt(10); b[5] = byteAt(8);                                        // Data2, little-endian
	b[6] = byteAt(14); b[7] = byteAt(12);                                       // Data3, little-endian
	for (int i = 0; i < 8; i++) b[8 + i] = byteAt(16 + i * 2);                  // Data4, wie im String
	return base64Encode(b);
}

static std::string generateNewGuidUpper() {
	std::string out;
	runAsRootCaptured({ FXString("cat"), FXString("/proc/sys/kernel/random/uuid") }, out);
	while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
	for (auto& c : out) c = toupper((unsigned char)c);
	return "{" + out + "}";
}

// Der CN eines packageRegistration-Objekts ist auf einem echten
// Windows-2000-Server eine GUID in Kleinbuchstaben OHNE geschweifte
// Klammern -- im Gegensatz zum Dateinamen der .aas, der sie hat.
// WICHTIG: "samba-tool gpo create" legt die Zweige als "Machine" und
// "User" an -- genau so, wie sie auch im msiScriptPath und in den
// Pfaden stehen, die ein Client anfragt. Frueher stand hier an
// mehreren Stellen "MACHINE"/"USER", was auf einem
// gross-/kleinschreibungsempfindlichen Dateisystem ein ZWEITES
// Verzeichnis erzeugt hat: mit falschen Rechten, und vom Client nie
// gelesen. Betroffen waren die .aas-Datei, Registry.pol und
// scripts.ini -- also praktisch alles, was ins SYSVOL geschrieben wird.
static const char* SYSVOL_MACHINE_DIR = "Machine";
static const char* SYSVOL_USER_DIR = "User";

static std::string generateNewGuidLowerPlain() {
	std::string out;
	runAsRootCaptured({ FXString("cat"), FXString("/proc/sys/kernel/random/uuid") }, out);
	while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
	for (auto& c : out) c = tolower((unsigned char)c);
	return out;
}

// Zeitstempel im Format, das Windows fuer lastUpdateSequence benutzt.
static std::string updateSequenceStamp() {
	time_t t = time(NULL);
	struct tm lt;
	localtime_r(&t, &lt);
	char buf[32];
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02d",
	         lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec);
	return buf;
}

// Haengt ein CSE+Werkzeug-GUID-Paar an gPCMachineExtensionNames/
// gPCUserExtensionNames an, falls es dort noch nicht steht -- sonst
// wuerde ein echter Client die jeweilige Erweiterung nie aufrufen,
// selbst wenn Einstellungen vorhanden sind. Generisch gehalten, damit
// sowohl Softwareinstallation als auch Skripte (und kuenftige
// Erweiterungen) dieselbe Funktion nutzen koennen.
static void writeGptIniVersion(const std::string& gptIniPath, uint32_t newVersion); // weiter unten definiert


static std::string guidFromGpoDn(const std::string& dn) {
	if (dn.compare(0, 3, "CN=") != 0) return "";
	size_t end = dn.find(',');
	if (end == std::string::npos) return "";
	return dn.substr(3, end - 3);
}

// ---------------------------------------------------------------------
// Versionszaehler eines GPOs erhoehen -- AN BEIDEN STELLEN.
//
// Ein Client merkt sich pro GPO die zuletzt verarbeitete Version und
// ueberspringt es beim naechsten Start vollstaendig, wenn sie sich nicht
// geaendert hat. Wird die Nummer nach einer Aenderung nicht erhoeht,
// passiert also nie wieder etwas, egal wie oft neu gestartet wird --
// genau dieser Fall ist einem Nutzer begegnet, nachdem ein Paket zu
// einem GPO hinzugefuegt wurde, das der Client vorher schon leer
// verarbeitet hatte.
//
// Massgeblich ist das AD-Attribut versionNumber; die GPT.INI im SYSVOL
// bekommt denselben Wert. Schlaegt das Schreiben in AD fehl, bleibt die
// GPT.INI absichtlich unangetastet, damit beide konsistent bleiben.
// ---------------------------------------------------------------------
static void bumpGpoVersion(FXWindow* owner, const FXString& realm, const std::string& gpoObjectDn,
                           bool machine, bool user, std::string& log) {
	if (!machine && !user) return;

	std::string cur = trimStr(readLdapAttribute(owner, realm, gpoObjectDn, "versionNumber"));
	uint32_t version = 0;
	try { version = (uint32_t)std::stoul(cur); } catch (...) {}

	uint32_t machineVer = version & 0xFFFF;
	uint32_t userVer = (version >> 16) & 0xFFFF;
	if (machine) machineVer++;
	if (user) userVer++;
	uint32_t newVersion = (userVer << 16) | machineVer;

	std::string ldif = "dn: " + gpoObjectDn + "\n"
	                    "changetype: modify\n"
	                    "replace: versionNumber\n"
	                    "versionNumber: " + std::to_string(newVersion) + "\n";
	FXString errorMsg;
	if (!runLdapChange(owner, realm, ldif, false, log, errorMsg)) {
		log += "Konnte versionNumber in AD nicht setzen: " + std::string(errorMsg.text()) + "\n"
		       "Die GPT.INI bleibt deshalb unveraendert, damit beide Stellen zusammenpassen.\n";
		return;
	}

	std::string guid = guidFromGpoDn(gpoObjectDn);
	if (guid.empty()) return;
	FXString realmLower = realm; realmLower.lower();
	writeGptIniVersion("/var/lib/samba/sysvol/" + std::string(realmLower.text()) +
	                    "/Policies/" + guid + "/GPT.INI", newVersion);
	log += "GPO-Version auf " + std::to_string(newVersion) + " erhoeht (AD und GPT.INI).\n";
}

// gPC*ExtensionNames: Bloecke "[{CSE}{Tool}...]". Laut [MS-GPOL] muessen
// die Bloecke nach CSE-GUID aufsteigend sortiert sein, ebenso die
// Tool-GUIDs innerhalb eines Blocks -- neue Eintraege werden deshalb
// einsortiert statt angehaengt (und eine vorhandene unsortierte Liste
// dabei gleich richtiggestellt).
static std::string mergeExtensionNames(const std::string& current, const std::string& cseGuid, const std::string& toolGuid) {
	auto upper = [](std::string x) { std::transform(x.begin(), x.end(), x.begin(), [](unsigned char c) { return std::toupper(c); }); return x; };
	std::map<std::string, std::set<std::string>> blocks; // CSE -> Tools (beides in Grossbuchstaben)
	for (auto& block : parseGpLinkBlocks(current)) {
		std::vector<std::string> guids;
		size_t pos = 0;
		while ((pos = block.find('{', pos)) != std::string::npos) {
			size_t end = block.find('}', pos);
			if (end == std::string::npos) break;
			guids.push_back(upper(block.substr(pos, end - pos + 1)));
			pos = end + 1;
		}
		if (guids.empty()) continue;
		auto& tools = blocks[guids[0]];
		for (size_t i = 1; i < guids.size(); i++) tools.insert(guids[i]);
	}
	blocks[upper(cseGuid)].insert(upper(toolGuid));
	std::string out;
	for (auto& kv : blocks) {
		out += "[" + kv.first;
		for (auto& t : kv.second) out += t;
		out += "]";
	}
	return out;
}

static bool registerExtensionOnly(FXWindow* owner, const FXString& realm, const std::string& gpoObjectDn, bool isMachine,
                                   const std::string& cseGuid, const std::string& toolGuid, std::string& log, FXString& errorMsg) {
	std::string attrName = isMachine ? "gPCMachineExtensionNames" : "gPCUserExtensionNames";
	std::string curVal = trimStr(readLdapAttribute(owner, realm, gpoObjectDn, attrName));
	std::string newVal = mergeExtensionNames(curVal, cseGuid, toolGuid);
	if (newVal == curVal) return true; // schon registriert und sortiert

	std::string ldif = "dn: " + gpoObjectDn + "\n"
	                    "changetype: modify\n"
	                    "replace: " + attrName + "\n" +
	                    attrName + ": " + newVal + "\n";
	return runLdapChange(owner, realm, ldif, false, log, errorMsg);
}

// Jede Aenderung an einer Erweiterung laeuft hier durch: erst die CSE
// registrieren (falls noch nicht geschehen), dann in jedem Fall den
// Versionszaehler erhoehen.
static bool ensureExtensionRegistered(FXWindow* owner, const FXString& realm, const std::string& gpoObjectDn, bool isMachine,
                                       const std::string& cseGuid, const std::string& toolGuid, std::string& log, FXString& errorMsg) {
	if (!registerExtensionOnly(owner, realm, gpoObjectDn, isMachine, cseGuid, toolGuid, log, errorMsg)) return false;
	bumpGpoVersion(owner, realm, gpoObjectDn, isMachine, !isMachine, log);
	return true;
}

static bool ensureSoftwareInstallExtensionRegistered(FXWindow* owner, const FXString& realm, const std::string& gpoObjectDn, bool isMachine, std::string& log, FXString& errorMsg) {
	std::string toolGuid = isMachine ? GPSI_TOOL_GUID_MACHINE : GPSI_TOOL_GUID_USER;
	return ensureExtensionRegistered(owner, realm, gpoObjectDn, isMachine, GPSI_CSE_GUID, toolGuid, log, errorMsg);
}

// ---------------------------------------------------------------------
// Skripte (An-/Abmeldung, Start/Herunterfahren) -- deutlich einfacher
// als Softwareinstallation: eine einzige scripts.ini pro Zweig
// (Computer: Start/Herunterfahren: <GPO>\MACHINE\Scripts\scripts.ini,
// Benutzer: Anmelden/Abmelden: <GPO>\USER\Scripts\scripts.ini), nach
// [MS-GPSCR]. Format: Abschnitte [Startup]/[Shutdown] bzw.
// [Logon]/[Logoff], darin durchnummerierte "<N>CmdLine="/
// "<N>Parameters="-Paare ab 0. Die Datei ist UTF-16LE mit BOM (0xFFFE)
// kodiert -- wie Registry.pol.
// ---------------------------------------------------------------------
static const char* GPSCR_CSE_GUID = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}";
static const char* GPSCR_TOOL_GUID_MACHINE = "{40B6664F-4972-11D1-A7CA-0000F87571E3}";
static const char* GPSCR_TOOL_GUID_USER = "{40B66650-4972-11D1-A7CA-0000F87571E3}";

struct ScriptEntry { FXString cmdLine, parameters; };

static std::string utf16leToUtf8(const std::string& raw) {
	std::string out;
	size_t start = 0;
	if (raw.size() >= 2 && (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) start = 2;
	for (size_t i = start; i + 1 < raw.size(); i += 2) {
		uint16_t u = (uint8_t)raw[i] | ((uint8_t)raw[i + 1] << 8);
		uint32_t cp = u;
		if (u >= 0xD800 && u <= 0xDBFF && i + 3 < raw.size()) {
			uint16_t lo = (uint8_t)raw[i + 2] | ((uint8_t)raw[i + 3] << 8);
			if (lo >= 0xDC00 && lo <= 0xDFFF) { cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00); i += 2; }
		}
		if (cp <= 0x7F) out += (char)cp;
		else if (cp <= 0x7FF) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
		else if (cp <= 0xFFFF) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
		else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
	}
	return out;
}

static std::string utf8ToUtf16leWithBom(const std::string& utf8) {
	std::string out;
	out += (char)0xFF; out += (char)0xFE;
	size_t i = 0, n = utf8.size();
	while (i < n) {
		unsigned char c = utf8[i];
		uint32_t cp = 0; int len = 1;
		if ((c & 0x80) == 0) { cp = c; len = 1; }
		else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
		else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
		else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
		else { i++; continue; }
		if (i + len > n) break;
		bool ok = true;
		for (int k = 1; k < len; k++) { unsigned char cc = utf8[i + k]; if ((cc & 0xC0) != 0x80) { ok = false; break; } cp = (cp << 6) | (cc & 0x3F); }
		if (!ok) { i++; continue; }
		i += len;
		auto put16 = [&](uint16_t u) { out += (char)(u & 0xFF); out += (char)((u >> 8) & 0xFF); };
		if (cp <= 0xFFFF) put16((uint16_t)cp);
		else { cp -= 0x10000; put16((uint16_t)(0xD800 + (cp >> 10))); put16((uint16_t)(0xDC00 + (cp & 0x3FF))); }
	}
	return out;
}

// Liest eine scripts.ini und liefert je Abschnitt ("Startup",
// "Shutdown", "Logon", "Logoff") die Liste ihrer Skripte, jeweils
// nach Index sortiert. Fehlende Datei ist okay (leeres Ergebnis --
// noch keine Skripte konfiguriert).
static std::map<std::string, std::vector<ScriptEntry>> parseScriptsIni(const std::string& path) {
	std::map<std::string, std::vector<ScriptEntry>> out;
	std::string raw = readFileUnprivileged(path.c_str());
	if (raw.empty()) return out;
	std::string utf8 = utf16leToUtf8(raw);
	std::string curSection;
	std::map<int, ScriptEntry> curEntries;
	auto flush = [&]() {
		if (!curSection.empty()) {
			std::vector<ScriptEntry> v;
			for (auto& kv : curEntries) v.push_back(kv.second);
			out[curSection] = v;
		}
		curEntries.clear();
	};
	for (auto& lineStr : splitLines(utf8)) {
		FXString line = lineStr.c_str();
		line.trim();
		if (line.empty()) continue;
		if (line[0] == '[' && line[line.length() - 1] == ']') {
			flush();
			curSection = line.mid(1, line.length() - 2).text();
			continue;
		}
		int eq = line.find('=');
		if (eq < 0) continue;
		FXString key = line.left(eq);
		FXString val = line.mid(eq + 1, line.length() - eq - 1);
		// Schluessel-Form "<N>CmdLine" / "<N>Parameters"
		int i = 0;
		while (i < (int)key.length() && isdigit((unsigned char)key[i])) i++;
		if (i == 0) continue;
		int idx = atoi(key.left(i).text());
		FXString rest = key.mid(i, key.length() - i);
		if (rest == "CmdLine") curEntries[idx].cmdLine = val;
		else if (rest == "Parameters") curEntries[idx].parameters = val;
	}
	flush();
	return out;
}

static bool writeScriptsIni(const std::string& path, const std::map<std::string, std::vector<ScriptEntry>>& sections, FXString& errorMsg) {
	std::string utf8;
	for (auto& kv : sections) {
		if (kv.second.empty()) continue;
		utf8 += "[" + kv.first + "]\r\n";
		for (size_t i = 0; i < kv.second.size(); i++) {
			utf8 += std::to_string(i) + "CmdLine=" + kv.second[i].cmdLine.text() + "\r\n";
			utf8 += std::to_string(i) + "Parameters=" + kv.second[i].parameters.text() + "\r\n";
		}
	}
	std::string encoded = utf8ToUtf16leWithBom(utf8);
	FXString tmpPath = "/tmp/ice2k-scripts-tmp.ini";
	std::ofstream out(tmpPath.text(), std::ios::binary);
	out.write(encoded.data(), (std::streamsize)encoded.size());
	out.close();
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(path.substr(0, path.find_last_of('/')).c_str()) });
	int rc = runAsRoot({ FXString("cp"), tmpPath, FXString(path.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });
	if (rc != 0) { errorMsg = "Konnte scripts.ini nicht schreiben."; return false; }
	return true;
}

// ---------------------------------------------------------------------
// Ordnerumleitung -- der eigentliche Zielpfad wird (wie bei
// Administrativen Vorlagen) ganz gewoehnlich per Registry.pol
// uebertragen: die Windows-Shell liest den Ordnerort aus den
// "User Shell Folders"-Registrierungswerten, unabhaengig von der
// Gruppenrichtlinien-Erweiterung selbst. Zusaetzlich schreibt eine
// echte Windows-2000-Gruppenrichtlinie eine "fdeploy.ini" (nach
// [MS-GPFR], "Version Zero" -- die einzige Version, die Windows 2000
// beherrscht) mit Verhaltens-Flags je Ordner; wir schreiben hier
// bewusst nur den sichersten Standardwert (0, keine Zwangsrechte),
// da die genaue Flag-Bit-Bedeutung oeffentlich nicht vollstaendig
// dokumentiert ist -- die eigentliche Umleitung funktioniert bereits
// unabhaengig davon ueber die Registrierungswerte.
// ---------------------------------------------------------------------
static const char* GPFR_CSE_GUID = "{25537BA6-77A8-11D2-9B6C-0000F8080861}";
static const char* GPFR_TOOL_GUID_USER = "{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}";
static const char* USER_SHELL_FOLDERS_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";

struct FolderRedirEntry { std::string fdeployKey; std::string regValueName; FXString label; };
static const std::vector<FolderRedirEntry> FOLDER_REDIR_TARGETS = {
	{ "My Documents", "Personal", "Eigene Dateien (My Documents):" },
	{ "My Pictures", "My Pictures", "Eigene Bilder (My Pictures):" },
	{ "Start Menu", "Start Menu", "Startmenü:" },
	{ "Application Data", "AppData", "Anwendungsdaten:" },
	{ "Desktop", "Desktop", "Desktop:" },
};

// Liest die aktuell umgeleiteten Pfade aus der bestehenden User-
// Registry.pol (leere Zeichenkette = nicht umgeleitet).
static std::map<std::string, FXString> getFolderRedirectionPaths(const std::string& userPolPath) {
	std::map<std::string, FXString> out;
	RegPolFile file = parseRegPolFile(userPolPath);
	RegLookup lk = buildRegLookup(file);
	for (auto& t : FOLDER_REDIR_TARGETS) {
		auto it = lk.values.find({ lowerCopy(USER_SHELL_FOLDERS_KEY), lowerCopy(t.regValueName) });
		if (it != lk.values.end() && it->second.type == REG_TYPE_SZ) {
			out[t.fdeployKey] = FXString(std::string((const char*)it->second.data.data(), it->second.data.size()).c_str());
		} else {
			out[t.fdeployKey] = "";
		}
	}
	return out;
}

// Schreibt die Umleitungspfade -- leerer Pfad entfernt eine zuvor
// gesetzte Umleitung wieder (aktives Loeschen wie beim ADM-Editor,
// damit ein Client den Wert tatsaechlich zuruecknimmt).
static bool setFolderRedirectionPaths(FXWindow* owner, const DomainInfo& domain, const FXString& gpoGuid,
                                       const std::map<std::string, FXString>& newPaths, FXString& errorMsg) {
	FXString realmLower = domain.realm; realmLower.lower();
	std::string userScopeDir = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + std::string(gpoGuid.text()) + "/" + SYSVOL_USER_DIR;
	std::string userPolPath = userScopeDir + "/Registry.pol";

	RegPolFile origFile = parseRegPolFile(userPolPath);
	RegLookup origLookup = buildRegLookup(origFile);
	std::vector<RegPolEntry> finalEntries = origFile.entries;
	auto removeEntry = [&](const std::string& valuename) {
		std::string lv = lowerCopy(valuename);
		finalEntries.erase(std::remove_if(finalEntries.begin(), finalEntries.end(), [&](const RegPolEntry& e) {
			return lowerCopy(e.key) == lowerCopy(USER_SHELL_FOLDERS_KEY) && lowerCopy(e.valuename) == lv;
		}), finalEntries.end());
	};
	for (auto& t : FOLDER_REDIR_TARGETS) {
		auto it = newPaths.find(t.fdeployKey);
		if (it == newPaths.end()) continue;
		FXString path = it->second; path.trim();
		removeEntry(t.regValueName);
		bool wasConfigured = origLookup.values.count({ lowerCopy(USER_SHELL_FOLDERS_KEY), lowerCopy(t.regValueName) }) > 0;
		if (!path.empty()) {
			finalEntries.push_back(makeRegSzEntry(USER_SHELL_FOLDERS_KEY, t.regValueName, path.text()));
		} else if (wasConfigured) {
			finalEntries.push_back(makeDeleteValueEntry(USER_SHELL_FOLDERS_KEY, t.regValueName));
		}
	}

	std::string writeErr;
	FXString tmpPath = "/tmp/ice2k-folderredir-regpol.tmp";
	if (!writeRegPolFile(tmpPath.text(), finalEntries, writeErr)) { errorMsg = writeErr.c_str(); return false; }
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(userScopeDir.c_str()) });
	int rc = runAsRoot({ FXString("cp"), tmpPath, FXString(userPolPath.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });
	if (rc != 0) { errorMsg = "Konnte Registry.pol nicht schreiben."; return false; }

	// fdeploy.ini -- eine Zeile je tatsaechlich umgeleitetem Ordner.
	std::string fdeployUtf8 = "[Folder Status]\r\n";
	for (auto& t : FOLDER_REDIR_TARGETS) {
		auto it = newPaths.find(t.fdeployKey);
		if (it == newPaths.end()) continue;
		FXString path = it->second; path.trim();
		if (!path.empty()) fdeployUtf8 += t.fdeployKey + "=0\r\n";
	}
	std::string encoded = utf8ToUtf16leWithBom(fdeployUtf8);
	FXString fdeployTmp = "/tmp/ice2k-fdeploy.tmp";
	std::ofstream out(fdeployTmp.text(), std::ios::binary);
	out.write(encoded.data(), (std::streamsize)encoded.size());
	out.close();
	std::string fdeployDestDir = userScopeDir + "/Documents & Settings";
	std::string fdeployDest = fdeployDestDir + "/fdeploy.ini";
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(fdeployDestDir.c_str()) });
	rc = runAsRoot({ FXString("cp"), fdeployTmp, FXString(fdeployDest.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), fdeployTmp });
	if (rc != 0) { errorMsg = "Konnte fdeploy.ini nicht schreiben."; return false; }

	std::string log;
	std::string gpoObjectDn = "CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
	ensureExtensionRegistered(owner, domain.realm, gpoObjectDn, false, GPFR_CSE_GUID, GPFR_TOOL_GUID_USER, log, errorMsg);
	return true;
}

// Legt "CN=Class Store" und "CN=Packages,CN=Class Store" unter dem
// angegebenen skopierten GPO-DN an, falls sie noch nicht existieren.
static bool ensureClassStoreAndPackages(FXWindow* owner, const FXString& realm, const std::string& scopedGpoDn, std::string& log, FXString& errorMsg) {
	std::string classStoreDn = "CN=Class Store," + scopedGpoDn;
	// Attribute nach dem Vorbild eines echten Windows-2000-Servers:
	// ohne extensionName/displayName/showInAdvancedViewOnly findet der
	// Client den Store nicht als Softwareablage wieder.
	std::string gpoDnForDisplay = scopedGpoDn.substr(scopedGpoDn.find(',') + 1); // ohne "CN=Machine,"
	std::string ldif1 = "dn: " + classStoreDn + "\n"
	                     "changetype: add\n"
	                     "objectClass: classStore\n"
	                     "description: Application Store\n"
	                     "extensionName: Software\n"
	                     "appSchemaVersion: 1740\n"
	                     "displayName: LDAP://" + gpoDnForDisplay + "\n"
	                     "showInAdvancedViewOnly: TRUE\n"
	                     "lastUpdateSequence: " + updateSequenceStamp() + "\n";
	if (!runLdapChange(owner, realm, ldif1, true, log, errorMsg)) return false;   // CN=Class Store

	// "CN=Packages" wird ebenfalls als classStore angelegt. Das ist keine
	// Nachlaessigkeit, sondern vom Schema vorgegeben: unterhalb eines
	// classStore sind laut possSuperiors nur packageRegistration,
	// typeLibrary, classRegistration, categoryRegistration und classStore
	// erlaubt -- ein gewoehnlicher container wird mit "Naming violation
	// (64)" abgelehnt. (Ausprobiert; die Annahme, es muesse ein container
	// sein, war falsch.)
	std::string packagesDn = "CN=Packages," + classStoreDn;
	std::string ldif2 = "dn: " + packagesDn + "\n"
	                     "changetype: add\n"
	                     "objectClass: classStore\n"
	                     "description: Application Packages\n"
	                     "showInAdvancedViewOnly: TRUE\n";
	if (!runLdapChange(owner, realm, ldif2, true, log, errorMsg)) return false;   // CN=Packages

	return true;
}

// Aktualisiert den Zeitstempel von "CN=Class Store", damit andere
// Clients/Werkzeuge den Container als gueltig ansehen.
// Markiert den Class Store als geaendert. Achtung, hier standen zwei
// falsche Werte, die die beim Anlegen gesetzten wieder ueberschrieben
// haben:
//   - lastUpdateSequence als Unix-Zeit statt im Format yyyymmddhhmmss,
//     das ein echter Windows-2000-Server schreibt
//   - displayName auf "Application Store" -- das gehoert in
//     "description"; displayName traegt auf einem echten Server den
//     LDAP-Verweis auf das GPO, zu dem der Store gehoert.
static bool bumpClassStoreConfirmation(FXWindow* owner, const FXString& realm, const std::string& classStoreDn, std::string& log, FXString& errorMsg) {
	// "CN=Class Store,CN=Machine,<GPO-DN>" -> "<GPO-DN>"
	std::string gpoDn = classStoreDn;
	for (int i = 0; i < 2; i++) {
		size_t comma = gpoDn.find(',');
		if (comma == std::string::npos) break;
		gpoDn = gpoDn.substr(comma + 1);
	}

	std::string ldif = "dn: " + classStoreDn + "\n"
	                    "changetype: modify\n"
	                    "replace: lastUpdateSequence\n"
	                    "lastUpdateSequence: " + updateSequenceStamp() + "\n-\n"
	                    "replace: displayName\n"
	                    "displayName: LDAP://" + gpoDn + "\n";
	return runLdapChange(owner, realm, ldif, false, log, errorMsg);
}

// Liest ProductCode/ProductName/ProductVersion/Manufacturer aus der
// Property-Tabelle einer .msi (per "msiinfo export", Teil von
// msitools, siehe haveMsiextract()).
static std::map<std::string, std::string> extractMsiProperties(const std::string& msiPath) {
	std::map<std::string, std::string> props;
	std::string out;
	runAsRootCaptured({ FXString("msiinfo"), FXString("export"), FXString(msiPath.c_str()), FXString("Property") }, out);
	auto lines = splitLines(out);
	// Zeilen 0-2 sind Kopf/Typen/Schluessel-Wiederholung (siehe idt-Format),
	// die eigentlichen Werte beginnen ab Zeile 3.
	for (size_t i = 3; i < lines.size(); i++) {
		FXString l = lines[i].c_str();
		int tab = l.find('\t');
		if (tab < 0) continue;
		FXString key = l.left(tab);
		FXString val = l.mid(tab + 1, l.length() - tab - 1);
		props[key.text()] = val.text();
	}
	return props;
}

// Liest die Feature-Tabelle der .msi. Ohne diese Eintraege enthaelt das
// Advertise-Skript keine Features, und der Windows Installer weiss
// nicht, was er installieren soll -- im Vergleich mit einem echten,
// von Windows 2000 erzeugten Skript war genau das der Unterschied.
// Spalte 0 ist "Feature", Spalte 1 "Feature_Parent"; die
// Tabellenreihenfolge wird beibehalten.
static std::vector<AasFeature> extractMsiFeatures(const std::string& msiPath) {
	std::vector<AasFeature> features;
	std::string out;
	runAsRootCaptured({ FXString("msiinfo"), FXString("export"), FXString(msiPath.c_str()), FXString("Feature") }, out);
	auto lines = splitLines(out);
	for (size_t i = 3; i < lines.size(); i++) {   // Zeilen 0-2: Kopf/Typen/Schluessel
		FXString l = lines[i].c_str();
		if (trimStr(l.text()).empty()) continue;
		int tab = l.find('\t');
		AasFeature f;
		if (tab < 0) {
			f.name = trimStr(l.text());
		} else {
			f.name = trimStr(l.left(tab).text());
			FXString rest = l.mid(tab + 1, l.length() - tab - 1);
			int tab2 = rest.find('\t');
			f.parent = trimStr((tab2 < 0 ? rest : rest.left(tab2)).text());
		}
		if (!f.name.empty()) features.push_back(f);
	}
	return features;
}

// Der Package Code steht nicht in der Property-Tabelle, sondern als
// "Revision number" im Summary-Information-Stream.
static std::string extractMsiPackageCode(const std::string& msiPath) {
	std::string out;
	runAsRootCaptured({ FXString("msiinfo"), FXString("suminfo"), FXString(msiPath.c_str()) }, out);
	for (auto& line : splitLines(out)) {
		FXString l = line.c_str();
		FXString lower = l; lower.lower();
		if (lower.find("revision") < 0) continue;
		int b = l.find('{'), e = l.find('}');
		if (b >= 0 && e > b) return std::string(l.mid(b, e - b + 1).text());
	}
	return "";
}

struct SoftwarePackageParams {
	std::string localMsiPath;   // lokal lesbarer Pfad zur .msi (fuer msiinfo)
	std::string msiUncPath;     // vollstaendiger UNC-Pfad, wie ein Client ihn erreicht
	bool assignedPerMachine;    // true = Computerkonfiguration, false = Benutzerkonfiguration
	bool published;             // nur relevant fuer Benutzerkonfiguration (assignedPerMachine=false)
};

// Uebertraegt Besitzer, Modus und die NT-ACL eines vorhandenen
// SYSVOL-Verzeichnisses auf eine neu angelegte Datei oder ein neues
// Verzeichnis. Ohne das fehlen einer frisch per mkdir/cp erzeugten
// Datei genau die Rechte, ueber die Clients auf SYSVOL zugreifen.
static void inheritSysvolPermissions(const std::string& referenceDir, const std::string& target, bool isDir) {
	runAsRoot({ FXString("chown"), FXString(("--reference=" + referenceDir).c_str()), FXString(target.c_str()) });
	runAsRoot({ FXString("chmod"), FXString(isDir ? "0770" : "0770"), FXString(target.c_str()) });

	// NT-ACL vom Vorbild holen. "samba-tool ntacl get" schreibt diverse
	// Meldungen mit; die SDDL-Zeile ist die, die mit "O:" beginnt.
	std::string out;
	runAsRootCaptured({ FXString("samba-tool"), FXString("ntacl"), FXString("get"),
	                    FXString(referenceDir.c_str()), FXString("--as-sddl") }, out);
	std::string sddl;
	for (auto& line : splitLines(out)) {
		std::string l = trimStr(line);
		if (l.compare(0, 2, "O:") == 0) { sddl = l; break; }
	}
	if (sddl.empty()) return;
	runAsRoot({ FXString("samba-tool"), FXString("ntacl"), FXString("set"),
	            FXString(sddl.c_str()), FXString(target.c_str()) });
}

// Kompletter Ablauf: MSI-Metadaten lesen, .aas-Datei schreiben,
// PackageRegistration-Objekt in AD anlegen, GPO-Erweiterungsliste
// aktualisieren.
static bool addSoftwarePackage(FXWindow* owner, const DomainInfo& domain, const FXString& gpoGuid,
                                const SoftwarePackageParams& params, std::string& log, FXString& errorMsg) {
	if (!haveMsiextract()) {
		if (!installMsiextract(log, errorMsg)) return false;
	}

	auto props = extractMsiProperties(params.localMsiPath);
	if (!props.count("ProductCode")) { errorMsg = "Konnte ProductCode nicht aus der .msi lesen (siehe Protokoll)."; return false; }

	AasPackageInfo info;
	info.productName = props.count("ProductName") ? props["ProductName"] : "Unbekanntes Produkt";
	info.productCodeGuid = props["ProductCode"];
	// Package Code aus der .msi selbst, nicht selbst erfunden -- ein
	// echtes Windows-Skript traegt hier den Wert aus dem
	// Summary-Information-Stream.
	info.packageCodeGuid = extractMsiPackageCode(params.localMsiPath);
	if (info.packageCodeGuid.empty()) info.packageCodeGuid = generateNewGuidUpper();
	info.upgradeCodeGuid = props.count("UpgradeCode") ? props["UpgradeCode"] : "";
	info.versionString = props.count("ProductVersion") ? props["ProductVersion"] : "1.0.0";
	info.msiUncPath = params.msiUncPath;
	info.assignedPerMachine = params.assignedPerMachine;
	info.langId = props.count("ProductLanguage") ? (uint32_t)atoi(props["ProductLanguage"].c_str()) : 1031;
	if (info.langId == 0) info.langId = 1031;
	info.features = extractMsiFeatures(params.localMsiPath);
	if (info.features.empty())
		log += "Achtung: In der .msi wurde keine Feature-Tabelle gefunden.\n"
		       "Das Advertise-Skript veröffentlicht dann keine Features und der\n"
		       "Client kann nichts installieren.\n";
	else
		log += "Features aus der .msi: " + std::to_string(info.features.size()) + "\n";

	// CN des Objekts: Kleinbuchstaben ohne Klammern (wie auf einem echten
	// Server). Der Dateiname der .aas behaelt dagegen die Klammerform.
	std::string packageCn = generateNewGuidLowerPlain();
	std::string packageGuid = generateNewGuidUpper();
	FXString realmLower = domain.realm; realmLower.lower();
	std::string scope = params.assignedPerMachine ? "Machine" : "User";
	std::string scopedGpoDn = "CN=" + scope + ",CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string gpoObjectDn = "CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string classStoreDn = "CN=Class Store," + scopedGpoDn;
	std::string packagesDn = "CN=Packages," + classStoreDn;
	std::string packageDn = "CN=" + packageCn + "," + packagesDn;

	if (!ensureClassStoreAndPackages(owner, domain.realm, scopedGpoDn, log, errorMsg)) return false;

	// .aas-Datei schreiben -- lokal, dann als root nach SYSVOL kopieren.
	std::string sysvolScopeDir = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" +
	                              std::string(gpoGuid.text()) + "/" + (params.assignedPerMachine ? SYSVOL_MACHINE_DIR : SYSVOL_USER_DIR);
	std::string appsDir = sysvolScopeDir + "/Applications";
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(appsDir.c_str()) });
	std::string aasLocalTmp = "/tmp/ice2k-package.aas";
	std::string aasErrorMsg;
	if (!writeAasFile(aasLocalTmp, info, aasErrorMsg)) { errorMsg = aasErrorMsg.c_str(); return false; }
	std::string aasDestPath = appsDir + "/" + packageGuid + ".aas";
	int rc = runAsRoot({ FXString("cp"), FXString(aasLocalTmp.c_str()), FXString(aasDestPath.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), FXString(aasLocalTmp.c_str()) });
	if (rc != 0) { errorMsg = "Konnte .aas-Datei nicht nach SYSVOL kopieren."; return false; }

	// Rechte angleichen. "mkdir"/"cp" als root erzeugen root:root ohne
	// NT-ACL -- das Maschinenkonto des Clients kommt dann nicht an die
	// Datei heran und meldet beim Kopieren der Skriptdatei "Fehler 3"
	// (Pfad nicht gefunden). In der Praxis genau so aufgetreten.
	// Vorbild ist das uebergeordnete Verzeichnis des GPO-Zweigs.
	inheritSysvolPermissions(sysvolScopeDir, appsDir, true);
	inheritSysvolPermissions(sysvolScopeDir, aasDestPath, false);

	// UNC-Pfad zur .aas-Datei fuer das msiScriptPath-Attribut.
	std::string msiScriptPath = "\\\\" + std::string(realmLower.text()) + "\\sysvol\\" + std::string(realmLower.text()) +
	                             "\\Policies\\" + std::string(gpoGuid.text()) + "\\" + scope + "\\Applications\\" + packageGuid + ".aas";

	std::string msiScriptName = params.published ? "P" : "A";

	// packageFlags: alle Werte aus echten, von Windows 2000 erzeugten
	// Objekten. Zwei Annahmen haben sich dabei als falsch erwiesen --
	// veroeffentlichte Pakete tauschen das Assigned-Bit 0x800 nicht
	// gegen 0x8 (0x800 bleibt stehen), und die Zuweisung an die
	// Benutzerkonfiguration hat einen eigenen Wert statt desselben wie
	// beim Computer.
	uint32_t packageFlags = params.assignedPerMachine ? PACKAGE_FLAGS_ASSIGNED_MACHINE
	                      : params.published          ? PACKAGE_FLAGS_PUBLISHED
	                                                  : PACKAGE_FLAGS_ASSIGNED_USER;

	// versionNumberHi/Lo sind schlicht Haupt- und Nebenversion.
	int verHi = 0, verLo = 0;
	sscanf(info.versionString.c_str(), "%d.%d", &verHi, &verLo);

	std::string ldif = "dn: " + packageDn + "\n"
	                    "changetype: add\n"
	                    "objectClass: packageRegistration\n"
	                    "displayName: " + info.productName + "\n"
	                    "packageName: " + info.productName + "\n"
	                    "packageType: 5\n"
	                    "packageFlags: " + std::to_string(packageFlags) + "\n"
	                    "msiScriptName: " + msiScriptName + "\n"
	                    "msiScriptPath: " + msiScriptPath + "\n"
	                    "msiFileList: 0:" + params.msiUncPath + "\n"
	                    "productCode:: " + guidStringToBase64Binary(info.productCodeGuid) + "\n"
	                    "versionNumberHi: " + std::to_string(verHi) + "\n"
	                    "versionNumberLo: " + std::to_string(verLo) + "\n"
	                    "revision: 0\n"
	                    "localeID: " + std::to_string(info.langId) + "\n"
	                    "installUiLevel: 3\n"
	                    "showInAdvancedViewOnly: TRUE\n"
	                    "lastUpdateSequence: " + updateSequenceStamp() + "\n"
	                    // 1282 ist der Wert, den ein echter Server fuer x86 schreibt.
	                    "machineArchitecture: 1282\n";
	if (!info.upgradeCodeGuid.empty())
		ldif += "upgradeProductCode:: " + guidStringToBase64Binary(info.upgradeCodeGuid) + "\n";
	if (props.count("ARPURLINFOABOUT")) ldif += "url: " + props["ARPURLINFOABOUT"] + "\n";
	if (props.count("Manufacturer")) ldif += "vendor: " + props["Manufacturer"] + "\n";
	if (!runLdapChange(owner, domain.realm, ldif, true, log, errorMsg)) return false;

	if (!bumpClassStoreConfirmation(owner, domain.realm, classStoreDn, log, errorMsg)) return false;
	if (!ensureSoftwareInstallExtensionRegistered(owner, domain.realm, gpoObjectDn, params.assignedPerMachine, log, errorMsg)) return false;

	return true;
}

struct SoftwarePackageInfo {
	std::string guid;        // "{XXXXXXXX-...}" -- der CN des Objekts, fuer Loeschen gebraucht
	std::string displayName;
	std::string msiScriptPath;
	bool assigned = true;    // aus packageFlags abgeleitet
	bool published = false;
	bool pendingRemoval = false; // msiScriptName "R": wartet auf Deinstallation
};

// Listet alle Pakete eines Zweigs (Computer/Benutzer) eines GPOs auf.
// Leere Liste, wenn noch keine Pakete vorhanden sind (kein Fehler --
// die Packages-Container existieren dann evtl. noch gar nicht).
static std::vector<SoftwarePackageInfo> listSoftwarePackages(FXWindow* owner, const DomainInfo& domain, const FXString& gpoGuid, bool isMachine) {
	std::vector<SoftwarePackageInfo> out;
	if (ensureAdminCreds(owner).empty()) return out;
	std::string scope = isMachine ? "Machine" : "User";
	std::string packagesDn = "CN=Packages,CN=Class Store,CN=" + scope + ",CN=" + std::string(gpoGuid.text()) +
	                          ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string raw;
	runAsRootCaptured({
		FXString("bash"), FXString("-c"),
		FXString("LDAPTLS_REQCERT=never ldapsearch -H ldap://127.0.0.1 -Z -x -o ldif-wrap=no -LLL -D '") + g_adminUser + "@" + domain.realm +
			"' -w '" + g_adminPass + "' -b '" + packagesDn.c_str() + "' -s one '(objectClass=packageRegistration)' cn displayName packageFlags msiScriptPath msiScriptName 2>/dev/null"
	}, raw);

	SoftwarePackageInfo cur;
	bool haveEntry = false;
	auto flush = [&]() { if (haveEntry && !cur.guid.empty()) out.push_back(cur); cur = SoftwarePackageInfo(); haveEntry = false; };
	for (auto& line : splitLines(raw)) {
		if (line.empty()) { flush(); continue; }
		if (line.rfind("dn:", 0) == 0) { haveEntry = true; continue; }
		if (line.rfind("cn: ", 0) == 0) { cur.guid = line.substr(4); continue; }
		if (line.rfind("displayName: ", 0) == 0) { cur.displayName = line.substr(13); continue; }
		if (line.rfind("msiScriptPath: ", 0) == 0) { cur.msiScriptPath = line.substr(15); continue; }
		if (line.rfind("packageFlags: ", 0) == 0) {
			// Windows schreibt den Wert vorzeichenbehaftet (0xA0084C70
			// erscheint als -1610068880); stoul wuerde daran scheitern.
			uint32_t flags = 0;
			try { flags = (uint32_t)(int32_t)std::stoll(line.substr(14)); } catch (...) {}
			cur.assigned = (flags & 0x800) != 0;
			cur.published = (flags & 0x8) != 0;
			continue;
		}
		if (line.rfind("msiScriptName: ", 0) == 0) { cur.pendingRemoval = (line.substr(15) == "R"); continue; }
	}
	flush();
	return out;
}

// Beim Entfernen fragt das Original, was mit bereits installierter
// Software geschehen soll. Genau diese zwei Moeglichkeiten bilden wir ab.
class RemovePackageDialog : public FXDialogBox {
	FXDECLARE(RemovePackageDialog)
private:
	FXRadioButton *rbUninstall, *rbLeave;
protected:
	RemovePackageDialog() : rbUninstall(NULL), rbLeave(NULL) {}
public:
	enum { ID_CHOICE = FXDialogBox::ID_LAST };
	long onChoice(FXObject* sender, FXSelector, void*) {
		rbUninstall->setCheck(sender == rbUninstall);
		rbLeave->setCheck(sender == rbLeave);
		return 1;
	}
	bool uninstallFromClients() const { return rbUninstall->getCheck(); }

	RemovePackageDialog(FXWindow* owner, const std::string& name)
		: FXDialogBox(owner, "Software entfernen", DECOR_TITLE | DECOR_BORDER, 0,0,440,210) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12);
		new FXLabel(main, ("\"" + name + "\" aus der Gruppenrichtlinie entfernen:").c_str(), NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		rbUninstall = new FXRadioButton(main, "Software &sofort von Benutzern und Computern deinstallieren", this, ID_CHOICE);
		new FXLabel(main, "Das Paket bleibt als Auftrag stehen, bis alle Clients die\n"
		                  "Anwendung entfernt haben.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		rbLeave = new FXRadioButton(main, "Software auf den Clients &belassen", this, ID_CHOICE);
		new FXLabel(main, "Nur die Zuweisung wird gelöscht. Bereits installierte\n"
		                  "Anwendungen bleiben erhalten und werden nicht mehr verwaltet.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		rbUninstall->setCheck(TRUE);

		FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btns, LAYOUT_FILL_X);
		new FXButton(btns, "OK", NULL, this, ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btns, "Abbrechen", NULL, this, ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
};

FXDEFMAP(RemovePackageDialog) RemovePackageDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, RemovePackageDialog::ID_CHOICE, RemovePackageDialog::onChoice),
};
FXIMPLEMENT(RemovePackageDialog, FXDialogBox, RemovePackageDialogMap, ARRAYNUMBER(RemovePackageDialogMap))

// Merkt ein Paket zur Deinstallation vor, statt es zu loeschen.
//
// So macht es auch ein echter Windows-2000-Server: das
// packageRegistration-Objekt bleibt stehen, msiScriptName wechselt von
// "A" auf "R" und packageFlags von 0xA0084C70 auf 0xA0080110. Der
// Client sieht daran beim naechsten Start, dass er die Anwendung
// entfernen soll. Wird das Objekt stattdessen geloescht, erfaehrt er
// davon nie und die Software bleibt installiert. (Werte aus dem
// Vergleich mit einem echten Server uebernommen.)

static bool markSoftwarePackageForRemoval(FXWindow* owner, const DomainInfo& domain, const FXString& gpoGuid,
                                           bool isMachine, const SoftwarePackageInfo& pkg,
                                           std::string& log, FXString& errorMsg) {
	std::string scope = isMachine ? "Machine" : "User";
	std::string scopedGpoDn = "CN=" + scope + ",CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string classStoreDn = "CN=Class Store," + scopedGpoDn;
	std::string packageDn = "CN=" + pkg.guid + ",CN=Packages," + classStoreDn;
	std::string gpoObjectDn = "CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();

	std::string ldif = "dn: " + packageDn + "\n"
	                    "changetype: modify\n"
	                    "replace: msiScriptName\n"
	                    "msiScriptName: R\n-\n"
	                    "replace: packageFlags\n"
	                    "packageFlags: " + std::to_string((int32_t)PACKAGE_FLAGS_REMOVE) + "\n-\n"
	                    "replace: lastUpdateSequence\n"
	                    "lastUpdateSequence: " + updateSequenceStamp() + "\n";
	if (!runLdapChange(owner, domain.realm, ldif, false, log, errorMsg)) return false;

	if (!bumpClassStoreConfirmation(owner, domain.realm, classStoreDn, log, errorMsg)) return false;
	bumpGpoVersion(owner, domain.realm, gpoObjectDn, isMachine, !isMachine, log);
	return true;
}

// Entfernt ein Paket wieder: LDAP-Objekt loeschen + zugehoerige
// .aas-Datei aus SYSVOL entfernen.
static bool deleteSoftwarePackage(FXWindow* owner, const DomainInfo& domain, const FXString& gpoGuid, bool isMachine, const SoftwarePackageInfo& pkg, FXString& errorMsg) {
	if (ensureAdminCreds(owner).empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann nichts gelöscht werden."; return false; }
	std::string scope = isMachine ? "Machine" : "User";
	std::string packageDn = "CN=" + pkg.guid + ",CN=Packages,CN=Class Store,CN=" + scope + ",CN=" + std::string(gpoGuid.text()) +
	                         ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string out;
	int rc = runAsRootCaptured({
		FXString("bash"), FXString("-c"),
		FXString("LDAPTLS_REQCERT=never ldapdelete -H ldap://127.0.0.1 -Z -x -D '") + g_adminUser + "@" + domain.realm +
			"' -w '" + g_adminPass + "' '" + packageDn.c_str() + "'"
	}, out);
	if (rc != 0) { errorMsg = "Löschen in AD fehlgeschlagen (siehe Protokoll)."; return false; }

	FXString realmLower = domain.realm; realmLower.lower();
	std::string aasPath = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" +
	                       std::string(gpoGuid.text()) + "/" + (isMachine ? SYSVOL_MACHINE_DIR : SYSVOL_USER_DIR) +
	                       "/Applications/" + pkg.guid + ".aas";
	runAsRoot({ FXString("rm"), FXString("-f"), FXString(aasPath.c_str()) });
	return true;
}



// (system.adm, inetres.adm, ...) tragen oft zu denselben Ober-
// kategorien bei (z.B. "Windows-Komponenten"). Wir fuehren
// gleichnamige Kategorien rekursiv zusammen, damit im Baum keine
// Dopplungen entstehen.
// ---------------------------------------------------------------------
static void mergeCategoryInto(AdmCategory& target, AdmCategory&& src) {
	if (target.keyname.empty()) target.keyname = src.keyname;
	for (auto& sc : src.subCategories) {
		bool merged = false;
		for (auto& tc : target.subCategories) {
			if (tc.label == sc.label) { mergeCategoryInto(tc, std::move(sc)); merged = true; break; }
		}
		if (!merged) target.subCategories.push_back(std::move(sc));
	}
	for (auto& p : src.policies) target.policies.push_back(std::move(p));
}

static void mergeCategoriesInto(std::vector<AdmCategory>& target, std::vector<AdmCategory>&& src) {
	for (auto& sc : src) {
		bool merged = false;
		for (auto& tc : target) {
			if (tc.label == sc.label) { mergeCategoryInto(tc, std::move(sc)); merged = true; break; }
		}
		if (!merged) target.push_back(std::move(sc));
	}
}

// Laedt alle .adm-Dateien aus ADM_DIR und liefert die zusammengefuehrten
// Ober-Kategorien fuer eine gegebene CLASS ("MACHINE" oder "USER").
static std::vector<AdmCategory> loadMergedAdmCategories(const std::string& wantClass) {
	std::vector<AdmCategory> result;
	std::string out;
	runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString("ls ") + ADM_DIR + "/*.adm 2>/dev/null" }, out);
	for (auto& fname : splitLines(out)) {
		if (fname.empty()) continue;
		AdmFile file = parseAdmFile(fname);
		if (!file.parseError.empty()) continue;
		for (auto& cls : file.classes) {
			if (cls.classType != wantClass) continue;
			mergeCategoriesInto(result, std::move(cls.topCategories));
		}
	}
	return result;
}

class NewUserDialog : public FXDialogBox {
	FXDECLARE(NewUserDialog)
private:
	FXTextField *fullNameField, *usernameField, *pwField, *pwConfirmField;
protected:
	NewUserDialog() {}
public:
	NewUserDialog(FXWindow* owner)
		: FXDialogBox(owner, "Neues Objekt - Benutzer", DECOR_TITLE | DECOR_BORDER, 0,0,380,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Vollständiger Name:");
		fullNameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXLabel(main, "Benutzeranmeldename:");
		usernameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXLabel(main, "Kennwort:");
		pwField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
		new FXLabel(main, "Kennwort bestätigen:");
		pwConfirmField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getFullName() const { return fullNameField->getText(); }
	FXString getUsername() const { return usernameField->getText(); }
	FXString getPassword() const { return pwField->getText(); }
	FXString getConfirm() const { return pwConfirmField->getText(); }
	virtual ~NewUserDialog() {}
};
FXIMPLEMENT(NewUserDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Neue Gruppe"
// ---------------------------------------------------------------------
class NewGroupDialog : public FXDialogBox {
	FXDECLARE(NewGroupDialog)
private:
	FXTextField* nameField;
protected:
	NewGroupDialog() {}
public:
	NewGroupDialog(FXWindow* owner)
		: FXDialogBox(owner, "Neues Objekt - Gruppe", DECOR_TITLE | DECOR_BORDER, 0,0,360,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Gruppenname:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getName() const { return nameField->getText(); }
	virtual ~NewGroupDialog() {}
};
FXIMPLEMENT(NewGroupDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Neue Organisationseinheit"
// ---------------------------------------------------------------------
class NewOUDialog : public FXDialogBox {
	FXDECLARE(NewOUDialog)
private:
	FXTextField* nameField;
protected:
	NewOUDialog() {}
public:
	NewOUDialog(FXWindow* owner)
		: FXDialogBox(owner, "Neues Objekt - Organisationseinheit", DECOR_TITLE | DECOR_BORDER, 0,0,360,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Name:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getName() const { return nameField->getText(); }
	virtual ~NewOUDialog() {}
};
FXIMPLEMENT(NewOUDialog, FXDialogBox, NULL, 0)


static bool setUserEnabled(const FXString& username, bool enabled, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString(enabled ? "enable" : "disable"), username }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool setUserPassword(const FXString& username, const FXString& password, FXString& errorMsg) {
	std::string input = std::string(password.text()) + "\n" + password.text() + "\n";
	std::string out;
	int rc = runAsRootCapturedWithStdin({ FXString("samba-tool"), FXString("user"), FXString("setpassword"), username }, input, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// ---------------------------------------------------------------------
// Computerobjekte -- eigenstaendig anlegen/loeschen, unabhaengig vom
// eigentlichen Domaenenbeitritt (z.B. um einen Rechnernamen vorab zu
// reservieren).
// ---------------------------------------------------------------------
static bool createComputer(const FXString& name, const FXString& ouRelDN, FXString& errorMsg) {
	std::vector<FXString> args = { FXString("samba-tool"), FXString("computer"), FXString("create"), name };
	if (!ouRelDN.empty()) args.push_back(FXString("--computerou=") + ouRelDN);
	std::string out;
	int rc = runAsRootCaptured(args, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

static bool deleteComputer(const FXString& name, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("computer"), FXString("delete"), name }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// ---------------------------------------------------------------------
// Objekte zwischen Containern/Organisationseinheiten verschieben --
// gilt fuer Benutzer/Gruppen/Computer (per Anmeldename) und
// Organisationseinheiten selbst (per volle DN).
// ---------------------------------------------------------------------
static bool moveObject(ObjType type, const FXString& accountNameOrFullDN, const FXString& targetOuFullDN, FXString& errorMsg) {
	FXString sub;
	switch (type) {
		case OBJ_USER: sub = "user"; break;
		case OBJ_GROUP: sub = "group"; break;
		case OBJ_COMPUTER: sub = "computer"; break;
		case OBJ_OU: sub = "ou"; break;
		default: errorMsg = "Dieser Objekttyp kann hier nicht verschoben werden."; return false;
	}
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), sub, FXString("move"), accountNameOrFullDN, targetOuFullDN }, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// Umbenennen -- fuer Benutzer/Gruppen aendert dies nur den Anzeigenamen
// (CN), nicht den Anmeldenamen (sAMAccountName bleibt unveraendert,
// genau wie beim einfachen F2-Umbenennen in echten Active Directory-
// Benutzer und -Computer). Fuer Organisationseinheiten aendert sich
// die DN direkt. Fuer Computer gibt es kein eigenes samba-tool-
// Unterkommando -- dafuer per LDAP-Modrdn direkt umbenannt.
static bool renameObject(FXWindow* owner, const DomainInfo& domain, ObjType type, const FXString& accountName,
                          const FXString& currentFullDN, const FXString& newName, FXString& errorMsg) {
	switch (type) {
		case OBJ_USER:
		case OBJ_GROUP: {
			FXString sub = (type == OBJ_USER) ? "user" : "group";
			std::string out;
			int rc = runAsRootCaptured({ FXString("samba-tool"), sub, FXString("rename"), accountName, FXString("--force-new-cn=") + newName }, out);
			if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
			return true;
		}
		case OBJ_OU: {
			int comma = currentFullDN.find(',');
			if (comma < 0) { errorMsg = "Konnte übergeordneten Container nicht bestimmen."; return false; }
			FXString parentPart = currentFullDN.mid(comma + 1, currentFullDN.length() - comma - 1);
			FXString newFullDN = "OU=" + newName + "," + parentPart;
			std::string out;
			int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("rename"), currentFullDN, newFullDN }, out);
			if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
			return true;
		}
		case OBJ_COMPUTER: {
			std::string ldif = "dn: " + std::string(currentFullDN.text()) + "\n"
			                    "changetype: modrdn\n"
			                    "newrdn: CN=" + std::string(newName.text()) + "\n"
			                    "deleteoldrdn: 1\n";
			std::string log;
			return runLdapChange(owner, domain.realm, ldif, false, log, errorMsg);
		}
		default: errorMsg = "Dieser Objekttyp kann hier nicht umbenannt werden."; return false;
	}
}

// ---------------------------------------------------------------------
// Sicherheitseinstellungen -- Kennwort- und Kontosperrungsrichtlinie.
// In Active Directory (wie schon unter Windows 2000/2003, vor den
// granularen Kennwortrichtlinien von 2008) gibt es davon nur EINE
// domainweite Auspraegung, die ueber die "Default Domain Policy"
// bearbeitet wird -- entsprechend bildet Samba das nicht als
// Registry.pol/GptTmpl.inf-Datei ab, sondern direkt als Attribute des
// Domaenenobjekts, verwaltet ueber "samba-tool domain passwordsettings".
// ---------------------------------------------------------------------
struct PasswordPolicy {
	bool complexity = true;
	int historyLength = 24;
	int minPwdLength = 7;
	int minPwdAgeDays = 1;
	int maxPwdAgeDays = 42;
	int lockoutDurationMins = 30;
	int lockoutThreshold = 0;
	int lockoutWindowMins = 30;
};

static FXString trimmed(const std::string& s) {
	FXString f = s.c_str();
	f.trim();
	return f;
}

static PasswordPolicy getPasswordPolicy() {
	PasswordPolicy p;
	std::string out;
	runAsRootCaptured({ FXString("samba-tool"), FXString("domain"), FXString("passwordsettings"), FXString("show") }, out);
	for (auto& line : splitLines(out)) {
		size_t colon = line.find(':');
		if (colon == std::string::npos) continue;
		std::string key = line.substr(0, colon);
		FXString val = trimmed(line.substr(colon + 1));
		try {
			if (key.find("Password complexity") != std::string::npos) p.complexity = (val == "on");
			else if (key.find("history length") != std::string::npos) p.historyLength = std::stoi(val.text());
			else if (key.find("Minimum password length") != std::string::npos) p.minPwdLength = std::stoi(val.text());
			else if (key.find("Minimum password age") != std::string::npos) p.minPwdAgeDays = std::stoi(val.text());
			else if (key.find("Maximum password age") != std::string::npos) p.maxPwdAgeDays = std::stoi(val.text());
			else if (key.find("lockout duration") != std::string::npos) p.lockoutDurationMins = std::stoi(val.text());
			else if (key.find("lockout threshold") != std::string::npos) p.lockoutThreshold = std::stoi(val.text());
			else if (key.find("Reset account lockout") != std::string::npos) p.lockoutWindowMins = std::stoi(val.text());
		} catch (...) {}
	}
	return p;
}

static bool setPasswordPolicy(const PasswordPolicy& p, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({
		FXString("samba-tool"), FXString("domain"), FXString("passwordsettings"), FXString("set"),
		FXString("--complexity=") + (p.complexity ? "on" : "off"),
		FXString("--history-length=") + std::to_string(p.historyLength).c_str(),
		FXString("--min-pwd-length=") + std::to_string(p.minPwdLength).c_str(),
		FXString("--min-pwd-age=") + std::to_string(p.minPwdAgeDays).c_str(),
		FXString("--max-pwd-age=") + std::to_string(p.maxPwdAgeDays).c_str(),
		FXString("--account-lockout-duration=") + std::to_string(p.lockoutDurationMins).c_str(),
		FXString("--account-lockout-threshold=") + std::to_string(p.lockoutThreshold).c_str(),
		FXString("--reset-account-lockout-after=") + std::to_string(p.lockoutWindowMins).c_str(),
	}, out);
	if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	return true;
}

// Liste aller Organisationseinheiten der Domaene (volle DN + Anzeige-
// pfad), fuer die Zielauswahl beim Verschieben.
static std::vector<std::pair<FXString, FXString>> listAllOUsWithPaths() {
	std::vector<std::pair<FXString, FXString>> out;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("list") }, raw);
	for (auto& l : splitLines(raw)) {
		FXString dn = l.c_str();
		dn.trim();
		if (dn.empty()) continue;
		out.push_back({ dn, dn });
	}
	return out;
}

// ---------------------------------------------------------------------
// Kleiner Dialog fuer die Kennworteingabe (zweimal, zur Bestaetigung).
// ---------------------------------------------------------------------
class SetPasswordDialog : public FXDialogBox {
	FXDECLARE(SetPasswordDialog)
private:
	FXTextField *pwField, *confirmField;
protected:
	SetPasswordDialog() {}
public:
	SetPasswordDialog(FXWindow* owner, const FXString& username)
		: FXDialogBox(owner, "Kennwort für " + username, DECOR_TITLE | DECOR_BORDER, 0,0,340,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Neues Kennwort:");
		pwField = new FXTextField(main, 24, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
		new FXLabel(main, "Kennwort bestätigen:");
		confirmField = new FXTextField(main, 24, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getPassword() const { return pwField->getText(); }
	FXString getConfirm() const { return confirmField->getText(); }
	virtual ~SetPasswordDialog() {}
};
FXIMPLEMENT(SetPasswordDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Symbole fuer Dialoge. Einmal erzeugt und fuer die ganze Laufzeit
// gehalten -- Listeneintraege, die erst nach create() angehaengt
// werden, erzeugen ihre Symbole naemlich nicht selbst.
// ---------------------------------------------------------------------
static FXIcon* sharedPngIcon(const unsigned char* data) {
	static std::map<const unsigned char*, FXIcon*> cache;
	auto it = cache.find(data);
	if (it != cache.end()) return it->second;
	FXIcon* ic = new FXPNGIcon(app, data, IMAGE_NEAREST);
	ic->create();
	cache[data] = ic;
	return ic;
}

// ---------------------------------------------------------------------
// LDIF-Ausgabe von "samba-tool user show" zerlegen. Fortsetzungszeilen
// (beginnen mit einem Leerzeichen) werden angehaengt, "attr:: ..."
// ist base64-kodiert. Schluessel in Kleinbuchstaben, mehrwertige
// Attribute (memberOf, objectClass ...) bleiben alle erhalten.
// ---------------------------------------------------------------------
static std::string base64Decode(const std::string& in) {
	auto val = [](char c) -> int {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '+') return 62;
		if (c == '/') return 63;
		return -1;
	};
	std::string out;
	uint32_t buf = 0;
	int bits = 0;
	for (char c : in) {
		int v = val(c);
		if (v < 0) continue;
		buf = (buf << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) { bits -= 8; out += (char)((buf >> bits) & 0xFF); }
	}
	return out;
}

static std::multimap<std::string, std::string> parseLdifRecord(const std::string& raw) {
	std::vector<std::string> logical;
	for (auto& l : splitLines(raw)) {
		if (!l.empty() && l[0] == ' ' && !logical.empty()) logical.back() += l.substr(1);
		else logical.push_back(l);
	}
	std::multimap<std::string, std::string> out;
	for (auto& l : logical) {
		size_t p = l.find(':');
		if (p == std::string::npos || p == 0) continue;
		std::string key = lowerCopy(l.substr(0, p));
		if (key.find(' ') != std::string::npos) continue; // Rauschzeilen von samba-tool
		std::string value;
		if (p + 1 < l.size() && l[p + 1] == ':') value = base64Decode(trimStr(l.substr(p + 2)));
		else value = trimStr(l.substr(p + 1));
		out.emplace(key, value);
	}
	return out;
}

static std::string ldifFirst(const std::multimap<std::string, std::string>& rec, const char* attr) {
	auto it = rec.find(lowerCopy(attr));
	return it == rec.end() ? std::string() : it->second;
}

// ---------------------------------------------------------------------
// Beschreibung und Gruppentyp fuer die Listenansicht. "samba-tool ...
// list" liefert beides nicht, und fuer jedes Objekt einzeln "show"
// aufzurufen waere viel zu langsam. Samba stellt aber fuer root einen
// privilegierten ldapi-Socket bereit, ueber den ohne Anmeldedaten
// GELESEN werden darf (schreiben nicht) -- eine einzige Abfrage pro
// Container. Fehlt ldap-utils oder laeuft der Dienst nicht, bleiben die
// Spalten einfach leer; hier wird bewusst nichts nachinstalliert, das
// bleibt den schreibenden Aktionen vorbehalten.
// ---------------------------------------------------------------------
static const char* SAMBA_LDAPI_URL = "ldapi://%2Fvar%2Flib%2Fsamba%2Fprivate%2Fldap_priv%2Fldapi";

// Objektklassen, die das Snap-In als Ordner zeigt und im Baum aufklappt.
static bool isContainerClass(const std::string& cls) {
	static const std::set<std::string> classes = {
		"container", "builtindomain", "lostandfound", "msds-quotacontainer",
		"mstpm-informationobjectscontainer", "rpccontainer", "msds-passwordsettingscontainer",
		"filelinktracking"
	};
	return classes.count(lowerCopy(cls)) > 0;
}

struct LdapChildInfo {
	std::string dn;          // volle DN
	std::string description;
	long groupType = 0;
	bool advancedOnly = false;
	std::string objectClass; // speziellste Klasse
};

// Direkte Kinder eines Containers ueber den ldapi-Socket. ok=false,
// wenn ldapsearch fehlt oder die Abfrage scheitert -- der Aufrufer
// faellt dann auf das bisherige Verhalten zurueck.
static std::vector<LdapChildInfo> ldapListChildren(const FXString& containerFullDN, bool& ok) {
	std::vector<LdapChildInfo> out;
	ok = false;
	if (access("/usr/bin/ldapsearch", X_OK) != 0) return out;
	std::string raw;
	int rc = runAsRootCaptured({
		FXString("ldapsearch"), FXString("-x"), FXString("-LLL"), FXString("-o"), FXString("ldif-wrap=no"),
		FXString("-H"), FXString(SAMBA_LDAPI_URL), FXString("-b"), containerFullDN, FXString("-s"), FXString("one"),
		FXString("(objectClass=*)"), FXString("description"), FXString("groupType"),
		FXString("showInAdvancedViewOnly"), FXString("objectClass")
	}, raw);
	if (rc != 0) return out;
	ok = true;

	std::string block;
	auto flush = [&]() {
		auto rec = parseLdifRecord(block);
		block.clear();
		LdapChildInfo ci;
		ci.dn = ldifFirst(rec, "dn");
		if (ci.dn.empty()) return;
		ci.description = ldifFirst(rec, "description");
		try { ci.groupType = std::stol(ldifFirst(rec, "groupType")); } catch (...) {}
		ci.advancedOnly = lowerCopy(ldifFirst(rec, "showInAdvancedViewOnly")) == "true";
		// multimap haengt gleiche Schluessel in Einfuegereihenfolge an --
		// ldapsearch liefert objectClass von "top" bis zur speziellsten.
		auto range = rec.equal_range("objectclass");
		for (auto it = range.first; it != range.second; ++it) ci.objectClass = it->second;
		out.push_back(ci);
	};
	for (auto& l : splitLines(raw)) {
		if (l.empty()) flush();
		else block += l + "\n";
	}
	flush();
	return out;
}

static void enrichFromLdap(std::vector<DirObject>& objects, const FXString& containerFullDN, const FXString& baseDN) {
	if (objects.empty()) return;
	bool ok;
	std::vector<LdapChildInfo> children = ldapListChildren(containerFullDN, ok);
	if (!ok) return;
	std::map<std::string, const LdapChildInfo*> byDn;
	for (auto& c : children) byDn[lowerCopy(c.dn)] = &c;

	for (auto& obj : objects) {
		auto it = byDn.find(lowerCopy(std::string((obj.dn + "," + baseDN).text())));
		if (it == byDn.end()) continue;
		const LdapChildInfo& ci = *it->second;
		obj.description = ci.description.c_str();
		obj.groupType = ci.groupType;
		obj.advancedOnly = ci.advancedOnly;
		obj.objectClass = ci.objectClass.c_str();
		// Die Klassifizierung aus samba-tool kennt Container nur am Namen --
		// die echte Objektklasse ist verlaesslicher (z.B. ist
		// CN=Infrastructure ein infrastructureUpdate, kein Container).
		if (obj.type == OBJ_OTHER && isContainerClass(ci.objectClass)) obj.type = OBJ_CONTAINER;
		else if (obj.type == OBJ_CONTAINER && !ci.objectClass.empty() && !isContainerClass(ci.objectClass)) obj.type = OBJ_OTHER;
	}
}

// Typbezeichnung wie im deutschen Windows 2000.
static const char* groupTypeName(long groupType) {
	uint32_t gt = (uint32_t)groupType;
	bool security = (gt & 0x80000000u) != 0;
	if (gt & 0x1) return "Sicherheitsgruppe - Lokal (vordefiniert)";
	if (gt & 0x4) return security ? "Sicherheitsgruppe - Lokal (in Domäne)" : "Verteilergruppe - Lokal (in Domäne)";
	if (gt & 0x8) return security ? "Sicherheitsgruppe - Universal" : "Verteilergruppe - Universal";
	if (gt & 0x2) return security ? "Sicherheitsgruppe - Global" : "Verteilergruppe - Global";
	return "Gruppe";
}

// ---------------------------------------------------------------------
// DNs mit maskierten Zeichen ("CN=Meier\, Hans,OU=...") korrekt
// zerlegen -- Gruppennamen koennen, anders als OUs, durchaus Kommas
// enthalten.
// ---------------------------------------------------------------------
static std::vector<std::string> splitDnEscaped(const std::string& dn) {
	std::vector<std::string> out;
	std::string cur;
	for (size_t i = 0; i < dn.size(); i++) {
		char c = dn[i];
		if (c == '\\' && i + 1 < dn.size()) { cur += c; cur += dn[++i]; continue; }
		if (c == ',') { out.push_back(cur); cur.clear(); continue; }
		cur += c;
	}
	if (!cur.empty()) out.push_back(cur);
	return out;
}

static std::string rdnType(const std::string& rdn) {
	size_t p = rdn.find('=');
	return p == std::string::npos ? std::string() : lowerCopy(trimStr(rdn.substr(0, p)));
}

static std::string rdnValue(const std::string& rdn) {
	size_t p = rdn.find('=');
	std::string v = (p == std::string::npos) ? rdn : rdn.substr(p + 1);
	std::string out;
	for (size_t i = 0; i < v.size(); i++) {
		if (v[i] == '\\' && i + 1 < v.size()) { out += v[++i]; continue; }
		out += v[i];
	}
	return out;
}

// "CN=Domain Users,CN=Users,DC=linux,DC=zwiebelchen,DC=org" ->
// "linux.zwiebelchen.org/Users" -- der kanonische Name des
// UEBERGEORDNETEN Containers, so wie ihn die Spalte
// "Active Directory-Ordner" im Original zeigt.
static FXString dnToFolder(const std::string& dn) {
	std::vector<std::string> parts = splitDnEscaped(dn);
	std::string domainName;
	std::vector<std::string> path;
	for (size_t i = 1; i < parts.size(); i++) {
		if (rdnType(parts[i]) == "dc") {
			if (!domainName.empty()) domainName += ".";
			domainName += rdnValue(parts[i]);
		} else {
			path.push_back(rdnValue(parts[i]));
		}
	}
	std::string out = lowerCopy(domainName);
	for (auto it = path.rbegin(); it != path.rend(); ++it) out += "/" + *it;
	return FXString(out.c_str());
}

static FXString dnLeafName(const std::string& dn) {
	std::vector<std::string> parts = splitDnEscaped(dn);
	return parts.empty() ? FXString() : FXString(rdnValue(parts[0]).c_str());
}

// ---------------------------------------------------------------------
// Alle Gruppen der Domaene mit Ordner, Typ und Bereich. Drei
// samba-tool-Aufrufe: Anmeldenamen und DNs kommen in derselben
// Reihenfolge (wie schon bei buildDnToSamMap), Typ/Bereich liefert
// "group list -v" als Tabelle, deren letzte drei Spalten immer
// Typ/Bereich/Mitgliederzahl sind -- der Name davor darf also
// Leerzeichen enthalten.
// ---------------------------------------------------------------------
struct GroupEntry {
	FXString sam;     // sAMAccountName -- fuer samba-tool
	FXString cn;      // Anzeigename in den Listen
	std::string dn;   // volle DN
	FXString folder;  // "linux.zwiebelchen.org/Users"
	bool security = true;
	FXString scope;   // Builtin / Domain / Global / Universal
	std::string sid;  // nur wo gebraucht (Sicherheitseinstellungen)
	const unsigned char* icon = nullptr; // eigenes Symbol je Eintrag, sonst das des Dialogs
};

static std::vector<GroupEntry> listAllGroupsDetailed() {
	std::vector<FXString> plain = listNames({ FXString("samba-tool"), FXString("group"), FXString("list") });
	std::vector<FXString> dns = listNames({ FXString("samba-tool"), FXString("group"), FXString("list"), FXString("--full-dn") });

	std::map<std::string, std::pair<bool, FXString>> typeBySam;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("list"), FXString("-v") }, raw);
	for (auto& line : splitLines(raw)) {
		std::string l = trimStr(line);
		std::string rest = l;
		std::string cols[3];
		bool ok = true;
		for (int c = 2; c >= 0; c--) {
			size_t sp = rest.find_last_of(" \t");
			if (sp == std::string::npos) { ok = false; break; }
			cols[c] = rest.substr(sp + 1);
			rest = trimStr(rest.substr(0, sp));
		}
		if (!ok || rest.empty()) continue;
		if (cols[0] != "Security" && cols[0] != "Distribution") continue; // Kopfzeile/Trenner
		typeBySam[lowerCopy(rest)] = { cols[0] == "Security", FXString(cols[1].c_str()) };
	}

	std::vector<GroupEntry> out;
	size_t n = std::min(plain.size(), dns.size());
	for (size_t i = 0; i < n; i++) {
		GroupEntry g;
		g.sam = plain[i];
		g.dn = dns[i].text();
		g.cn = dnLeafName(g.dn);
		g.folder = dnToFolder(g.dn);
		auto t = typeBySam.find(lowerCopy(g.sam.text()));
		if (t != typeBySam.end()) { g.security = t->second.first; g.scope = t->second.second; }
		out.push_back(g);
	}
	std::sort(out.begin(), out.end(), [](const GroupEntry& a, const GroupEntry& b) {
		int fa = strcasecmp(a.folder.text(), b.folder.text());
		if (fa != 0) return fa < 0;
		return strcasecmp(a.cn.text(), b.cn.text()) < 0;
	});
	return out;
}

static int findGroupByDn(const std::vector<GroupEntry>& groups, const std::string& dn) {
	std::string needle = lowerCopy(dn);
	for (size_t i = 0; i < groups.size(); i++)
		if (lowerCopy(groups[i].dn) == needle) return (int)i;
	return -1;
}

// Direkte Gruppenmitgliedschaften eines Benutzers als DNs. Die primaere
// Gruppe steht bei "user getgroups" immer an erster Stelle -- sie kommt
// nicht aus memberOf, sondern aus primaryGroupID.
static bool getUserGroupDns(const FXString& username, std::vector<std::string>& dns, std::string& primaryDn, FXString& errorMsg) {
	std::string raw;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("getgroups"), username, FXString("--full-dn") }, raw);
	if (rc != 0) { errorMsg = condenseSambaToolError(raw).c_str(); return false; }
	dns.clear();
	for (auto& l : splitLines(raw)) {
		std::string t = trimStr(l);
		if (t.size() < 3 || lowerCopy(t.substr(0, 3)) != "cn=") continue;
		dns.push_back(t);
	}
	primaryDn = dns.empty() ? std::string() : dns.front();
	return true;
}

static bool setUserPrimaryGroup(FXWindow* owner, const FXString& username, const FXString& groupSam, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("setprimarygroup"), username, groupSam }, out);
	if (rc != 0) {
		FXString cred = ensureAdminCreds(owner);
		if (cred.empty()) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
		out.clear();
		rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("setprimarygroup"), username, groupSam, cred }, out);
		if (rc != 0) { errorMsg = condenseSambaToolError(out).c_str(); return false; }
	}
	return true;
}

// Ein LDIF-Wert, der nicht rein aus druckbarem ASCII besteht (Umlaute,
// fuehrende Leerzeichen/Doppelpunkte ...), muss laut RFC 2849
// base64-kodiert als "attr:: ..." uebergeben werden.
static std::string ldifAttrLine(const std::string& attr, const std::string& value) {
	bool safe = !value.empty() && value[0] != ' ' && value[0] != ':' && value[0] != '<' && value.back() != ' ';
	for (unsigned char c : value) if (c < 0x20 || c > 0x7E) { safe = false; break; }
	if (safe) return attr + ": " + value + "\n";
	return attr + ":: " + base64Encode(std::vector<uint8_t>(value.begin(), value.end())) + "\n";
}

// ---------------------------------------------------------------------
// Dialog "Gruppen auswählen" -- Nachbau der Objektauswahl, die der
// Reiter "Mitglied von" unter Windows 2000 oeffnet: oben alle Gruppen
// der Domaene, unten ein Eingabefeld fuer Namen getrennt durch
// Semikolons. "Namen überprüfen" loest die Eingabe auf und
// unterstreicht erkannte Namen.
// ---------------------------------------------------------------------
static const char* GROUP_PICKER_HINT = "<< Geben Sie die Namen getrennt durch Semikolons ein oder wählen Sie in der Liste aus >>";

class GroupPickerDialog : public FXDialogBox {
	FXDECLARE(GroupPickerDialog)
private:
	const std::vector<GroupEntry>* groups = nullptr;
	FXIconList* groupList = nullptr;
	FXText* namesText = nullptr;
	bool showingHint = true;
	std::vector<int> result;
	FXHiliteStyle styles[1];
protected:
	GroupPickerDialog() {}
public:
	enum { ID_GROUPLIST = FXDialogBox::ID_LAST, ID_ADD, ID_CHECK_NAMES, ID_NAMES, ID_OK };

	GroupPickerDialog(FXWindow* owner, const FXString& realm, const std::vector<GroupEntry>& groups_,
	                  const char* title = "Gruppen auswählen", const unsigned char* iconData = resico_users)
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,566,440),
		  groups(&groups_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 8,8,8,8, 0,6);

		FXHorizontalFrame* lookin = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(lookin, "Suchen &in:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH, 0,0,64,0);
		FXListBox* lookinBox = new FXListBox(lookin, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		FXString lowerRealm = realm; lowerRealm.lower();
		lookinBox->appendItem(lowerRealm, sharedPngIcon(resico_server));
		lookinBox->setNumVisible(1);
		lookinBox->disable();

		FXPacker* listFrame = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		groupList = new FXIconList(listFrame, this, ID_GROUPLIST,
		                           ICONLIST_DETAILED | ICONLIST_EXTENDEDSELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		groupList->appendHeader("Name", NULL, 256);
		groupList->appendHeader("Ordner", NULL, 270);
		for (auto& g : *groups) {
			FXIcon* ic = sharedPngIcon(g.icon ? g.icon : iconData);
			groupList->appendItem(g.cn + "\t" + g.folder, ic, ic);
		}

		FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btns, "Hin&zufügen", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);
		new FXButton(btns, "&Namen überprüfen", NULL, this, ID_CHECK_NAMES, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);

		FXPacker* textFrame = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FIX_HEIGHT, 0,0,0,130, 0,0,0,0);
		namesText = new FXText(textFrame, this, ID_NAMES, TEXT_WORDWRAP | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		styles[0].normalForeColor = namesText->getTextColor();
		styles[0].normalBackColor = namesText->getBackColor();
		styles[0].selectForeColor = namesText->getSelTextColor();
		styles[0].selectBackColor = namesText->getSelBackColor();
		styles[0].hiliteForeColor = namesText->getHiliteTextColor();
		styles[0].hiliteBackColor = namesText->getHiliteBackColor();
		styles[0].activeBackColor = namesText->getActiveBackColor();
		styles[0].style = FXText::STYLE_UNDERLINE;
		namesText->setHiliteStyles(styles);
		namesText->setStyled(TRUE);
		showHint();

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,80,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,80,0, 14,14,3,3);
	}

	void showHint() {
		namesText->setText(GROUP_PICKER_HINT);
		namesText->setSelection(0, namesText->getLength());
		showingHint = true;
	}

	void leaveHint() {
		if (!showingHint) return;
		showingHint = false;
		namesText->setText("");
	}

	FXString enteredText() const { return showingHint ? FXString() : namesText->getText(); }

	virtual void create() {
		FXDialogBox::create();
		namesText->setFocus();
	}

	// Eingabe in Namen zerlegen -- Semikolon als Trenner, wie im Original.
	static std::vector<FXString> splitNames(const FXString& text) {
		std::vector<FXString> out;
		FXString t = text;
		t.substitute('\n', ';');
		FXint start = 0;
		for (;;) {
			FXint p = t.find(';', start);
			FXString part = (p < 0) ? t.mid(start, t.length() - start) : t.mid(start, p - start);
			part.trim();
			if (!part.empty()) out.push_back(part);
			if (p < 0) break;
			start = p + 1;
		}
		return out;
	}

	// Anzeigename oder Anmeldename, exakt (ohne Gross-/Kleinschreibung);
	// sonst ein eindeutiger Namensanfang. -1 = nicht gefunden,
	// -2 = mehrdeutig.
	int resolveName(const FXString& name) const {
		for (size_t i = 0; i < groups->size(); i++) {
			if (strcasecmp((*groups)[i].cn.text(), name.text()) == 0 ||
			    strcasecmp((*groups)[i].sam.text(), name.text()) == 0) return (int)i;
		}
		int found = -1;
		for (size_t i = 0; i < groups->size(); i++) {
			bool prefix = strncasecmp((*groups)[i].cn.text(), name.text(), name.length()) == 0 ||
			              strncasecmp((*groups)[i].sam.text(), name.text(), name.length()) == 0;
			if (!prefix) continue;
			if (found >= 0) return -2;
			found = (int)i;
		}
		return found;
	}

	// Loest alle eingegebenen Namen auf. Bei Erfolg steht die Eingabe
	// danach in kanonischer Form (unterstrichen) im Feld.
	// quiet: keine Meldungen, bei einem unbekannten Namen bleibt die
	// Eingabe einfach unveraendert stehen.
	bool checkNames(std::vector<int>& resolved, bool quiet = false) {
		resolved.clear();
		std::vector<FXString> names = splitNames(enteredText());
		for (auto& n : names) {
			int idx = resolveName(n);
			if (idx < 0 && quiet) return false;
			if (idx == -1) {
				FXMessageBox::error(this, MBOX_OK, "Name nicht gefunden",
					"Der Name \"%s\" wurde nicht gefunden.\n\n"
					"Überprüfen Sie die Schreibweise, oder wählen Sie das Objekt in der Liste aus.", n.text());
				return false;
			}
			if (idx == -2) {
				FXMessageBox::error(this, MBOX_OK, "Mehrere Namen gefunden",
					"Der Name \"%s\" passt auf mehrere Objekte.\n\n"
					"Geben Sie den Namen genauer ein, oder wählen Sie das Objekt in der Liste aus.", n.text());
				return false;
			}
			if (std::find(resolved.begin(), resolved.end(), idx) == resolved.end()) resolved.push_back(idx);
		}
		if (resolved.empty()) return true;

		FXString text;
		std::vector<std::pair<FXint, FXint>> spans;
		for (size_t i = 0; i < resolved.size(); i++) {
			if (i > 0) text += "; ";
			spans.push_back({ text.length(), (*groups)[resolved[i]].cn.length() });
			text += (*groups)[resolved[i]].cn;
		}
		showingHint = false;
		namesText->setText(text);
		for (auto& s : spans) namesText->changeStyle(s.first, s.second, 1);
		namesText->setCursorPos(text.length());
		return true;
	}

	long onAdd(FXObject*, FXSelector, void*) {
		FXString add;
		for (FXint i = 0; i < groupList->getNumItems(); i++) {
			if (!groupList->isItemSelected(i)) continue;
			if (!add.empty()) add += "; ";
			add += (*groups)[i].cn;
		}
		if (add.empty()) return 1;
		leaveHint();
		FXString cur = namesText->getText();
		cur.trimEnd();
		if (!cur.empty() && cur.right(1) != ";") cur += "; ";
		else if (!cur.empty()) cur += " ";
		namesText->setText(cur + add);
		std::vector<int> dummy;
		checkNames(dummy, true);
		return 1;
	}

	long onUpdAdd(FXObject* sender, FXSelector, void*) {
		bool any = false;
		for (FXint i = 0; i < groupList->getNumItems() && !any; i++) any = groupList->isItemSelected(i);
		sender->handle(this, FXSEL(SEL_COMMAND, any ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}

	long onUpdNeedsText(FXObject* sender, FXSelector, void*) {
		FXString t = enteredText();
		t.trim();
		sender->handle(this, FXSEL(SEL_COMMAND, t.empty() ? ID_DISABLE : ID_ENABLE), NULL);
		return 1;
	}

	long onCheckNames(FXObject*, FXSelector, void*) {
		std::vector<int> dummy;
		checkNames(dummy);
		return 1;
	}

	long onListDoubleClick(FXObject*, FXSelector, void*) {
		return onAdd(NULL, 0, NULL);
	}

	// Klick ins Feld, solange der Hinweis steht: Hinweis weg, dann normal
	// weiter (return 0 laesst FXText den Klick selbst verarbeiten).
	long onNamesClick(FXObject*, FXSelector, void*) {
		leaveHint();
		return 0;
	}

	// Tippen ersetzt den markierten Hinweis ohnehin -- danach nur noch
	// den Merker zuruecksetzen.
	long onNamesChanged(FXObject*, FXSelector, void*) {
		if (showingHint && namesText->getText() != GROUP_PICKER_HINT) showingHint = false;
		return 1;
	}

	long onOk(FXObject*, FXSelector, void*) {
		std::vector<int> resolved;
		if (!checkNames(resolved)) return 1;
		result = resolved;
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}

	const std::vector<int>& getResult() const { return result; }
	virtual ~GroupPickerDialog() {}
};
FXDEFMAP(GroupPickerDialog) GroupPickerDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, GroupPickerDialog::ID_ADD, GroupPickerDialog::onAdd),
	FXMAPFUNC(SEL_UPDATE, GroupPickerDialog::ID_ADD, GroupPickerDialog::onUpdAdd),
	FXMAPFUNC(SEL_COMMAND, GroupPickerDialog::ID_CHECK_NAMES, GroupPickerDialog::onCheckNames),
	FXMAPFUNC(SEL_UPDATE, GroupPickerDialog::ID_CHECK_NAMES, GroupPickerDialog::onUpdNeedsText),
	FXMAPFUNC(SEL_UPDATE, GroupPickerDialog::ID_OK, GroupPickerDialog::onUpdNeedsText),
	FXMAPFUNC(SEL_COMMAND, GroupPickerDialog::ID_OK, GroupPickerDialog::onOk),
	FXMAPFUNC(SEL_DOUBLECLICKED, GroupPickerDialog::ID_GROUPLIST, GroupPickerDialog::onListDoubleClick),
	FXMAPFUNC(SEL_LEFTBUTTONPRESS, GroupPickerDialog::ID_NAMES, GroupPickerDialog::onNamesClick),
	FXMAPFUNC(SEL_CHANGED, GroupPickerDialog::ID_NAMES, GroupPickerDialog::onNamesChanged),
};
FXIMPLEMENT(GroupPickerDialog, FXDialogBox, GroupPickerDialogMap, ARRAYNUMBER(GroupPickerDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" eines Benutzers -- mit Reitern wie im
// Original. Umgesetzt sind "Allgemein", "Konto" und "Mitglied von";
// alle Aenderungen werden erst mit OK/Übernehmen geschrieben.
// ---------------------------------------------------------------------
class UserPropertiesDialog : public FXDialogBox {
	FXDECLARE(UserPropertiesDialog)
private:
	DomainInfo domain;
	FXString accountName;
	FXString userFullDN;

	// Allgemein
	struct AttrField { const char* attr; FXTextField* field; FXString orig; };
	std::vector<AttrField> attrFields;

	// Konto
	FXCheckButton* disabledCheck = nullptr;
	bool origDisabled = false;

	// Mitglied von
	FXIconList* memberList = nullptr;
	FXLabel* primaryLabel = nullptr;
	std::vector<GroupEntry> allGroups;
	std::vector<std::string> origMemberDns, memberDns;
	std::string origPrimaryDn, primaryDn;

protected:
	UserPropertiesDialog() {}
public:
	enum { ID_MEMBER_ADD = FXDialogBox::ID_LAST, ID_MEMBER_REMOVE, ID_SET_PRIMARY, ID_APPLY, ID_OK };

	UserPropertiesDialog(FXWindow* owner, const DomainInfo& domain_, const DirObject& obj)
		: FXDialogBox(owner, "Eigenschaften von " + obj.name, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,430,480),
		  domain(domain_), accountName(obj.accountName) {
		userFullDN = obj.dn.empty() ? domain.baseDN : obj.dn + "," + domain.baseDN;

		std::string raw;
		runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("show"), accountName }, raw);
		auto rec = parseLdifRecord(raw);
		long uac = 0;
		try { uac = std::stol(ldifFirst(rec, "userAccountControl")); } catch (...) {}
		origDisabled = (uac & 0x2) != 0; // UF_ACCOUNTDISABLE

		FXString errorMsg;
		allGroups = listAllGroupsDetailed();
		if (!getUserGroupDns(accountName, origMemberDns, origPrimaryDn, errorMsg)) {
			FXMessageBox::error(owner, MBOX_OK, "Fehler", "Die Gruppenmitgliedschaften konnten nicht gelesen werden.\n\n%s", errorMsg.text());
		}
		memberDns = origMemberDns;
		primaryDn = origPrimaryDn;

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		buildGeneralTab(tabs, obj, rec);
		buildAccountTab(tabs, rec);
		buildMemberOfTab(tabs);

		// Reihenfolge wie im Original: OK, Abbrechen, Übernehmen -- rechtsbuendig.
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		const FXuint bstyle = BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH;
		new FXButton(btnf, "OK", NULL, this, ID_OK, bstyle | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, bstyle, 0,0,88,0, 4,4,3,3);
		(new FXButton(btnf, "Ü&bernehmen", NULL, this, ID_APPLY, bstyle, 0,0,88,0, 4,4,3,3))->disable(); // bis zur ersten Aenderung grau

		reloadMemberList();
	}

	// ---- Allgemein ---------------------------------------------------
	FXTextField* addAttrRow(FXComposite* parent, const char* label, const char* attr,
	                        const std::multimap<std::string, std::string>& rec) {
		FXHorizontalFrame* row = new FXHorizontalFrame(parent, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(row, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,96,0);
		FXTextField* tf = new FXTextField(row, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		FXString v = ldifFirst(rec, attr).c_str();
		tf->setText(v);
		attrFields.push_back({ attr, tf, v });
		return tf;
	}

	void buildGeneralTab(FXTabBook* tabs, const DirObject& obj, const std::multimap<std::string, std::string>& rec) {
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,5);

		FXHorizontalFrame* head = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
		new FXLabel(head, "", sharedPngIcon(resico_user), LAYOUT_CENTER_Y);
		new FXLabel(head, obj.name, NULL, LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		// Vorname und Initialen stehen im Original in einer Zeile.
		FXHorizontalFrame* row = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(row, "&Vorname:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,96,0);
		FXTextField* given = new FXTextField(row, 14, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		FXString gv = ldifFirst(rec, "givenName").c_str();
		given->setText(gv);
		attrFields.push_back({ "givenName", given, gv });
		new FXLabel(row, "&Initialen:", NULL, LAYOUT_CENTER_Y);
		FXTextField* initials = new FXTextField(row, 4, NULL, 0, FRAME_SUNKEN | FRAME_THICK);
		initials->setNumColumns(4);
		FXString iv = ldifFirst(rec, "initials").c_str();
		initials->setText(iv);
		attrFields.push_back({ "initials", initials, iv });

		addAttrRow(page, "&Nachname:", "sn", rec);
		addAttrRow(page, "Anzei&gename:", "displayName", rec);
		addAttrRow(page, "&Beschreibung:", "description", rec);
		addAttrRow(page, "Bü&ro:", "physicalDeliveryOfficeName", rec);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		addAttrRow(page, "&Rufnummer:", "telephoneNumber", rec);
		addAttrRow(page, "&E-Mail:", "mail", rec);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		addAttrRow(page, "&Webseite:", "wWWHomePage", rec);
	}

	// ---- Konto -------------------------------------------------------
	void buildAccountTab(FXTabBook* tabs, const std::multimap<std::string, std::string>& rec) {
		new FXTabItem(tabs, "Konto", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,5);

		FXString upn = ldifFirst(rec, "userPrincipalName").c_str();
		FXString lowerRealm = domain.realm; lowerRealm.lower();
		if (upn.empty()) upn = accountName + "@" + lowerRealm;
		new FXLabel(page, "Benutzeranmeldename:");
		FXTextField* upnField = new FXTextField(page, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_READONLY);
		upnField->setText(upn);

		std::string conf = readFileUnprivileged("/etc/samba/smb.conf");
		FXString netbios = smbConfValue(conf, "workgroup");
		netbios.upper();
		new FXLabel(page, "Benutzeranmeldename (Prä-Windows 2000):");
		FXTextField* samField = new FXTextField(page, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_READONLY);
		samField->setText(netbios + "\\" + accountName);

		FXGroupBox* opts = new FXGroupBox(page, "Kontooptionen", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 8,8,6,8);
		disabledCheck = new FXCheckButton(opts, "Konto ist &deaktiviert");
		disabledCheck->setCheck(origDisabled);
	}

	// ---- Mitglied von ------------------------------------------------
	void buildMemberOfTab(FXTabBook* tabs) {
		new FXTabItem(tabs, "Mitglied von", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,5);

		new FXLabel(page, "&Mitglied von:");
		FXPacker* listFrame = new FXPacker(page, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		memberList = new FXIconList(listFrame, NULL, 0, ICONLIST_DETAILED | ICONLIST_EXTENDEDSELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		memberList->appendHeader("Name", NULL, 140);
		memberList->appendHeader("Active Directory-Ordner", NULL, 230);

		FXHorizontalFrame* btns = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXButton(btns, "Hin&zufügen...", NULL, this, ID_MEMBER_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "En&tfernen", NULL, this, ID_MEMBER_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);

		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		FXHorizontalFrame* prim = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXLabel(prim, "Primäre Gruppe:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,110,0);
		primaryLabel = new FXLabel(prim, "", NULL, LAYOUT_CENTER_Y | JUSTIFY_LEFT);

		FXHorizontalFrame* primBtn = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,0);
		new FXButton(primBtn, "&Primäre Gruppe festlegen", NULL, this, ID_SET_PRIMARY, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_TOP, 0,0,0,0, 8,8,3,3);
		new FXLabel(primBtn, "Die primäre Gruppe muss nur geändert\nwerden, wenn Sie Macintosh-Clients\noder POSIX-kompatible Anwendungen\nhaben.", NULL, JUSTIFY_LEFT | LAYOUT_TOP);
	}

	GroupEntry groupForDn(const std::string& dn) const {
		int idx = findGroupByDn(allGroups, dn);
		if (idx >= 0) return allGroups[idx];
		GroupEntry g;          // nicht in der Gruppenliste -- aus der DN ableiten
		g.dn = dn;
		g.cn = dnLeafName(dn);
		g.sam = g.cn;
		g.folder = dnToFolder(dn);
		return g;
	}

	void reloadMemberList() {
		memberList->clearItems();
		FXIcon* ic = sharedPngIcon(resico_users);
		for (auto& dn : memberDns) {
			GroupEntry g = groupForDn(dn);
			memberList->appendItem(g.cn + "\t" + g.folder, ic, ic);
		}
		if (!memberDns.empty()) { memberList->setCurrentItem(0); memberList->selectItem(0); }
		primaryLabel->setText(primaryDn.empty() ? FXString("") : groupForDn(primaryDn).cn);
	}

	std::vector<int> selectedMembers() const {
		std::vector<int> out;
		for (FXint i = 0; i < memberList->getNumItems(); i++)
			if (memberList->isItemSelected(i)) out.push_back(i);
		return out;
	}

	static bool sameDn(const std::string& a, const std::string& b) { return lowerCopy(a) == lowerCopy(b); }
	static bool containsDn(const std::vector<std::string>& v, const std::string& dn) {
		for (auto& x : v) if (sameDn(x, dn)) return true;
		return false;
	}

	long onMemberAdd(FXObject*, FXSelector, void*) {
		GroupPickerDialog dlg(this, domain.realm, allGroups);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		for (int idx : dlg.getResult()) {
			const std::string& dn = allGroups[idx].dn;
			if (!containsDn(memberDns, dn)) memberDns.push_back(dn);
		}
		reloadMemberList();
		return 1;
	}

	long onMemberRemove(FXObject*, FXSelector, void*) {
		std::vector<int> sel = selectedMembers();
		if (sel.empty()) return 1;
		for (int i : sel) {
			if (sameDn(memberDns[i], primaryDn)) {
				FXMessageBox::error(this, MBOX_OK, "Active Directory",
					"Die primäre Gruppe kann nicht entfernt werden.\n\n"
					"Legen Sie zuerst eine andere Gruppe als primäre Gruppe fest.");
				return 1;
			}
		}
		if (FXMessageBox::question(this, MBOX_YES_NO, "Active Directory",
		        "Möchten Sie den Benutzer wirklich aus den ausgewählten Gruppen entfernen?") != MBOX_CLICKED_YES) return 1;
		for (auto it = sel.rbegin(); it != sel.rend(); ++it) memberDns.erase(memberDns.begin() + *it);
		reloadMemberList();
		return 1;
	}

	long onUpdMemberRemove(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, selectedMembers().empty() ? ID_DISABLE : ID_ENABLE), NULL);
		return 1;
	}

	// Primaere Gruppe kann nur eine globale oder universelle
	// Sicherheitsgruppe werden -- Domaenen-lokale und vordefinierte
	// (Builtin) Gruppen lehnt AD ab.
	bool canBePrimary(int idx) const {
		if (idx < 0 || idx >= (int)memberDns.size()) return false;
		if (sameDn(memberDns[idx], primaryDn)) return false;
		GroupEntry g = groupForDn(memberDns[idx]);
		return g.security && (g.scope == "Global" || g.scope == "Universal");
	}

	long onUpdSetPrimary(FXObject* sender, FXSelector, void*) {
		std::vector<int> sel = selectedMembers();
		bool ok = sel.size() == 1 && canBePrimary(sel[0]);
		sender->handle(this, FXSEL(SEL_COMMAND, ok ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}

	long onSetPrimary(FXObject*, FXSelector, void*) {
		std::vector<int> sel = selectedMembers();
		if (sel.size() != 1 || !canBePrimary(sel[0])) return 1;
		primaryDn = memberDns[sel[0]];
		primaryLabel->setText(groupForDn(primaryDn).cn);
		return 1;
	}

	// ---- Uebernehmen -------------------------------------------------
	bool isDirty() const {
		for (auto& f : attrFields) if (f.field->getText() != f.orig) return true;
		if (disabledCheck->getCheck() != origDisabled) return true;
		if (!sameDn(primaryDn, origPrimaryDn)) return true;
		if (memberDns.size() != origMemberDns.size()) return true;
		for (auto& dn : memberDns) if (!containsDn(origMemberDns, dn)) return true;
		return false;
	}

	long onUpdApply(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, isDirty() ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}

	bool apply() {
		FXString errorMsg;

		// Allgemein -- nur tatsaechlich geaenderte Attribute schreiben; ein
		// geleertes Feld entfernt das Attribut (ein leerer Wert waere in AD
		// ein Syntaxfehler).
		std::string ldif;
		for (auto& f : attrFields) {
			FXString v = f.field->getText();
			v.trim();
			FXString o = f.orig;
			o.trim();
			if (v == o) continue;
			ldif += std::string("replace: ") + f.attr + "\n";
			if (!v.empty()) ldif += ldifAttrLine(f.attr, v.text());
			ldif += "-\n";
		}
		if (!ldif.empty()) {
			ldif = "dn: " + std::string(userFullDN.text()) + "\nchangetype: modify\n" + ldif;
			std::string log;
			if (!runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) {
				FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
				return false;
			}
			for (auto& f : attrFields) { FXString v = f.field->getText(); v.trim(); f.field->setText(v); f.orig = v; }
		}

		// Konto
		if (disabledCheck->getCheck() != origDisabled) {
			if (!setUserEnabled(accountName, !disabledCheck->getCheck(), errorMsg)) {
				FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
				return false;
			}
			origDisabled = disabledCheck->getCheck();
		}

		// Mitglied von -- Reihenfolge ist wichtig: erst hinzufuegen (eine
		// neue primaere Gruppe muss schon Mitglied sein), dann die primaere
		// Gruppe umstellen, zuletzt entfernen.
		bool membershipChanged = false;
		for (auto& dn : memberDns) {
			if (containsDn(origMemberDns, dn)) continue;
			GroupEntry g = groupForDn(dn);
			if (!addGroupMember(this, g.sam, accountName, errorMsg)) {
				FXMessageBox::error(this, MBOX_OK, "Fehler", "\"%s\" konnte nicht zur Gruppe \"%s\" hinzugefügt werden.\n\n%s",
				                    accountName.text(), g.cn.text(), errorMsg.text());
				resyncMembership();
				return false;
			}
			membershipChanged = true;
		}
		if (!sameDn(primaryDn, origPrimaryDn)) {
			GroupEntry g = groupForDn(primaryDn);
			if (!setUserPrimaryGroup(this, accountName, g.sam, errorMsg)) {
				FXMessageBox::error(this, MBOX_OK, "Fehler", "Die primäre Gruppe konnte nicht auf \"%s\" gesetzt werden.\n\n%s",
				                    g.cn.text(), errorMsg.text());
				resyncMembership();
				return false;
			}
			membershipChanged = true;
		}
		for (auto& dn : origMemberDns) {
			if (containsDn(memberDns, dn)) continue;
			// Die bisherige primaere Gruppe fuehrt AD beim Umstellen selbst
			// als normale Mitgliedschaft weiter -- wurde sie im Dialog
			// entfernt, jetzt ebenfalls entfernen.
			GroupEntry g = groupForDn(dn);
			if (!removeGroupMember(this, g.sam, accountName, errorMsg)) {
				FXMessageBox::error(this, MBOX_OK, "Fehler", "\"%s\" konnte nicht aus der Gruppe \"%s\" entfernt werden.\n\n%s",
				                    accountName.text(), g.cn.text(), errorMsg.text());
				resyncMembership();
				return false;
			}
			membershipChanged = true;
		}
		if (membershipChanged) resyncMembership();
		return true;
	}

	// Nach dem Schreiben (oder einem Teilfehler) den echten Stand aus AD
	// holen -- beim Wechsel der primaeren Gruppe ergaenzt AD die
	// bisherige primaere Gruppe z.B. selbst als normale Mitgliedschaft.
	void resyncMembership() {
		FXString errorMsg;
		std::vector<std::string> dns;
		std::string prim;
		if (getUserGroupDns(accountName, dns, prim, errorMsg)) {
			origMemberDns = memberDns = dns;
			origPrimaryDn = primaryDn = prim;
		}
		reloadMemberList();
	}

	long onApply(FXObject*, FXSelector, void*) {
		apply();
		return 1;
	}

	long onOk(FXObject*, FXSelector, void*) {
		if (isDirty() && !apply()) return 1;
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}

	virtual ~UserPropertiesDialog() {}
};
FXDEFMAP(UserPropertiesDialog) UserPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, UserPropertiesDialog::ID_MEMBER_ADD, UserPropertiesDialog::onMemberAdd),
	FXMAPFUNC(SEL_COMMAND, UserPropertiesDialog::ID_MEMBER_REMOVE, UserPropertiesDialog::onMemberRemove),
	FXMAPFUNC(SEL_UPDATE, UserPropertiesDialog::ID_MEMBER_REMOVE, UserPropertiesDialog::onUpdMemberRemove),
	FXMAPFUNC(SEL_COMMAND, UserPropertiesDialog::ID_SET_PRIMARY, UserPropertiesDialog::onSetPrimary),
	FXMAPFUNC(SEL_UPDATE, UserPropertiesDialog::ID_SET_PRIMARY, UserPropertiesDialog::onUpdSetPrimary),
	FXMAPFUNC(SEL_COMMAND, UserPropertiesDialog::ID_APPLY, UserPropertiesDialog::onApply),
	FXMAPFUNC(SEL_UPDATE, UserPropertiesDialog::ID_APPLY, UserPropertiesDialog::onUpdApply),
	FXMAPFUNC(SEL_COMMAND, UserPropertiesDialog::ID_OK, UserPropertiesDialog::onOk),
};
FXIMPLEMENT(UserPropertiesDialog, FXDialogBox, UserPropertiesDialogMap, ARRAYNUMBER(UserPropertiesDialogMap))

// ---------------------------------------------------------------------
// Dialog "Neuer Computer" -- analog zu Benutzer/Gruppe/OU.
// ---------------------------------------------------------------------
class NewComputerDialog : public FXDialogBox {
	FXDECLARE(NewComputerDialog)
private:
	FXTextField* nameField;
protected:
	NewComputerDialog() {}
public:
	NewComputerDialog(FXWindow* owner)
		: FXDialogBox(owner, "Neuer Computer", DECOR_TITLE | DECOR_BORDER, 0,0,360,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Computername:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getName() const { return nameField->getText(); }
	virtual ~NewComputerDialog() {}
};
FXIMPLEMENT(NewComputerDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Verschieben nach" -- einfache Liste aller Organisations-
// einheiten der Domaene zur Auswahl des Ziels.
// ---------------------------------------------------------------------
class MoveObjectDialog : public FXDialogBox {
	FXDECLARE(MoveObjectDialog)
private:
	FXList* ouList;
	std::vector<std::pair<FXString, FXString>> ous;
protected:
	MoveObjectDialog() {}
public:
	MoveObjectDialog(FXWindow* owner, const FXString& objectName, const FXString& domainRootLabel)
		: FXDialogBox(owner, "Verschieben von " + objectName, DECOR_TITLE | DECOR_BORDER, 0,0,420,380) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Ziel-Organisationseinheit auswählen:");
		ouList = new FXList(main, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		ouList->appendItem(domainRootLabel); // Domaenenwurzel selbst als Ziel moeglich
		ous.push_back({ "", "" }); // Platzhalter fuer die Wurzel -- volle DN wird vom Aufrufer aufgeloest
		for (auto& ou : listAllOUsWithPaths()) {
			ouList->appendItem(ou.second);
			ous.push_back(ou);
		}
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Verschieben", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	// Leerer String = Domaenenwurzel (der Aufrufer muss das erkennen und
	// domain.baseDN selbst einsetzen).
	FXString getTargetFullDN() const {
		int idx = ouList->getCurrentItem();
		if (idx < 0 || idx >= (int)ous.size()) return "";
		return ous[idx].first;
	}
	virtual ~MoveObjectDialog() {}
};
FXIMPLEMENT(MoveObjectDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer einzelnen Richtlinie -- Nicht
// konfiguriert/Aktiviert/Deaktiviert plus (falls vorhanden) das
// Eingabefeld des ersten Parts. Mehrere Parts pro Richtlinie werden in
// dieser ersten Version noch nicht unterstuetzt (in der Praxis haben
// die meisten Richtlinien hoechstens einen Part).
// ---------------------------------------------------------------------
// Ein Eingabe-Widget pro Part einer Richtlinie (mehrere Parts moeglich).
struct PartWidget {
	FXCheckButton* checkbox = NULL;
	FXTextField* textField = NULL;
	FXComboBox* combo = NULL;
	std::vector<AdmItem> comboItems;
};

class PolicyEditDialog : public FXDialogBox {
	FXDECLARE(PolicyEditDialog)
private:
	const AdmPolicy* policy;
	FXint stateVar = 0; // 0=Nicht konfiguriert, 1=Aktiviert, 2=Deaktiviert
	FXDataTarget* stateTarget = NULL;
	std::vector<PartWidget> partWidgets;
protected:
	PolicyEditDialog() {}
public:
	enum { ID_STATE = FXDialogBox::ID_LAST };
	long onStateChanged(FXObject*, FXSelector, void*) {
		bool enabled = (stateVar == 1);
		for (auto& pw : partWidgets) {
			if (pw.checkbox) enabled ? pw.checkbox->enable() : pw.checkbox->disable();
			if (pw.textField) enabled ? pw.textField->enable() : pw.textField->disable();
			if (pw.combo) enabled ? pw.combo->enable() : pw.combo->disable();
		}
		return 1;
	}

	PolicyEditDialog(FXWindow* owner, const AdmPolicy& pol, PolicyState initialState, const std::vector<std::string>& initialPartValues)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + pol.label.c_str(), DECOR_TITLE | DECOR_BORDER, 0,0,440,0),
		  policy(&pol) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, pol.label.c_str(), NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		FXText* explainText = new FXText(main, NULL, 0, TEXT_READONLY | FRAME_SUNKEN | LAYOUT_FILL_X, 0,0,0,70);
		explainText->setText(pol.explainText.c_str());

		stateVar = (initialState == POLSTATE_ENABLED) ? 1 : (initialState == POLSTATE_DISABLED) ? 2 : 0;
		stateTarget = new FXDataTarget(stateVar, this, ID_STATE);
		FXGroupBox* group = new FXGroupBox(main, "", GROUPBOX_NORMAL | FRAME_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* radioFrame = new FXVerticalFrame(group, LAYOUT_FILL_X);
		new FXRadioButton(radioFrame, "&Nicht konfiguriert", stateTarget, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(radioFrame, "&Aktiviert", stateTarget, FXDataTarget::ID_OPTION + 1);
		new FXRadioButton(radioFrame, "&Deaktiviert", stateTarget, FXDataTarget::ID_OPTION + 2);

		FXVerticalFrame* dynamicArea = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 20,0,4,4);
		for (size_t i = 0; i < pol.parts.size(); i++) {
			auto& part = pol.parts[i];
			std::string initVal = i < initialPartValues.size() ? initialPartValues[i] : "";
			PartWidget pw;
			switch (part.type) {
				case ADMPART_CHECKBOX:
					pw.checkbox = new FXCheckButton(dynamicArea, part.label.c_str());
					if (initVal == "1") pw.checkbox->setCheck(true);
					break;
				case ADMPART_EDITTEXT:
					new FXLabel(dynamicArea, part.label.c_str());
					pw.textField = new FXTextField(dynamicArea, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
					pw.textField->setText((!initVal.empty() ? initVal : part.defaultValue).c_str());
					break;
				case ADMPART_NUMERIC:
					new FXLabel(dynamicArea, part.label.c_str());
					pw.textField = new FXTextField(dynamicArea, 10, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
					pw.textField->setText((!initVal.empty() ? initVal : part.defaultValue).c_str());
					break;
				case ADMPART_DROPDOWNLIST:
				case ADMPART_COMBOBOX:
					new FXLabel(dynamicArea, part.label.c_str());
					pw.combo = new FXComboBox(dynamicArea, 20, NULL, 0, COMBOBOX_STATIC | FRAME_SUNKEN | LAYOUT_FILL_X);
					pw.comboItems = part.items;
					for (size_t j = 0; j < part.items.size(); j++) {
						pw.combo->appendItem(part.items[j].label.c_str());
						if (part.items[j].value == initVal) pw.combo->setCurrentItem((FXint)j);
					}
					break;
				default: break;
			}
			partWidgets.push_back(pw);
		}

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

		onStateChanged(NULL, 0, NULL);
	}

	PolicyState getState() const {
		return stateVar == 1 ? POLSTATE_ENABLED : stateVar == 2 ? POLSTATE_DISABLED : POLSTATE_NOT_CONFIGURED;
	}
	// Liefert die aktuellen Werte aller Parts, parallel zu pol.parts.
	std::vector<std::string> getPartValues() const {
		std::vector<std::string> out;
		for (auto& pw : partWidgets) {
			if (pw.checkbox) out.push_back(pw.checkbox->getCheck() ? "1" : "0");
			else if (pw.textField) out.push_back(pw.textField->getText().text());
			else if (pw.combo) {
				int idx = pw.combo->getCurrentItem();
				out.push_back((idx >= 0 && idx < (int)pw.comboItems.size()) ? pw.comboItems[idx].value : "");
			} else out.push_back("");
		}
		return out;
	}
	virtual ~PolicyEditDialog() { delete stateTarget; }
};
FXDEFMAP(PolicyEditDialog) PolicyEditDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, PolicyEditDialog::ID_STATE, PolicyEditDialog::onStateChanged),
};
FXIMPLEMENT(PolicyEditDialog, FXDialogBox, PolicyEditDialogMap, ARRAYNUMBER(PolicyEditDialogMap))

// ---------------------------------------------------------------------
// Schreibt die GPT.INI mit einem VORGEGEBENEN Versionswert. Der Wert
// wird nicht mehr hier ermittelt, sondern aus dem AD-Attribut
// versionNumber abgeleitet -- beide Stellen muessen uebereinstimmen,
// sonst haelt ein echter Client das GPO fuer widerspruechlich.
// Format der Zahl: oberes Halbwort = Benutzer-Version, unteres Halbwort
// = Computer-Version.
// ---------------------------------------------------------------------
static void writeGptIniVersion(const std::string& gptIniPath, uint32_t newVersion) {
	std::string newContent = "[General]\r\nVersion=" + std::to_string(newVersion) + "\r\n";

	FXString tmpPath = "/tmp/ice2k-gptini-tmp";
	std::ofstream out(tmpPath.text());
	out << newContent;
	out.close();
	runAsRoot({ FXString("cp"), tmpPath, FXString(gptIniPath.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });

	// "cp" als root setzt Besitzer und Modus der Zieldatei neu und laesst
	// die NT-ACL fallen -- danach gehoert die GPT.INI root statt den
	// Domaenen-Administratoren. Deshalb die Rechte des GPO-Verzeichnisses
	// wieder uebernehmen, wie bei der .aas-Datei auch.
	size_t slash = gptIniPath.find_last_of('/');
	if (slash != std::string::npos)
		inheritSysvolPermissions(gptIniPath.substr(0, slash), gptIniPath, false);
}

// ---------------------------------------------------------------------
// Gruppenrichtlinienobjekt-Editor: Baum links (Kategorien der
// zusammengefuehrten ADM-Dateien), Liste rechts (Richtlinien der
// gewaehlten Kategorie mit Status). Doppelklick oeffnet
// PolicyEditDialog; "Speichern" schreibt die Aenderungen in die
// Registry.pol des GPOs und erhoeht die GPT.INI-Version.
// ---------------------------------------------------------------------
struct PendingEdit { PolicyState state; std::vector<std::string> partValues; std::string effectiveKey; };

// Ein "Registrierungszweig" (Computer- oder Benutzerkonfiguration) mit
// eigener Registry.pol-Datei und eigenem ADM-Kategorienbaum.
struct PolHive {
	std::vector<AdmCategory> categories;
	RegPolFile file;
	RegLookup lookup;
	std::string polPath;
};

static const char* REGISTRY_CSE_GUID = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}";
static const char* REGISTRY_TOOL_GUID_MACHINE = "{0F6B957D-509E-11D1-A7CC-0000F87571E3}";
static const char* REGISTRY_TOOL_GUID_USER = "{0F6B957E-509E-11D1-A7CC-0000F87571E3}";

static const char* admStateLabel(PolicyState st) {
	return st == POLSTATE_ENABLED ? "Aktiviert" : st == POLSTATE_DISABLED ? "Deaktiviert" : "Nicht konfiguriert";
}

// Aktuell in der Registry.pol gespeicherter Wert eines Parts (fuer die
// Vorbelegung des Bearbeiten-Dialogs).
static std::string readStoredPartValue(const PolHive& hive, const std::string& key, const std::string& vn) {
	auto it = hive.lookup.values.find({ lowerCopy(key), lowerCopy(vn) });
	if (it == hive.lookup.values.end()) return "";
	if (it->second.type == REG_TYPE_DWORD && it->second.data.size() >= 4) {
		uint32_t v = (uint32_t)it->second.data[0] | ((uint32_t)it->second.data[1] << 8)
		           | ((uint32_t)it->second.data[2] << 16) | ((uint32_t)it->second.data[3] << 24);
		return std::to_string(v);
	} else if (it->second.type == REG_TYPE_SZ) {
		return std::string((const char*)it->second.data.data(), it->second.data.size());
	}
	return "";
}

// Wendet eine Richtlinienaenderung auf die Eintraege einer Registry.pol
// an: alte Werte der Richtlinie entfernen, neue anhaengen bzw. bei
// Deaktiviert/Nicht konfiguriert vorher gesetzte Parts aktiv loeschen.
static void applyAdmPolicyEdit(std::vector<RegPolEntry>& finalEntries, const RegLookup& lookup,
                               const AdmPolicy* pol, const PendingEdit& ed) {
	auto removeEntry = [&](const std::string& key, const std::string& valuename) {
		std::string lk = lowerCopy(key), lv = lowerCopy(valuename);
		finalEntries.erase(std::remove_if(finalEntries.begin(), finalEntries.end(), [&](const RegPolEntry& e) {
			return lowerCopy(e.key) == lk && lowerCopy(e.valuename) == lv;
		}), finalEntries.end());
	};
	std::string key = ed.effectiveKey;
	if (pol->hasValueOnOff) {
		removeEntry(key, pol->valuename);
		if (ed.state == POLSTATE_ENABLED) {
			uint32_t v = 0; try { v = (uint32_t)std::stol(pol->valueOn.empty() ? "1" : pol->valueOn); } catch (...) {}
			finalEntries.push_back(makeRegDwordEntry(key, pol->valuename, v));
		} else if (ed.state == POLSTATE_DISABLED) {
			uint32_t v = 0; try { v = (uint32_t)std::stol(pol->valueOff.empty() ? "0" : pol->valueOff); } catch (...) {}
			finalEntries.push_back(makeRegDwordEntry(key, pol->valuename, v));
		}
		// POLSTATE_NOT_CONFIGURED: Zeile bleibt entfernt, keine neue.
	}
	for (size_t i = 0; i < pol->parts.size(); i++) {
		auto& part = pol->parts[i];
		std::string vn = !part.valuename.empty() ? part.valuename : pol->valuename;
		std::string pv = i < ed.partValues.size() ? ed.partValues[i] : "";
		removeEntry(key, vn);
		removeEntry(key, "**del." + vn);
		bool wasConfigured = lookup.values.count({ lowerCopy(key), lowerCopy(vn) }) > 0;
		if (ed.state == POLSTATE_ENABLED) {
			switch (part.type) {
				case ADMPART_CHECKBOX:
				case ADMPART_NUMERIC: {
					uint32_t v = 0; try { v = (uint32_t)std::stol(pv.empty() ? "0" : pv); } catch (...) {}
					finalEntries.push_back(makeRegDwordEntry(key, vn, v));
					break;
				}
				case ADMPART_EDITTEXT:
					finalEntries.push_back(makeRegSzEntry(key, vn, pv));
					break;
				case ADMPART_DROPDOWNLIST:
				case ADMPART_COMBOBOX: {
					bool isNum = false;
					for (auto& it2 : part.items) if (it2.value == pv) isNum = it2.isNumeric;
					if (isNum) {
						uint32_t v = 0; try { v = (uint32_t)std::stol(pv.empty() ? "0" : pv); } catch (...) {}
						finalEntries.push_back(makeRegDwordEntry(key, vn, v));
					} else {
						finalEntries.push_back(makeRegSzEntry(key, vn, pv));
					}
					break;
				}
				default: break;
			}
		} else if (wasConfigured) {
			// Deaktiviert ODER (wieder) Nicht konfiguriert, aber vorher
			// gesetzt -- aktiv loeschen, damit ein Client den Wert
			// tatsaechlich entfernt statt ihn stehen zu lassen.
			finalEntries.push_back(makeDeleteValueEntry(key, vn));
		}
	}
}

// Registry.pol als root lesen -- im SYSVOL darf der angemeldete Benutzer
// in der Regel nicht lesen. Fehlende Datei = leer.
static RegPolFile readRegPolAsRoot(const std::string& path) {
	std::string raw;
	if (runAsRootCaptured({ FXString("cat"), FXString(path.c_str()) }, raw) != 0) return RegPolFile();
	const char* tmp = "/tmp/ice2k-regpol-read";
	{
		std::ofstream out(tmp, std::ios::binary);
		out.write(raw.data(), (std::streamsize)raw.size());
	}
	RegPolFile f = parseRegPolFile(tmp);
	unlink(tmp);
	return f;
}

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" von Domäne/OU -- mit dem "Gruppenrichtlinie"-
// Reiter (Original-Vorbild: Screenshot des Nutzers). Der eigentliche
// Editor der Administrativen Vorlagen ist ein eigener, spaeterer
// Baustein -- hier nur Verknuepfen/Loesen/Anlegen von GPOs.
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Dialog zum Hinzufuegen eines Softwareinstallations-Pakets --
// minimale erste Version: lokaler Pfad (zum Lesen der .msi-Metadaten)
// + UNC-Pfad (wie ein Client zugreift) + Zuweisen/Veroeffentlichen.
// ---------------------------------------------------------------------
// Sucht in der smb.conf eine Freigabe, unter deren "path" die gewaehlte
// Datei liegt, und baut daraus den UNC-Pfad. Liefert "" wenn keine
// passende Freigabe existiert -- dann muss der Benutzer selbst wissen,
// wie die Clients an die Datei kommen.
static FXString suggestUncPath(const FXString& localFile) {
	std::string conf = readFileUnprivileged("/etc/samba/smb.conf");
	if (conf.empty()) return "";

	char host[256] = { 0 };
	if (gethostname(host, sizeof(host) - 1) != 0) return "";
	FXString shortHost = FXString(host).section('.', 0);

	FXString bestShare, bestPath;
	FXString currentShare;
	std::istringstream iss(conf);
	std::string line;
	while (std::getline(iss, line)) {
		FXString l = line.c_str();
		l.trim();
		if (l.left(1) == "[" && l.right(1) == "]") {
			currentShare = l.mid(1, l.length() - 2);
			continue;
		}
		if (currentShare.empty()) continue;
		FXint eq = l.find('=');
		if (eq < 0) continue;
		FXString key = l.left(eq); key.trim(); key.lower();
		if (key != "path") continue;
		FXString val = l.mid(eq + 1, l.length() - eq - 1); val.trim();
		if (val.empty()) continue;

		// Passt der Anfang, und zwar an einer Verzeichnisgrenze?
		if (localFile.left(val.length()) != val) continue;
		if (localFile.length() > val.length() && localFile[val.length()] != '/' && val.right(1) != "/") continue;
		// Die laengste passende Freigabe gewinnt (verschachtelte Pfade).
		if (val.length() > bestPath.length()) { bestPath = val; bestShare = currentShare; }
	}
	if (bestShare.empty()) return "";

	FXString rest = localFile.mid(bestPath.length(), localFile.length() - bestPath.length());
	while (rest.left(1) == "/") rest = rest.mid(1, rest.length() - 1);
	rest.substitute('/', '\\', true);
	return FXString("\\\\") + shortHost + "\\" + bestShare + (rest.empty() ? FXString("") : FXString("\\") + rest);
}

class SoftwareInstallDialog : public FXDialogBox {
	FXDECLARE(SoftwareInstallDialog)
private:
	FXTextField *localPathField, *uncPathField;
	FXint modeVar = 0; // 0=Computer zuweisen, 1=Benutzer zuweisen, 2=Benutzer veroeffentlichen
	FXDataTarget* modeTarget = NULL;
protected:
	SoftwareInstallDialog() {}
public:
	enum { ID_BROWSE = FXDialogBox::ID_LAST };
	long onBrowse(FXObject*, FXSelector, void*) {
		// Dort weitersuchen, wo der Benutzer zuletzt war: eingetippter
		// Pfad vor Freigabenverzeichnis vor Home.
		FXString start = localPathField->getText();
		if (!start.empty()) {
			start = FXPath::directory(start);
			if (!FXStat::isDirectory(start)) start = "";
		}
		if (start.empty() && FXStat::isDirectory("/srv/freigaben")) start = "/srv/freigaben";
		if (start.empty()) start = FXSystem::getHomeDirectory();

		FXString picked = FXFileDialog::getOpenFilename(this, ".msi-Datei auswählen", start,
		                                                 "MSI-Dateien (*.msi)\nAlle Dateien (*)");
		if (picked.empty()) return 1;
		localPathField->setText(picked);

		// Wenn die Datei unter einer bekannten Freigabe liegt, den
		// UNC-Pfad gleich vorschlagen -- das ist die Angabe, die der
		// Client spaeter wirklich benutzt, und sie von Hand zu tippen ist
		// die fehleranfaelligste Stelle des Dialogs.
		if (uncPathField->getText().empty()) {
			FXString unc = suggestUncPath(picked);
			if (!unc.empty()) uncPathField->setText(unc);
		}
		return 1;
	}
	SoftwareInstallDialog(FXWindow* owner)
		: FXDialogBox(owner, "Software installieren", DECOR_TITLE | DECOR_BORDER, 0,0,480,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Lokaler Pfad zur .msi-Datei (zum Lesen der Paketangaben):");
		FXHorizontalFrame* pf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		localPathField = new FXTextField(pf, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXButton(pf, "&Durchsuchen...", NULL, this, ID_BROWSE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXLabel(main, "UNC-Netzwerkpfad, unter dem Clients die Datei erreichen\n(z.B. \\\\server\\freigabe\\pfad\\datei.msi):");
		uncPathField = new FXTextField(main, 40, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		modeTarget = new FXDataTarget(modeVar);
		FXGroupBox* group = new FXGroupBox(main, "Bereitstellungsart", GROUPBOX_NORMAL | FRAME_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* radioFrame = new FXVerticalFrame(group, LAYOUT_FILL_X);
		new FXRadioButton(radioFrame, "Computer zuweisen (Installation beim Hochfahren)", modeTarget, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(radioFrame, "Benutzer zuweisen (Installation bei Anmeldung)", modeTarget, FXDataTarget::ID_OPTION + 1);
		new FXRadioButton(radioFrame, "Benutzer veröffentlichen (in Software-Katalog verfügbar)", modeTarget, FXDataTarget::ID_OPTION + 2);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	SoftwarePackageParams getParams() const {
		SoftwarePackageParams p;
		p.localMsiPath = localPathField->getText().text();
		p.msiUncPath = uncPathField->getText().text();
		p.assignedPerMachine = (modeVar == 0);
		p.published = (modeVar == 2);
		return p;
	}
	virtual ~SoftwareInstallDialog() { delete modeTarget; }
};
// Ohne diese Tabelle laeuft der Klick auf "Durchsuchen..." ins Leere:
// FXIMPLEMENT stand hier mit einer leeren Map, onBrowse war damit toter
// Code.
FXDEFMAP(SoftwareInstallDialog) SoftwareInstallDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, SoftwareInstallDialog::ID_BROWSE, SoftwareInstallDialog::onBrowse),
};
FXIMPLEMENT(SoftwareInstallDialog, FXDialogBox, SoftwareInstallDialogMap, ARRAYNUMBER(SoftwareInstallDialogMap))

// ---------------------------------------------------------------------
// Dialog zur Verwaltung der Softwarepakete eines GPOs -- getrennte
// Listen fuer Computer-/Benutzerkonfiguration, mit Hinzufuegen/
// Entfernen.
// ---------------------------------------------------------------------
class SoftwarePackageListDialog : public FXDialogBox {
	FXDECLARE(SoftwarePackageListDialog)
private:
	DomainInfo domain;
	FXString gpoGuid;
	FXWindow* credOwner; // bereits erstelltes Elternfenster -- fuer Admin-Anmeldedaten-Dialoge, die schon waehrend des eigenen Konstruktors noetig werden koennten
	FXList *machineList, *userList;
	std::vector<SoftwarePackageInfo> machinePkgs, userPkgs;
protected:
	SoftwarePackageListDialog() {}
public:
	enum { ID_ADD_MACHINE = FXDialogBox::ID_LAST, ID_REMOVE_MACHINE, ID_ADD_USER, ID_REMOVE_USER };

	void reload() {
		machineList->clearItems();
		machinePkgs = listSoftwarePackages(credOwner, domain, gpoGuid, true);
		for (auto& p : machinePkgs)
			machineList->appendItem((p.displayName + (p.pendingRemoval ? " (wird deinstalliert)" : " (Zugewiesen)")).c_str());

		userList->clearItems();
		userPkgs = listSoftwarePackages(credOwner, domain, gpoGuid, false);
		for (auto& p : userPkgs)
			userList->appendItem((p.displayName + (p.pendingRemoval ? " (wird deinstalliert)"
			                                     : p.published ? " (Veröffentlicht)" : " (Zugewiesen)")).c_str());
	}

	long onAdd(FXWindow* owner, bool forcedMachine) {
		SoftwareInstallDialog dlg(this);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		SoftwarePackageParams params = dlg.getParams();
		if (params.localMsiPath.empty() || params.msiUncPath.empty()) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte sowohl den lokalen Pfad als auch den UNC-Pfad angeben.");
			return 1;
		}
		std::string log;
		FXString errorMsg;
		if (!addSoftwarePackage(credOwner, domain, gpoGuid, params, log, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s\n\nProtokoll:\n%s", errorMsg.text(), log.c_str());
			return 1;
		}
		reload();
		return 1;
	}
	long onAddMachine(FXObject* o, FXSelector s, void* p) { (void)o; (void)s; (void)p; return onAdd(this, true); }
	long onAddUser(FXObject* o, FXSelector s, void* p) { (void)o; (void)s; (void)p; return onAdd(this, false); }

	long removeSelected(bool isMachine) {
		auto& pkgs = isMachine ? machinePkgs : userPkgs;
		int idx = (isMachine ? machineList : userList)->getCurrentItem();
		if (idx < 0 || idx >= (int)pkgs.size()) return 1;

		// Steht das Paket schon auf "wird deinstalliert", ist die Frage
		// nach der Software auf den Clients hinfaellig -- dann geht es
		// nur noch darum, den Auftrag selbst loszuwerden.
		if (pkgs[idx].pendingRemoval) {
			if (FXMessageBox::question(this, MBOX_YES_NO, "Eintrag löschen",
				"\"%s\" ist bereits zur Deinstallation vorgemerkt.\n\n"
				"Den Auftrag jetzt endgültig aus der Gruppenrichtlinie löschen?\n"
				"Clients, die ihn noch nicht ausgeführt haben, behalten die\n"
				"Anwendung dann.", pkgs[idx].displayName.c_str()) != MBOX_CLICKED_YES) return 1;
			FXString errorMsg;
			if (!deleteSoftwarePackage(credOwner, domain, gpoGuid, isMachine, pkgs[idx], errorMsg))
				FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
			reload();
			return 1;
		}

		RemovePackageDialog dlg(this, pkgs[idx].displayName);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;

		FXString errorMsg;
		std::string log;
		bool ok;
		if (dlg.uninstallFromClients())
			ok = markSoftwarePackageForRemoval(credOwner, domain, gpoGuid, isMachine, pkgs[idx], log, errorMsg);
		else
			ok = deleteSoftwarePackage(credOwner, domain, gpoGuid, isMachine, pkgs[idx], errorMsg);

		if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		reload();
		return 1;
	}
	long onRemoveMachine(FXObject*, FXSelector, void*) { return removeSelected(true); }
	long onRemoveUser(FXObject*, FXSelector, void*) { return removeSelected(false); }

	SoftwarePackageListDialog(FXWindow* owner, const DomainInfo& domain_, const FXString& gpoGuid_)
		: FXDialogBox(owner, "Softwareinstallation", DECOR_ALL, 0,0,520,420),
		  domain(domain_), gpoGuid(gpoGuid_), credOwner(owner) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);

		new FXTabItem(tabs, "Computerkonfiguration");
		FXVerticalFrame* machinePage = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		machineList = new FXList(machinePage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXHorizontalFrame* machineBtns = new FXHorizontalFrame(machinePage, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXButton(machineBtns, "&Hinzufügen...", NULL, this, ID_ADD_MACHINE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(machineBtns, "&Entfernen", NULL, this, ID_REMOVE_MACHINE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		new FXTabItem(tabs, "Benutzerkonfiguration");
		FXVerticalFrame* userPage = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		userList = new FXList(userPage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXHorizontalFrame* userBtns = new FXHorizontalFrame(userPage, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXButton(userBtns, "H&inzufügen...", NULL, this, ID_ADD_USER, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(userBtns, "E&ntfernen", NULL, this, ID_REMOVE_USER, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "Schließen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

		reload();
	}
	virtual ~SoftwarePackageListDialog() {}
};
FXDEFMAP(SoftwarePackageListDialog) SoftwarePackageListDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, SoftwarePackageListDialog::ID_ADD_MACHINE, SoftwarePackageListDialog::onAddMachine),
	FXMAPFUNC(SEL_COMMAND, SoftwarePackageListDialog::ID_REMOVE_MACHINE, SoftwarePackageListDialog::onRemoveMachine),
	FXMAPFUNC(SEL_COMMAND, SoftwarePackageListDialog::ID_ADD_USER, SoftwarePackageListDialog::onAddUser),
	FXMAPFUNC(SEL_COMMAND, SoftwarePackageListDialog::ID_REMOVE_USER, SoftwarePackageListDialog::onRemoveUser),
};
FXIMPLEMENT(SoftwarePackageListDialog, FXDialogBox, SoftwarePackageListDialogMap, ARRAYNUMBER(SoftwarePackageListDialogMap))

// ---------------------------------------------------------------------
// Dialog "Sicherheitseinstellungen" -- Kennwort- und
// Kontosperrungsrichtlinie der Domäne (siehe Erläuterung oben bei
// PasswordPolicy: es gibt in AD nur eine einzige, domainweite
// Ausprägung davon, wie unter echtem Windows 2000/2003).
// ---------------------------------------------------------------------
class SecuritySettingsDialog : public FXDialogBox {
	FXDECLARE(SecuritySettingsDialog)
private:
	FXCheckButton* complexityCheck;
	FXTextField *historyField, *minLenField, *minAgeField, *maxAgeField;
	FXTextField *lockoutThresholdField, *lockoutDurationField, *lockoutWindowField;
protected:
	SecuritySettingsDialog() {}
public:
	SecuritySettingsDialog(FXWindow* owner, const PasswordPolicy& p)
		: FXDialogBox(owner, "Sicherheitseinstellungen", DECOR_TITLE | DECOR_BORDER, 0,0,420,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		FXGroupBox* pwGroup = new FXGroupBox(main, "Kennwortrichtlinie", GROUPBOX_NORMAL | FRAME_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* pwFrame = new FXVerticalFrame(pwGroup, LAYOUT_FILL_X);
		complexityCheck = new FXCheckButton(pwFrame, "Kennwort muss Komplexität entsprechen");
		complexityCheck->setCheck(p.complexity);
		FXMatrix* pwMatrix = new FXMatrix(pwFrame, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X);
		new FXLabel(pwMatrix, "Kennwortchronik (Anzahl):");
		historyField = new FXTextField(pwMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		historyField->setText(FXStringFormat("%d", p.historyLength));
		new FXLabel(pwMatrix, "Minimale Kennwortlänge:");
		minLenField = new FXTextField(pwMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		minLenField->setText(FXStringFormat("%d", p.minPwdLength));
		new FXLabel(pwMatrix, "Minimales Kennwortalter (Tage):");
		minAgeField = new FXTextField(pwMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		minAgeField->setText(FXStringFormat("%d", p.minPwdAgeDays));
		new FXLabel(pwMatrix, "Maximales Kennwortalter (Tage):");
		maxAgeField = new FXTextField(pwMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		maxAgeField->setText(FXStringFormat("%d", p.maxPwdAgeDays));

		FXGroupBox* loGroup = new FXGroupBox(main, "Kontosperrungsrichtlinie", GROUPBOX_NORMAL | FRAME_GROOVE | LAYOUT_FILL_X);
		FXMatrix* loMatrix = new FXMatrix(loGroup, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X);
		new FXLabel(loMatrix, "Kontosperrungsschwelle (0 = nie sperren):");
		lockoutThresholdField = new FXTextField(loMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		lockoutThresholdField->setText(FXStringFormat("%d", p.lockoutThreshold));
		new FXLabel(loMatrix, "Kontosperrdauer (Minuten):");
		lockoutDurationField = new FXTextField(loMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		lockoutDurationField->setText(FXStringFormat("%d", p.lockoutDurationMins));
		new FXLabel(loMatrix, "Zurücksetzungsdauer des Zählers (Minuten):");
		lockoutWindowField = new FXTextField(loMatrix, 6, NULL, 0, FRAME_SUNKEN | TEXTFIELD_INTEGER);
		lockoutWindowField->setText(FXStringFormat("%d", p.lockoutWindowMins));

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	PasswordPolicy getPolicy() const {
		PasswordPolicy p;
		p.complexity = complexityCheck->getCheck();
		try {
			p.historyLength = std::stoi(historyField->getText().text());
			p.minPwdLength = std::stoi(minLenField->getText().text());
			p.minPwdAgeDays = std::stoi(minAgeField->getText().text());
			p.maxPwdAgeDays = std::stoi(maxAgeField->getText().text());
			p.lockoutThreshold = std::stoi(lockoutThresholdField->getText().text());
			p.lockoutDurationMins = std::stoi(lockoutDurationField->getText().text());
			p.lockoutWindowMins = std::stoi(lockoutWindowField->getText().text());
		} catch (...) {}
		return p;
	}
	virtual ~SecuritySettingsDialog() {}
};
FXIMPLEMENT(SecuritySettingsDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Kleiner Dialog zum Hinzufuegen eines Skripts (Pfad + Parameter).
// ---------------------------------------------------------------------
class AddScriptDialog : public FXDialogBox {
	FXDECLARE(AddScriptDialog)
private:
	FXTextField *cmdField, *paramField;
protected:
	AddScriptDialog() {}
public:
	AddScriptDialog(FXWindow* owner, const FXString& title)
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER, 0,0,420,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Skriptname (z.B. \\\\server\\netlogon\\skript.bat):");
		cmdField = new FXTextField(main, 40, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXLabel(main, "Skriptparameter:");
		paramField = new FXTextField(main, 40, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getCmdLine() const { return cmdField->getText(); }
	FXString getParameters() const { return paramField->getText(); }
	virtual ~AddScriptDialog() {}
};
FXIMPLEMENT(AddScriptDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Skripte" -- vier einfache Listen (Start/Herunterfahren fuer
// Computer, Anmelden/Abmelden fuer Benutzer), je Zweig in einer
// eigenen scripts.ini.
// ---------------------------------------------------------------------
class ScriptsDialog : public FXDialogBox {
	FXDECLARE(ScriptsDialog)
private:
	DomainInfo domain;
	FXString gpoGuid;
	std::string machinePath, userPath;
	FXList *startupList, *shutdownList, *logonList, *logoffList;
protected:
	ScriptsDialog() {}
public:
	enum { ID_ADD_STARTUP = FXDialogBox::ID_LAST, ID_REMOVE_STARTUP, ID_ADD_SHUTDOWN, ID_REMOVE_SHUTDOWN,
	       ID_ADD_LOGON, ID_REMOVE_LOGON, ID_ADD_LOGOFF, ID_REMOVE_LOGOFF, ID_SAVE };
	long onSave(FXObject*, FXSelector, void*) {
		if (saveAll()) {
			FXMessageBox::information(this, MBOX_OK, "Gespeichert", "Die Skripte wurden gespeichert.");
		}
		return 1;
	}

	void reload() {
		auto machineSections = parseScriptsIni(machinePath);
		startupList->clearItems();
		for (auto& e : machineSections["Startup"]) startupList->appendItem(e.cmdLine + " " + e.parameters);
		shutdownList->clearItems();
		for (auto& e : machineSections["Shutdown"]) shutdownList->appendItem(e.cmdLine + " " + e.parameters);

		auto userSections = parseScriptsIni(userPath);
		logonList->clearItems();
		for (auto& e : userSections["Logon"]) logonList->appendItem(e.cmdLine + " " + e.parameters);
		logoffList->clearItems();
		for (auto& e : userSections["Logoff"]) logoffList->appendItem(e.cmdLine + " " + e.parameters);
	}

	bool saveBranch(bool isMachine, const std::string& sectionName1, const std::vector<ScriptEntry>& entries1,
	                 const std::string& sectionName2, const std::vector<ScriptEntry>& entries2) {
		std::string path = isMachine ? machinePath : userPath;
		auto sections = parseScriptsIni(path);
		sections[sectionName1] = entries1;
		sections[sectionName2] = entries2;
		FXString errorMsg;
		if (!writeScriptsIni(path, sections, errorMsg)) { FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text()); return false; }
		std::string log;
		std::string gpoObjectDn = "CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
		std::string toolGuid = isMachine ? GPSCR_TOOL_GUID_MACHINE : GPSCR_TOOL_GUID_USER;
		ensureExtensionRegistered(this, domain.realm, gpoObjectDn, isMachine, GPSCR_CSE_GUID, toolGuid, log, errorMsg);
		return true;
	}

	std::vector<ScriptEntry> listToEntries(FXList* list) {
		(void)list;
		return {};
	}

	long onAdd(FXList* list, const FXString& title) {
		AddScriptDialog dlg(this, title);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		if (dlg.getCmdLine().trim().empty()) return 1;
		list->appendItem(dlg.getCmdLine() + " " + dlg.getParameters());
		return 1;
	}
	long onAddStartup(FXObject*, FXSelector, void*) { return onAdd(startupList, "Startskript hinzufügen"); }
	long onAddShutdown(FXObject*, FXSelector, void*) { return onAdd(shutdownList, "Herunterfahrskript hinzufügen"); }
	long onAddLogon(FXObject*, FXSelector, void*) { return onAdd(logonList, "Anmeldeskript hinzufügen"); }
	long onAddLogoff(FXObject*, FXSelector, void*) { return onAdd(logoffList, "Abmeldeskript hinzufügen"); }
	long onRemoveStartup(FXObject*, FXSelector, void*) { int i = startupList->getCurrentItem(); if (i >= 0) startupList->removeItem(i); return 1; }
	long onRemoveShutdown(FXObject*, FXSelector, void*) { int i = shutdownList->getCurrentItem(); if (i >= 0) shutdownList->removeItem(i); return 1; }
	long onRemoveLogon(FXObject*, FXSelector, void*) { int i = logonList->getCurrentItem(); if (i >= 0) logonList->removeItem(i); return 1; }
	long onRemoveLogoff(FXObject*, FXSelector, void*) { int i = logoffList->getCurrentItem(); if (i >= 0) logoffList->removeItem(i); return 1; }

	ScriptsDialog(FXWindow* owner, const DomainInfo& domain_, const FXString& gpoGuid_)
		: FXDialogBox(owner, "Skripte", DECOR_ALL, 0,0,480,460),
		  domain(domain_), gpoGuid(gpoGuid_) {
		FXString realmLower = domain.realm; realmLower.lower();
		std::string sysvolBase = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + std::string(gpoGuid.text());
		machinePath = sysvolBase + "/" + SYSVOL_MACHINE_DIR + "/Scripts/scripts.ini";
		userPath = sysvolBase + "/" + SYSVOL_USER_DIR + "/Scripts/scripts.ini";

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);

		new FXTabItem(tabs, "Computerkonfiguration");
		FXVerticalFrame* machinePage = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(machinePage, "Startskripte:");
		startupList = new FXList(machinePage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X, 0,0,0,80);
		FXHorizontalFrame* sbtn = new FXHorizontalFrame(machinePage, LAYOUT_FILL_X, 0,0,0,0, 0,0,2,2);
		new FXButton(sbtn, "&Hinzufügen...", NULL, this, ID_ADD_STARTUP, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(sbtn, "&Entfernen", NULL, this, ID_REMOVE_STARTUP, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXLabel(machinePage, "Herunterfahrskripte:");
		shutdownList = new FXList(machinePage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X, 0,0,0,80);
		FXHorizontalFrame* dbtn = new FXHorizontalFrame(machinePage, LAYOUT_FILL_X, 0,0,0,0, 0,0,2,2);
		new FXButton(dbtn, "H&inzufügen...", NULL, this, ID_ADD_SHUTDOWN, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(dbtn, "E&ntfernen", NULL, this, ID_REMOVE_SHUTDOWN, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		new FXTabItem(tabs, "Benutzerkonfiguration");
		FXVerticalFrame* userPage = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(userPage, "Anmeldeskripte:");
		logonList = new FXList(userPage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X, 0,0,0,80);
		FXHorizontalFrame* lonbtn = new FXHorizontalFrame(userPage, LAYOUT_FILL_X, 0,0,0,0, 0,0,2,2);
		new FXButton(lonbtn, "Hin&zufügen...", NULL, this, ID_ADD_LOGON, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(lonbtn, "Ent&fernen", NULL, this, ID_REMOVE_LOGON, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXLabel(userPage, "Abmeldeskripte:");
		logoffList = new FXList(userPage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X, 0,0,0,80);
		FXHorizontalFrame* lofbtn = new FXHorizontalFrame(userPage, LAYOUT_FILL_X, 0,0,0,0, 0,0,2,2);
		new FXButton(lofbtn, "Hinz&ufügen...", NULL, this, ID_ADD_LOGOFF, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(lofbtn, "Entf&ernen", NULL, this, ID_REMOVE_LOGOFF, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Speichern", NULL, this, ID_SAVE, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Schließen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

		reload();
	}
	// Parst eine Listeneintrag-Zeile ("cmd param param2") wieder in
	// CmdLine/Parameters -- erstes Leerzeichen trennt.
	static ScriptEntry parseListLine(const FXString& line) {
		ScriptEntry e;
		int sp = line.find(' ');
		if (sp < 0) { e.cmdLine = line; return e; }
		e.cmdLine = line.left(sp);
		e.parameters = line.mid(sp + 1, line.length() - sp - 1);
		return e;
	}
	std::vector<ScriptEntry> listEntries(FXList* list) {
		std::vector<ScriptEntry> out;
		for (int i = 0; i < list->getNumItems(); i++) out.push_back(parseListLine(list->getItemText(i)));
		return out;
	}
	bool saveAll() {
		bool ok = true;
		ok &= saveBranch(true, "Startup", listEntries(startupList), "Shutdown", listEntries(shutdownList));
		ok &= saveBranch(false, "Logon", listEntries(logonList), "Logoff", listEntries(logoffList));
		return ok;
	}
	virtual ~ScriptsDialog() {}
};
FXDEFMAP(ScriptsDialog) ScriptsDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_ADD_STARTUP, ScriptsDialog::onAddStartup),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_REMOVE_STARTUP, ScriptsDialog::onRemoveStartup),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_ADD_SHUTDOWN, ScriptsDialog::onAddShutdown),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_REMOVE_SHUTDOWN, ScriptsDialog::onRemoveShutdown),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_ADD_LOGON, ScriptsDialog::onAddLogon),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_REMOVE_LOGON, ScriptsDialog::onRemoveLogon),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_ADD_LOGOFF, ScriptsDialog::onAddLogoff),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_REMOVE_LOGOFF, ScriptsDialog::onRemoveLogoff),
	FXMAPFUNC(SEL_COMMAND, ScriptsDialog::ID_SAVE, ScriptsDialog::onSave),
};
FXIMPLEMENT(ScriptsDialog, FXDialogBox, ScriptsDialogMap, ARRAYNUMBER(ScriptsDialogMap))

// ---------------------------------------------------------------------
// Dialog "Ordnerumleitung" -- fuenf Textfelder (leer = keine
// Umleitung), vorbelegt mit den aktuell in der Registry.pol
// gesetzten Zielpfaden.
// ---------------------------------------------------------------------
class FolderRedirectionDialog : public FXDialogBox {
	FXDECLARE(FolderRedirectionDialog)
private:
	std::map<std::string, FXTextField*> fields;
protected:
	FolderRedirectionDialog() {}
public:
	FolderRedirectionDialog(FXWindow* owner, const std::map<std::string, FXString>& current)
		: FXDialogBox(owner, "Ordnerumleitung", DECOR_TITLE | DECOR_BORDER, 0,0,460,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "UNC-Zielpfad je Ordner (leer lassen = keine Umleitung):");
		for (auto& t : FOLDER_REDIR_TARGETS) {
			new FXLabel(main, t.label);
			FXTextField* f = new FXTextField(main, 40, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
			auto it = current.find(t.fdeployKey);
			if (it != current.end()) f->setText(it->second);
			fields[t.fdeployKey] = f;
		}
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	std::map<std::string, FXString> getPaths() const {
		std::map<std::string, FXString> out;
		for (auto& kv : fields) out[kv.first] = kv.second->getText();
		return out;
	}
	virtual ~FolderRedirectionDialog() {}
};
FXIMPLEMENT(FolderRedirectionDialog, FXDialogBox, NULL, 0)


// =====================================================================
// Gruppenrichtlinienfenster, OU-Eigenschaften und alles, was beide
// brauchen.
// =====================================================================

// ---------------------------------------------------------------------
// Allgemeine LDAP-Suche ueber den privilegierten ldapi-Socket (nur
// lesend, ohne Anmeldedaten -- siehe ldapListChildren).
// ---------------------------------------------------------------------
static std::vector<std::multimap<std::string, std::string>> ldapiSearch(const std::string& base, const char* scope,
                                                                        const std::string& filter,
                                                                        const std::vector<std::string>& attrs) {
	std::vector<std::multimap<std::string, std::string>> out;
	if (access("/usr/bin/ldapsearch", X_OK) != 0) return out;
	std::vector<FXString> args = {
		FXString("ldapsearch"), FXString("-x"), FXString("-LLL"), FXString("-o"), FXString("ldif-wrap=no"),
		FXString("-H"), FXString(SAMBA_LDAPI_URL), FXString("-b"), FXString(base.c_str()),
		FXString("-s"), FXString(scope), FXString(filter.c_str())
	};
	for (auto& a : attrs) args.push_back(FXString(a.c_str()));
	std::string raw;
	if (runAsRootCaptured(args, raw) != 0) return out;
	std::string block;
	auto flush = [&]() {
		if (block.empty()) return;
		auto rec = parseLdifRecord(block);
		block.clear();
		if (!ldifFirst(rec, "dn").empty()) out.push_back(rec);
	};
	for (auto& l : splitLines(raw)) {
		if (l.empty()) flush();
		else if (l[0] != '#') block += l + "\n";
	}
	flush();
	return out;
}

static std::string ldapiReadAttr(const std::string& dn, const std::string& attr) {
	auto recs = ldapiSearch(dn, "base", "(objectClass=*)", { attr });
	return recs.empty() ? std::string() : ldifFirst(recs[0], attr.c_str());
}

// Vollstaendiger Rechnername des DCs fuer Titel wie
// "Richtlinien für Software [win2k-server.zwiebelchen.org]".
static FXString serverFqdn(const DomainInfo& domain) {
	char host[256] = { 0 };
	gethostname(host, sizeof(host) - 1);
	std::string h = host;
	size_t dot = h.find('.');
	if (dot != std::string::npos) h = h.substr(0, dot);
	FXString realmLower = domain.realm; realmLower.lower();
	return FXString(lowerCopy(h).c_str()) + "." + realmLower;
}

// ---------------------------------------------------------------------
// gPLink: Bloecke "[LDAP://cn={GUID},cn=policies,...;Optionen]".
// Die HOECHSTE Prioritaet hat der LETZTE Block -- Samba verarbeitet die
// Liste von vorn nach hinten, Spaeteres ueberschreibt Frueheres, und
// "samba-tool gpo setlink" stellt neue Verknuepfungen vorne an (neue
// Verknuepfung = niedrigste Prioritaet, wie im Original).
// ---------------------------------------------------------------------
static const int GPLINK_OPT_DISABLE = 1;
static const int GPLINK_OPT_ENFORCE = 2;

struct GpLinkEntry {
	std::string dn;    // DN des GPO-Objekts, wie im Attribut
	std::string guid;  // "{...}" in Grossbuchstaben
	int options = 0;
};

static std::vector<GpLinkEntry> parseGpLink(const std::string& raw) {
	std::vector<GpLinkEntry> out;
	for (auto& block : parseGpLinkBlocks(raw)) {
		std::string inner = block.substr(1, block.size() - 2);
		size_t semi = inner.rfind(';');
		GpLinkEntry e;
		std::string url = semi == std::string::npos ? inner : inner.substr(0, semi);
		if (semi != std::string::npos) { try { e.options = std::stoi(inner.substr(semi + 1)); } catch (...) {} }
		if (lowerCopy(url.substr(0, 7)) == "ldap://") url = url.substr(7);
		e.dn = url;
		size_t a = url.find('{'), b = url.find('}');
		if (a != std::string::npos && b != std::string::npos && b > a) {
			e.guid = url.substr(a, b - a + 1);
			std::transform(e.guid.begin(), e.guid.end(), e.guid.begin(), [](unsigned char c) { return std::toupper(c); });
		}
		out.push_back(e);
	}
	return out;
}

static std::string encodeGpLink(const std::vector<GpLinkEntry>& links) {
	std::string out;
	for (auto& l : links) out += "[LDAP://" + l.dn + ";" + std::to_string(l.options) + "]";
	return out;
}

static bool writeGpLink(FXWindow* owner, const FXString& realm, const std::string& containerDn,
                        const std::vector<GpLinkEntry>& links, FXString& errorMsg) {
	std::string ldif = "dn: " + containerDn + "\nchangetype: modify\nreplace: gPLink\n";
	if (!links.empty()) ldif += ldifAttrLine("gPLink", encodeGpLink(links));
	ldif += "-\n";
	std::string log;
	return runLdapChange(owner, realm, ldif, false, log, errorMsg);
}

struct GpoSummary {
	std::string guid, displayName, dn;
	std::string whenCreated, whenChanged;
	uint32_t version = 0;
	int flags = 0; // 1 = Benutzerkonfiguration deaktiviert, 2 = Computerkonfiguration deaktiviert
};

static std::vector<GpoSummary> listGposLdapi(const FXString& baseDN) {
	std::vector<GpoSummary> out;
	for (auto& rec : ldapiSearch("CN=Policies,CN=System," + std::string(baseDN.text()), "one",
	                             "(objectClass=groupPolicyContainer)",
	                             { "cn", "displayName", "versionNumber", "flags", "whenCreated", "whenChanged" })) {
		GpoSummary g;
		g.dn = ldifFirst(rec, "dn");
		g.guid = ldifFirst(rec, "cn");
		std::transform(g.guid.begin(), g.guid.end(), g.guid.begin(), [](unsigned char c) { return std::toupper(c); });
		g.displayName = ldifFirst(rec, "displayName");
		g.whenCreated = ldifFirst(rec, "whenCreated");
		g.whenChanged = ldifFirst(rec, "whenChanged");
		try { g.version = (uint32_t)std::stoul(ldifFirst(rec, "versionNumber")); } catch (...) {}
		try { g.flags = std::stoi(ldifFirst(rec, "flags")); } catch (...) {}
		out.push_back(g);
	}
	std::sort(out.begin(), out.end(), [](const GpoSummary& a, const GpoSummary& b) {
		return strcasecmp(a.displayName.c_str(), b.displayName.c_str()) < 0;
	});
	return out;
}

// "20260916165113.0Z" -> "16.09.2026 16:51:13" (UTC, wie gespeichert)
static FXString formatGeneralizedTime(const std::string& t) {
	if (t.size() < 14) return FXString(t.c_str());
	return FXString((t.substr(6, 2) + "." + t.substr(4, 2) + "." + t.substr(0, 4) + " " +
	                 t.substr(8, 2) + ":" + t.substr(10, 2) + ":" + t.substr(12, 2)).c_str());
}

// ---------------------------------------------------------------------
// SYSVOL-Pfade eines GPOs. Die bei der Provisionierung angelegten
// Standard-GPOs haben die Zweige "MACHINE"/"USER", mit "samba-tool gpo
// create" angelegte dagegen "Machine"/"User" -- genommen wird, was
// tatsaechlich existiert, sonst die neue Schreibweise.
// ---------------------------------------------------------------------
static std::string gpoSysvolBase(const DomainInfo& domain, const std::string& guid) {
	FXString realmLower = domain.realm; realmLower.lower();
	return "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + guid;
}

static std::string gpoBranchDir(const DomainInfo& domain, const std::string& guid, bool machine) {
	std::string base = gpoSysvolBase(domain, guid);
	const char* preferred = machine ? SYSVOL_MACHINE_DIR : SYSVOL_USER_DIR;
	const char* legacy = machine ? "MACHINE" : "USER";
	if (runAsRoot({ FXString("test"), FXString("-d"), FXString((base + "/" + preferred).c_str()) }) == 0) return base + "/" + preferred;
	if (runAsRoot({ FXString("test"), FXString("-d"), FXString((base + "/" + legacy).c_str()) }) == 0) return base + "/" + legacy;
	return base + "/" + preferred;
}

// ---------------------------------------------------------------------
// Laenderliste fuer "Land/Region" -- aus dem Debian-Paket iso-codes
// (JSON), deutsche Namen direkt aus dessen .mo-Datei, unabhaengig von
// der eingestellten Sprache des Prozesses.
// ---------------------------------------------------------------------
struct CountryEntry { std::string alpha2, name; int numeric = 0; };

static std::map<std::string, std::string> readMoCatalog(const char* path) {
	std::map<std::string, std::string> out;
	std::string data = readFileUnprivileged(path);
	if (data.size() < 28) return out;
	auto u32 = [&](size_t off) -> uint32_t {
		if (off + 4 > data.size()) return 0;
		return (uint8_t)data[off] | ((uint8_t)data[off + 1] << 8) | ((uint8_t)data[off + 2] << 16) | ((uint32_t)(uint8_t)data[off + 3] << 24);
	};
	if (u32(0) != 0x950412de) return out; // nur Little-Endian-Kataloge
	uint32_t n = u32(8), origTab = u32(12), transTab = u32(16);
	for (uint32_t i = 0; i < n; i++) {
		uint32_t ol = u32(origTab + i * 8), oo = u32(origTab + i * 8 + 4);
		uint32_t tl = u32(transTab + i * 8), to = u32(transTab + i * 8 + 4);
		if ((size_t)oo + ol > data.size() || (size_t)to + tl > data.size()) continue;
		out[data.substr(oo, ol)] = data.substr(to, tl);
	}
	return out;
}

static const std::vector<CountryEntry>& countryList() {
	static std::vector<CountryEntry> list;
	static bool loaded = false;
	if (loaded) return list;
	loaded = true;
	std::string json = readFileUnprivileged("/usr/share/iso-codes/json/iso_3166-1.json");
	auto de = readMoCatalog("/usr/share/locale/de/LC_MESSAGES/iso_3166-1.mo");
	auto field = [](const std::string& obj, const char* key) -> std::string {
		std::string needle = std::string("\"") + key + "\"";
		size_t p = obj.find(needle);
		if (p == std::string::npos) return "";
		p = obj.find('"', obj.find(':', p) + 1);
		if (p == std::string::npos) return "";
		std::string v;
		for (size_t i = p + 1; i < obj.size() && obj[i] != '"'; i++) {
			if (obj[i] == '\\' && i + 1 < obj.size()) i++;
			v += obj[i];
		}
		return v;
	};
	size_t pos = 0;
	while ((pos = json.find('{', pos + 1)) != std::string::npos) {
		size_t end = json.find('}', pos);
		if (end == std::string::npos) break;
		std::string obj = json.substr(pos, end - pos);
		CountryEntry c;
		c.alpha2 = field(obj, "alpha_2");
		c.name = field(obj, "name");
		try { c.numeric = std::stoi(field(obj, "numeric")); } catch (...) {}
		if (c.alpha2.empty() || c.name.empty()) continue;
		auto t = de.find(c.name);
		if (t != de.end() && !t->second.empty()) c.name = t->second;
		list.push_back(c);
		pos = end;
	}
	std::sort(list.begin(), list.end(), [](const CountryEntry& a, const CountryEntry& b) {
		return germanLess(a.name, b.name);
	});
	return list;
}

// ---------------------------------------------------------------------
// GptTmpl.inf -- die Sicherheitsvorlage eines GPOs
// (Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf). UTF-16LE mit
// BOM, Abschnitte wie [System Access], [Event Audit], [System Log].
// Reihenfolge von Abschnitten und Schluesseln bleibt erhalten, damit
// nichts verlorengeht, was hier (noch) nicht bearbeitet wird.
// ---------------------------------------------------------------------
// Zeilen ohne "=" (Systemdienste, Registrierung, Dateisystem:
// "\"Name\",2,\"D:...\"") stehen komplett im Schluessel; dieser Wert
// markiert sie, damit beim Schreiben kein " = " angehaengt wird.
static const char* INF_BARE_LINE = "\x01";

struct InfFile {
	std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::string>>>> sections;

	std::vector<std::pair<std::string, std::string>>* find(const std::string& section) {
		for (auto& s : sections) if (lowerCopy(s.first) == lowerCopy(section)) return &s.second;
		return nullptr;
	}
	bool get(const std::string& section, const std::string& key, std::string& value) {
		auto* s = find(section);
		if (!s) return false;
		for (auto& kv : *s) if (lowerCopy(kv.first) == lowerCopy(key)) { value = kv.second; return true; }
		return false;
	}
	void set(const std::string& section, const std::string& key, const std::string& value) {
		auto* s = find(section);
		if (!s) {
			// [Version] steht ueblicherweise am Ende -- neue Abschnitte davor.
			auto it = sections.end();
			for (auto i = sections.begin(); i != sections.end(); ++i) if (lowerCopy(i->first) == "version") { it = i; break; }
			it = sections.insert(it, { section, {} });
			s = &it->second;
		}
		for (auto& kv : *s) if (lowerCopy(kv.first) == lowerCopy(key)) { kv.second = value; return; }
		s->push_back({ key, value });
	}
	void erase(const std::string& section, const std::string& key) {
		auto* s = find(section);
		if (!s) return;
		s->erase(std::remove_if(s->begin(), s->end(), [&](const std::pair<std::string, std::string>& kv) {
			return lowerCopy(kv.first) == lowerCopy(key);
		}), s->end());
	}
};

static InfFile parseInf(const std::string& raw) {
	InfFile inf;
	std::string text = raw;
	if (raw.size() >= 2 && (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) text = utf16leToUtf8(raw);
	else if (raw.size() >= 3 && (unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) text = raw.substr(3);
	std::vector<std::pair<std::string, std::string>>* cur = nullptr;
	for (auto& line : splitLines(text)) {
		std::string l = trimStr(line);
		if (l.empty() || l[0] == ';') continue;
		if (l.front() == '[' && l.back() == ']') {
			inf.sections.push_back({ l.substr(1, l.size() - 2), {} });
			cur = &inf.sections.back().second;
			continue;
		}
		if (!cur) continue;
		size_t eq = l.find('=');
		if (eq == std::string::npos || (!l.empty() && l[0] == '"')) cur->push_back({ l, INF_BARE_LINE });
		else cur->push_back({ trimStr(l.substr(0, eq)), trimStr(l.substr(eq + 1)) });
	}
	return inf;
}

static std::string serializeInf(InfFile inf) {
	// Pflichtabschnitte, sonst verwirft der Client die Vorlage.
	std::string dummy;
	if (!inf.find("Unicode")) inf.sections.insert(inf.sections.begin(), { "Unicode", { { "Unicode", "yes" } } });
	if (!inf.find("Version")) inf.sections.push_back({ "Version", { { "signature", "\"$CHICAGO$\"" }, { "Revision", "1" } } });
	std::string out;
	for (auto& s : inf.sections) {
		out += "[" + s.first + "]\r\n";
		for (auto& kv : s.second) {
			if (kv.second == INF_BARE_LINE) { out += kv.first + "\r\n"; continue; }
			// Wie secedit selbst: Registrierungswerte und die Pflichtabschnitte
			// ohne Leerzeichen um das Gleichheitszeichen.
			bool unicodeSection = lowerCopy(s.first) == "unicode" || lowerCopy(s.first) == "version" ||
			                      lowerCopy(s.first) == "registry values";
			out += kv.first + (unicodeSection ? "=" : " = ") + kv.second + "\r\n";
		}
	}
	return utf8ToUtf16leWithBom(out);
}

static const char* SECEDIT_CSE_GUID = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}";
static const char* SECEDIT_TOOL_GUID = "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}";

static std::string gptTmplPath(const DomainInfo& domain, const std::string& guid) {
	return gpoBranchDir(domain, guid, true) + "/Microsoft/Windows NT/SecEdit/GptTmpl.inf";
}

static InfFile loadGptTmpl(const DomainInfo& domain, const std::string& guid) {
	std::string raw;
	if (runAsRootCaptured({ FXString("cat"), FXString(gptTmplPath(domain, guid).c_str()) }, raw) != 0) return InfFile();
	return parseInf(raw);
}

// ---------------------------------------------------------------------
// Sicherheitsrichtlinien, die als einzelner Wert in der GptTmpl.inf
// stehen -- Tabellen mit den Bezeichnungen des deutschen Windows 2000.
//
// Speicherformat (regType):
//   REGT_PLAIN   [System Access]: "Schluessel = 5"
//   REGT_QUOTED  [System Access]: "NewAdministratorName = "Admin""
//   REGT_DWORD   [Registry Values]: "MACHINE\...\Wert=4,1"
//   REGT_SZ      [Registry Values]: "MACHINE\...\Wert=1,"Text""
//   REGT_BINARY  [Registry Values]: "MACHINE\...\Wert=3,0"
// ---------------------------------------------------------------------
enum SecValueKind { SV_NUMBER, SV_BOOL, SV_AUDIT, SV_RETENTION, SV_TEXT, SV_CHOICE };
enum SecRegType { REGT_PLAIN, REGT_QUOTED, REGT_DWORD, REGT_SZ, REGT_BINARY };

struct SecChoice { int value; const char* label; };

struct SecPolicyDef {
	const char* section;
	const char* key;
	const char* label;
	SecValueKind kind;
	const char* unit = "";      // SV_NUMBER: Einheit hinter der Zahl ("Tage")
	int minV = 0, maxV = 0, defV = 0;
	SecRegType regType = REGT_PLAIN;
	std::vector<SecChoice> choices = {}; // SV_CHOICE
};

static const std::vector<SecPolicyDef> SEC_PASSWORD_POLICIES = {
	{ "System Access", "PasswordHistorySize", "Kennwortchronik erzwingen", SV_NUMBER, "gespeicherte Kennwörter", 0, 24, 24 },
	{ "System Access", "MaximumPasswordAge", "Maximales Kennwortalter", SV_NUMBER, "Tage", 0, 999, 42 },
	{ "System Access", "MinimumPasswordAge", "Minimales Kennwortalter", SV_NUMBER, "Tage", 0, 998, 1 },
	{ "System Access", "MinimumPasswordLength", "Minimale Kennwortlänge", SV_NUMBER, "Zeichen", 0, 14, 7 },
	{ "System Access", "PasswordComplexity", "Kennwörter müssen den Komplexitätsvoraussetzungen entsprechen", SV_BOOL, "", 0, 1, 1 },
	{ "System Access", "ClearTextPassword", "Kennwörter für alle Domänenbenutzer mit umkehrbarer Verschlüsselung speichern", SV_BOOL, "", 0, 1, 0 },
};

static const std::vector<SecPolicyDef> SEC_LOCKOUT_POLICIES = {
	{ "System Access", "LockoutDuration", "Kontosperrdauer", SV_NUMBER, "Minuten", 0, 99999, 30 },
	{ "System Access", "LockoutBadCount", "Kontosperrungsschwelle", SV_NUMBER, "ungültige Anmeldeversuche", 0, 999, 5 },
	{ "System Access", "ResetLockoutCount", "Kontosperrungszähler zurücksetzen nach", SV_NUMBER, "Minuten", 1, 99999, 30 },
};

static const std::vector<SecPolicyDef> SEC_AUDIT_POLICIES = {
	{ "Event Audit", "AuditAccountLogon", "Anmeldeversuche überwachen", SV_AUDIT },
	{ "Event Audit", "AuditLogonEvents", "Anmeldeereignisse überwachen", SV_AUDIT },
	{ "Event Audit", "AuditAccountManage", "Kontenverwaltung überwachen", SV_AUDIT },
	{ "Event Audit", "AuditObjectAccess", "Objektzugriffsversuche überwachen", SV_AUDIT },
	{ "Event Audit", "AuditProcessTracking", "Prozessverfolgung überwachen", SV_AUDIT },
	{ "Event Audit", "AuditPrivilegeUse", "Rechteverwendung überwachen", SV_AUDIT },
	{ "Event Audit", "AuditPolicyChange", "Richtlinienänderungen überwachen", SV_AUDIT },
	{ "Event Audit", "AuditSystemEvents", "Systemereignisse überwachen", SV_AUDIT },
	{ "Event Audit", "AuditDSAccess", "Verzeichnisdienstzugriff überwachen", SV_AUDIT },
};

static const std::vector<SecPolicyDef> SEC_EVENTLOG_POLICIES = {
	{ "Application Log", "MaximumLogSize", "Maximale Anwendungsprotokollgröße", SV_NUMBER, "Kilobyte", 64, 4194240, 512 },
	{ "Security Log", "MaximumLogSize", "Maximale Sicherheitsprotokollgröße", SV_NUMBER, "Kilobyte", 64, 4194240, 512 },
	{ "System Log", "MaximumLogSize", "Maximale Systemprotokollgröße", SV_NUMBER, "Kilobyte", 64, 4194240, 512 },
	{ "Application Log", "RestrictGuestAccess", "Lokalen Gastkontozugriff auf Anwendungsprotokoll verhindern", SV_BOOL, "", 0, 1, 1 },
	{ "Security Log", "RestrictGuestAccess", "Lokalen Gastkontozugriff auf Sicherheitsprotokoll verhindern", SV_BOOL, "", 0, 1, 1 },
	{ "System Log", "RestrictGuestAccess", "Lokalen Gastkontozugriff auf Systemprotokoll verhindern", SV_BOOL, "", 0, 1, 1 },
	{ "Application Log", "RetentionDays", "Anwendungsprotokoll aufbewahren", SV_NUMBER, "Tage", 1, 365, 7 },
	{ "Security Log", "RetentionDays", "Sicherheitsprotokoll aufbewahren", SV_NUMBER, "Tage", 1, 365, 7 },
	{ "System Log", "RetentionDays", "Systemprotokoll aufbewahren", SV_NUMBER, "Tage", 1, 365, 7 },
	{ "Application Log", "AuditLogRetentionPeriod", "Aufbewahrungsmethode des Anwendungsprotokolls", SV_RETENTION, "", 0, 2, 1 },
	{ "Security Log", "AuditLogRetentionPeriod", "Aufbewahrungsmethode des Sicherheitsprotokolls", SV_RETENTION, "", 0, 2, 1 },
	{ "System Log", "AuditLogRetentionPeriod", "Aufbewahrungsmethode des Systemprotokolls", SV_RETENTION, "", 0, 2, 1 },
};

// Registrierungspfade, auf die sich die Sicherheitsoptionen verteilen.
#define REG_LSA        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\"
#define REG_POLSYS     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
#define REG_WINLOGON   "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
#define REG_LANMANSRV  "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"
#define REG_LANMANWKS  "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\"
#define REG_NETLOGON   "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\"
#define REG_RECOVERY   "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\"
#define REG_SESSIONMGR "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\"

static const std::vector<SecChoice> SIGNING_CHOICES = {
	{ 0, "Automatisch ohne Warnung durchführen" }, { 1, "Warnen, aber Installation zulassen" }, { 2, "Installation nicht zulassen" }
};

static const std::vector<SecPolicyDef> SEC_OPTIONS = {
	{ "Registry Values", REG_LSA "RestrictAnonymous", "Zusätzliche Einschränkungen für anonyme Verbindungen", SV_CHOICE, "", 0, 0, 0, REGT_DWORD,
	  { { 0, "Keine. Auf Standardberechtigungen zurückgreifen" }, { 1, "Aufzählung von SAM-Konten und -Namen nicht erlauben" },
	    { 2, "Kein Zugriff ohne explizite anonyme Berechtigungen" } } },
	{ "Registry Values", REG_LSA "SubmitControl", "Server-Operatoren das Zuweisen von Aufgaben ermöglichen", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_LSA "AuditBaseObjects", "Zugriff auf globale Systemobjekte prüfen", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_LSA "FullPrivilegeAuditing", "Zugriff auf Sicherungs- und Wiederherstellungsrechte prüfen", SV_BOOL, "", 0, 1, 0, REGT_BINARY },
	{ "System Access", "ForceLogoffWhenHourExpire", "Clientverbindungen automatisch trennen, wenn die Anmeldezeit überschritten wird", SV_BOOL, "", 0, 1, 1, REGT_PLAIN },
	{ "Registry Values", REG_POLSYS "ShutdownWithoutLogon", "Herunterfahren des Systems ohne Anmeldung zulassen", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_WINLOGON "AllocateDASD", "Formatieren und Auswerfen von Wechselmedien zulassen", SV_CHOICE, "", 0, 0, 0, REGT_SZ,
	  { { 0, "Administratoren" }, { 1, "Administratoren und Hauptbenutzer" }, { 2, "Administratoren und interaktive Benutzer" } } },
	{ "Registry Values", REG_LANMANSRV "AutoDisconnect", "Leerlaufzeit vor Trennung der Sitzung", SV_NUMBER, "Minuten", 0, 99999, 15, REGT_DWORD },
	{ "Registry Values", REG_LANMANSRV "RequireSecuritySignature", "Serverkommunikation digital signieren (immer)", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_LANMANSRV "EnableSecuritySignature", "Serverkommunikation digital signieren (wenn möglich)", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_LANMANWKS "RequireSecuritySignature", "Clientkommunikation digital signieren (immer)", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_LANMANWKS "EnableSecuritySignature", "Clientkommunikation digital signieren (wenn möglich)", SV_BOOL, "", 0, 1, 1, REGT_DWORD },
	{ "Registry Values", REG_LANMANWKS "EnablePlainTextPassword", "Unverschlüsseltes Kennwort senden, um Verbindung mit SMB-Servern von Drittanbietern herzustellen", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_POLSYS "DisableCAD", "Strg+Alt+Entf-Anforderung zur Anmeldung deaktivieren", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_POLSYS "DontDisplayLastUserName", "Letzten Benutzernamen nicht im Anmeldedialog anzeigen", SV_BOOL, "", 0, 1, 1, REGT_DWORD },
	{ "Registry Values", REG_LSA "LmCompatibilityLevel", "LAN Manager-Authentifizierungsebene", SV_CHOICE, "", 0, 0, 0, REGT_DWORD,
	  { { 0, "LM- und NTLM-Antworten senden" }, { 1, "LM- und NTLM-Antworten senden (NTLMv2 verwenden, wenn ausgehandelt)" },
	    { 2, "Nur NTLM-Antworten senden" }, { 3, "Nur NTLMv2-Antworten senden" } } },
	{ "Registry Values", REG_POLSYS "LegalNoticeText", "Nachricht für Benutzer, die sich anmelden wollen", SV_TEXT, "", 0, 0, 0, REGT_SZ },
	{ "Registry Values", REG_POLSYS "LegalNoticeCaption", "Nachrichtentitel für Benutzer, die sich anmelden wollen", SV_TEXT, "", 0, 0, 0, REGT_SZ },
	{ "Registry Values", REG_WINLOGON "CachedLogonsCount", "Anzahl zwischenzuspeichernder vorheriger Anmeldungen (für den Fall, dass der Domänencontroller nicht verfügbar ist)", SV_NUMBER, "Anmeldungen", 0, 50, 10, REGT_SZ },
	{ "Registry Values", "MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers", "Installation von Druckertreibern durch Benutzer verhindern", SV_BOOL, "", 0, 1, 1, REGT_DWORD },
	{ "Registry Values", REG_WINLOGON "PasswordExpiryWarning", "Benutzer auffordern, das Kennwort vor Ablauf zu ändern", SV_NUMBER, "Tage", 0, 999, 14, REGT_DWORD },
	{ "Registry Values", REG_RECOVERY "SecurityLevel", "Wiederherstellungskonsole: Automatische administrative Anmeldung zulassen", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_RECOVERY "SetCommand", "Wiederherstellungskonsole: Kopieren von Disketten und Zugriff auf alle Laufwerke und Ordner zulassen", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "System Access", "NewAdministratorName", "Administratorkonto umbenennen", SV_TEXT, "", 0, 0, 0, REGT_QUOTED },
	{ "System Access", "NewGuestName", "Gastkonto umbenennen", SV_TEXT, "", 0, 0, 0, REGT_QUOTED },
	{ "Registry Values", REG_WINLOGON "AllocateCDRoms", "Zugriff auf CD-ROM-Laufwerke auf lokal angemeldete Benutzer beschränken", SV_BOOL, "", 0, 1, 0, REGT_SZ },
	{ "Registry Values", REG_WINLOGON "AllocateFloppies", "Zugriff auf Diskettenlaufwerke auf lokal angemeldete Benutzer beschränken", SV_BOOL, "", 0, 1, 0, REGT_SZ },
	{ "Registry Values", REG_NETLOGON "RequireSignOrSeal", "Daten des sicheren Kanals digital verschlüsseln oder signieren (immer)", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_NETLOGON "SealSecureChannel", "Daten des sicheren Kanals digital verschlüsseln (wenn möglich)", SV_BOOL, "", 0, 1, 1, REGT_DWORD },
	{ "Registry Values", REG_NETLOGON "SignSecureChannel", "Daten des sicheren Kanals digital signieren (wenn möglich)", SV_BOOL, "", 0, 1, 1, REGT_DWORD },
	{ "Registry Values", REG_NETLOGON "RequireStrongKey", "Sicherer Kanal: Starker Sitzungsschlüssel erforderlich (Windows 2000 oder höher)", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_NETLOGON "DisablePasswordChange", "Änderungen des Computerkontokennworts verhindern", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_LSA "CrashOnAuditFail", "System sofort herunterfahren, wenn Sicherheitsüberwachungen nicht protokolliert werden können", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_WINLOGON "ScRemoveOption", "Verhalten beim Entfernen von Smartcards", SV_CHOICE, "", 0, 0, 0, REGT_SZ,
	  { { 0, "Keine Aktion" }, { 1, "Arbeitsstation sperren" }, { 2, "Abmeldung erzwingen" } } },
	{ "Registry Values", "MACHINE\\Software\\Microsoft\\Driver Signing\\Policy", "Verhalten bei der Installation von nicht signierten Treibern", SV_CHOICE, "", 0, 0, 1, REGT_BINARY, SIGNING_CHOICES },
	{ "Registry Values", "MACHINE\\Software\\Microsoft\\Non-Driver Signing\\Policy", "Verhalten bei der Installation von nicht signierten Nicht-Treibern", SV_CHOICE, "", 0, 0, 0, REGT_BINARY, SIGNING_CHOICES },
	{ "Registry Values", REG_SESSIONMGR "Memory Management\\ClearPageFileAtShutdown", "Auslagerungsdatei des virtuellen Arbeitsspeichers löschen, wenn das System heruntergefahren wird", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
	{ "Registry Values", REG_SESSIONMGR "ProtectionMode", "Standardberechtigungen der internen Systemobjekte (z.B. symbolische Verknüpfungen) verstärken", SV_BOOL, "", 0, 1, 1, REGT_DWORD },
	{ "Registry Values", REG_WINLOGON "ForceUnlockLogon", "Domänencontroller-Authentifizierung zum Aufheben der Sperrung erforderlich", SV_BOOL, "", 0, 1, 0, REGT_DWORD },
};

static const char* RETENTION_LABELS[3] = {
	"Ereignisse bei Bedarf überschreiben",
	"Ereignisse nach Tagen überschreiben",
	"Ereignisse nicht überschreiben (Protokoll manuell löschen)"
};

// Liest den Wert einer Richtlinie aus der Vorlage -- Zahlen als
// Dezimaltext, Texte ohne Anfuehrungszeichen. false = nicht definiert.
static bool readSecValue(InfFile& inf, const SecPolicyDef& def, std::string& value) {
	std::string raw;
	if (!inf.get(def.section, def.key, raw)) return false;
	raw = trimStr(raw);
	if (def.regType == REGT_DWORD || def.regType == REGT_SZ || def.regType == REGT_BINARY) {
		size_t comma = raw.find(',');
		if (comma == std::string::npos) return false;
		raw = trimStr(raw.substr(comma + 1));
	}
	if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"') raw = raw.substr(1, raw.size() - 2);
	if (def.kind != SV_TEXT) {
		try { value = std::to_string(std::stol(raw)); } catch (...) { return false; }
	} else {
		value = raw;
	}
	return true;
}

static void writeSecValue(InfFile& inf, const SecPolicyDef& def, bool defined, const std::string& value) {
	if (!defined) { inf.erase(def.section, def.key); return; }
	std::string v;
	switch (def.regType) {
		case REGT_PLAIN: v = value; break;
		case REGT_QUOTED: v = "\"" + value + "\""; break;
		case REGT_DWORD: v = "4," + value; break;
		case REGT_SZ: v = "1,\"" + value + "\""; break;
		case REGT_BINARY: v = "3," + value; break;
	}
	inf.set(def.section, def.key, v);
}

static FXString secValueText(const SecPolicyDef& def, bool defined, const std::string& value) {
	if (!defined) return "Nicht definiert";
	int v = 0;
	try { v = std::stoi(value); } catch (...) {}
	switch (def.kind) {
		case SV_BOOL: return v ? "Aktiviert" : "Deaktiviert";
		case SV_AUDIT:
			return v == 3 ? "Erfolgreich, Fehlgeschlagen" : v == 1 ? "Erfolgreich" : v == 2 ? "Fehlgeschlagen" : "Keine Überwachung";
		case SV_RETENTION: return (v >= 0 && v <= 2) ? RETENTION_LABELS[v] : "Nicht definiert";
		case SV_TEXT: return value.c_str();
		case SV_CHOICE:
			for (auto& c : def.choices) if (c.value == v) return c.label;
			return value.c_str();
		default: {
			char buf[128];
			snprintf(buf, sizeof(buf), "%d %s", v, def.unit);
			return buf;
		}
	}
}

// ---------------------------------------------------------------------
// Dialog "Sicherheitsrichtlinieneinstellung" fuer Einzelwerte.
// ---------------------------------------------------------------------
class SecPolicyEditDialog : public FXDialogBox {
	FXDECLARE(SecPolicyEditDialog)
private:
	const SecPolicyDef* def = nullptr;
	FXCheckButton* defineCheck = nullptr;
	std::vector<FXWindow*> controls;
	FXSpinner* spinner = nullptr;
	FXTextField* textField = nullptr;
	FXListBox* choiceBox = nullptr;
	FXint choice = 0;
	FXDataTarget* choiceTarget = nullptr;
	FXCheckButton* auditSuccess = nullptr, *auditFailure = nullptr;
protected:
	SecPolicyEditDialog() {}
public:
	enum { ID_DEFINE = FXDialogBox::ID_LAST };

	SecPolicyEditDialog(FXWindow* owner, const SecPolicyDef& def_, bool defined, const std::string& value)
		: FXDialogBox(owner, "Sicherheitsrichtlinieneinstellung", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,0),
		  def(&def_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,8);
		FXHorizontalFrame* head = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,0);
		new FXLabel(head, "", sharedPngIcon(resico_key), LAYOUT_TOP);
		new FXLabel(head, wrapLabel(def->label, 50), NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		defineCheck = new FXCheckButton(main, "Diese Richtlinieneinstellung &definieren:", this, ID_DEFINE);
		defineCheck->setCheck(defined);
		FXVerticalFrame* body = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 20,0,0,0, 0,4);

		int initial = def->defV;
		if (defined && def->kind != SV_TEXT) { try { initial = std::stoi(value); } catch (...) {} }
		choice = initial;
		switch (def->kind) {
			case SV_NUMBER: {
				FXHorizontalFrame* row = new FXHorizontalFrame(body, 0, 0,0,0,0, 0,0,0,0);
				spinner = new FXSpinner(row, 8, NULL, 0, SPIN_NORMAL | FRAME_SUNKEN | FRAME_THICK);
				spinner->setRange(def->minV, def->maxV);
				spinner->setValue(std::max(def->minV, std::min(def->maxV, initial)));
				if (def->minV == 64) spinner->setIncrement(64);
				FXLabel* unit = new FXLabel(row, def->unit, NULL, LAYOUT_CENTER_Y);
				controls = { spinner, unit };
				break;
			}
			case SV_BOOL: {
				choiceTarget = new FXDataTarget(choice);
				controls.push_back(new FXRadioButton(body, "&Aktiviert", choiceTarget, FXDataTarget::ID_OPTION + 1));
				controls.push_back(new FXRadioButton(body, "D&eaktiviert", choiceTarget, FXDataTarget::ID_OPTION + 0));
				break;
			}
			case SV_AUDIT: {
				controls.push_back(new FXLabel(body, "Diese Versuche überwachen:"));
				auditSuccess = new FXCheckButton(body, "&Erfolgreich");
				auditFailure = new FXCheckButton(body, "&Fehlgeschlagen");
				auditSuccess->setCheck((initial & 1) != 0);
				auditFailure->setCheck((initial & 2) != 0);
				controls.push_back(auditSuccess);
				controls.push_back(auditFailure);
				break;
			}
			case SV_RETENTION: {
				choiceTarget = new FXDataTarget(choice);
				for (int i : { 1, 0, 2 })
					controls.push_back(new FXRadioButton(body, RETENTION_LABELS[i], choiceTarget, FXDataTarget::ID_OPTION + i));
				break;
			}
			case SV_TEXT: {
				textField = new FXTextField(body, 40, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
				textField->setText(defined ? value.c_str() : "");
				controls.push_back(textField);
				break;
			}
			case SV_CHOICE: {
				choiceBox = new FXListBox(body, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
				int sel = 0;
				for (size_t i = 0; i < def->choices.size(); i++) {
					choiceBox->appendItem(def->choices[i].label);
					if (def->choices[i].value == initial) sel = (int)i;
				}
				choiceBox->setNumVisible((int)def->choices.size());
				choiceBox->setCurrentItem(sel);
				controls.push_back(choiceBox);
				break;
			}
		}

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		updateEnabled();
	}

	// Lange Richtliniennamen umbrechen, statt den Dialog zu sprengen.
	static FXString wrapLabel(const char* text, int width) {
		std::string in = text, out, line;
		std::istringstream iss(in);
		std::string word;
		while (iss >> word) {
			if (!line.empty() && (int)(line.size() + 1 + word.size()) > width) { out += line + "\n"; line.clear(); }
			if (!line.empty()) line += " ";
			line += word;
		}
		out += line;
		return out.c_str();
	}

	void updateEnabled() {
		for (auto* w : controls) {
			if (defineCheck->getCheck()) w->enable(); else w->disable();
		}
	}
	long onDefine(FXObject*, FXSelector, void*) { updateEnabled(); return 1; }

	bool isDefined() const { return defineCheck->getCheck(); }
	std::string getValue() const {
		switch (def->kind) {
			case SV_NUMBER: return std::to_string(spinner->getValue());
			case SV_AUDIT: return std::to_string((auditSuccess->getCheck() ? 1 : 0) | (auditFailure->getCheck() ? 2 : 0));
			case SV_TEXT: return trimStr(textField->getText().text());
			case SV_CHOICE: {
				int i = choiceBox->getCurrentItem();
				return std::to_string(i >= 0 && i < (int)def->choices.size() ? def->choices[i].value : 0);
			}
			default: return std::to_string(choice);
		}
	}
	virtual ~SecPolicyEditDialog() { delete choiceTarget; }
};
FXDEFMAP(SecPolicyEditDialog) SecPolicyEditDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, SecPolicyEditDialog::ID_DEFINE, SecPolicyEditDialog::onDefine),
};
FXIMPLEMENT(SecPolicyEditDialog, FXDialogBox, SecPolicyEditDialogMap, ARRAYNUMBER(SecPolicyEditDialogMap))

// ---------------------------------------------------------------------
// Konten als SIDs: GptTmpl.inf fuehrt Benutzerrechte und eingeschraenkte
// Gruppen als "*S-1-5-32-544". Aufloesung gegen AD (objectSid ueber
// ldapi) plus die festen SIDs, die es in keinem Verzeichnis gibt.
// ---------------------------------------------------------------------
static std::string sidFromBinary(const std::string& b) {
	if (b.size() < 8) return "";
	uint8_t rev = (uint8_t)b[0], count = (uint8_t)b[1];
	if (b.size() < 8 + 4u * count) return "";
	uint64_t auth = 0;
	for (int i = 2; i < 8; i++) auth = (auth << 8) | (uint8_t)b[i];
	std::string out = "S-" + std::to_string(rev) + "-" + std::to_string(auth);
	for (int i = 0; i < count; i++) {
		size_t o = 8 + 4 * i;
		uint32_t v = (uint8_t)b[o] | ((uint8_t)b[o + 1] << 8) | ((uint8_t)b[o + 2] << 16) | ((uint32_t)(uint8_t)b[o + 3] << 24);
		out += "-" + std::to_string(v);
	}
	return out;
}

struct WellKnownSid { const char* sid; const char* name; };
static const WellKnownSid WELL_KNOWN_SIDS[] = {
	{ "S-1-1-0", "Jeder" },
	{ "S-1-3-0", "ERSTELLER-BESITZER" },
	{ "S-1-5-2", "NETZWERK" },
	{ "S-1-5-3", "BATCH" },
	{ "S-1-5-4", "INTERAKTIV" },
	{ "S-1-5-6", "DIENST" },
	{ "S-1-5-7", "ANONYMOUS-ANMELDUNG" },
	{ "S-1-5-9", "DOMÄNENCONTROLLER DER ORGANISATION" },
	{ "S-1-5-11", "Authentifizierte Benutzer" },
	{ "S-1-5-18", "SYSTEM" },
	{ "S-1-5-19", "LOKALER DIENST" },
	{ "S-1-5-20", "NETZWERKDIENST" },
};

// Alle Benutzer und Gruppen (ohne Computerkonten) mit SID, fuer die
// Objektauswahl; groupsOnly fuer "Eingeschränkte Gruppen".
static std::vector<GroupEntry> listSecurityPrincipals(bool groupsOnly) {
	std::vector<GroupEntry> out;
	DomainInfo domain = detectDomain();
	std::string filter = groupsOnly ? "(objectClass=group)"
	                                : "(&(|(objectClass=user)(objectClass=group))(!(objectClass=computer)))";
	for (auto& rec : ldapiSearch(domain.baseDN.text(), "sub", filter, { "objectSid", "cn", "sAMAccountName", "objectClass" })) {
		GroupEntry e;
		e.dn = ldifFirst(rec, "dn");
		e.cn = ldifFirst(rec, "cn").c_str();
		e.sam = ldifFirst(rec, "sAMAccountName").c_str();
		e.folder = dnToFolder(e.dn);
		e.sid = sidFromBinary(ldifFirst(rec, "objectSid"));
		bool isGroup = false;
		auto range = rec.equal_range("objectclass");
		for (auto it = range.first; it != range.second; ++it) if (lowerCopy(it->second) == "group") isGroup = true;
		e.icon = isGroup ? resico_users : resico_user;
		if (e.sid.empty()) continue;
		out.push_back(e);
	}
	if (!groupsOnly) {
		for (auto& w : WELL_KNOWN_SIDS) {
			GroupEntry e;
			e.cn = w.name;
			e.sam = w.name;
			e.sid = w.sid;
			e.icon = resico_users;
			out.push_back(e);
		}
	}
	std::sort(out.begin(), out.end(), [](const GroupEntry& a, const GroupEntry& b) {
		return strcasecmp(a.cn.text(), b.cn.text()) < 0;
	});
	return out;
}

// "*S-1-5-32-544" -> "VORDEFINIERT\Administrators", "*S-1-5-21-...-512"
// -> "LINUX\Domain Admins". Unbekanntes bleibt, wie es ist.
static FXString accountTokenDisplay(const std::string& token, const std::vector<GroupEntry>& principals) {
	std::string t = trimStr(token);
	if (t.empty() || t[0] != '*') return t.c_str();
	std::string sid = t.substr(1);
	for (auto& w : WELL_KNOWN_SIDS) if (sid == w.sid) return w.name;
	for (auto& p : principals) {
		if (p.sid != sid) continue;
		if (sid.compare(0, 9, "S-1-5-32-") == 0) return "VORDEFINIERT\\" + p.sam;
		std::string conf = readFileUnprivileged("/etc/samba/smb.conf");
		FXString nb = smbConfValue(conf, "workgroup"); nb.upper();
		return nb + "\\" + p.sam;
	}
	return t.c_str();
}

static std::vector<std::string> splitAccountList(const std::string& value) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : value) {
		if (c == ',') { if (!trimStr(cur).empty()) out.push_back(trimStr(cur)); cur.clear(); }
		else cur += c;
	}
	if (!trimStr(cur).empty()) out.push_back(trimStr(cur));
	return out;
}

static std::string joinAccountList(const std::vector<std::string>& list) {
	std::string out;
	for (auto& s : list) { if (!out.empty()) out += ","; out += s; }
	return out;
}

// ---------------------------------------------------------------------
// Benutzerrechte ([Privilege Rights]) -- Bezeichnungen wie im deutschen
// Windows 2000.
// ---------------------------------------------------------------------
struct UserRightDef { const char* key; const char* label; };
static const std::vector<UserRightDef> USER_RIGHTS = {
	{ "SeTcbPrivilege", "Als Teil des Betriebssystems handeln" },
	{ "SeSystemtimePrivilege", "Ändern der Systemzeit" },
	{ "SeIncreaseBasePriorityPrivilege", "Anheben der Zeitplanungspriorität" },
	{ "SeBatchLogonRight", "Anmelden als Batchauftrag" },
	{ "SeDenyBatchLogonRight", "Anmelden als Batchauftrag verweigern" },
	{ "SeServiceLogonRight", "Anmelden als Dienst" },
	{ "SeDenyServiceLogonRight", "Anmelden als Dienst verweigern" },
	{ "SeMachineAccountPrivilege", "Arbeitsstationen zur Domäne hinzufügen" },
	{ "SeNetworkLogonRight", "Auf diesen Computer vom Netzwerk aus zugreifen" },
	{ "SeChangeNotifyPrivilege", "Auslassen der durchsuchenden Überprüfung" },
	{ "SeDebugPrivilege", "Debuggen von Programmen" },
	{ "SeUndockPrivilege", "Entfernen des Computers von der Dockingstation" },
	{ "SeIncreaseQuotaPrivilege", "Erhöhen von Kontingenten" },
	{ "SeEnableDelegationPrivilege", "Ermöglichen, dass Computer- und Benutzerkonten für Delegierungszwecke vertraut wird" },
	{ "SeCreatePagefilePrivilege", "Erstellen einer Auslagerungsdatei" },
	{ "SeProfileSingleProcessPrivilege", "Erstellen eines Profils für einen Einzelprozess" },
	{ "SeSystemProfilePrivilege", "Erstellen eines Profils der Systemleistung" },
	{ "SeCreateTokenPrivilege", "Erstellen eines Tokenobjekts" },
	{ "SeCreatePermanentPrivilege", "Erstellen von dauerhaft freigegebenen Objekten" },
	{ "SeAssignPrimaryTokenPrivilege", "Ersetzen eines Tokens auf Prozessebene" },
	{ "SeRemoteShutdownPrivilege", "Erzwingen des Herunterfahrens von einem Remotesystem aus" },
	{ "SeAuditPrivilege", "Generieren von Sicherheitsüberwachungen" },
	{ "SeShutdownPrivilege", "Herunterfahren des Systems" },
	{ "SeLoadDriverPrivilege", "Laden und Entfernen von Gerätetreibern" },
	{ "SeInteractiveLogonRight", "Lokal anmelden" },
	{ "SeDenyInteractiveLogonRight", "Lokal anmelden verweigern" },
	{ "SeLockMemoryPrivilege", "Sperren von Seiten im Speicher" },
	{ "SeSyncAgentPrivilege", "Synchronisieren von Verzeichnisdienstdaten" },
	{ "SeTakeOwnershipPrivilege", "Übernehmen des Besitzes von Dateien und Objekten" },
	{ "SeSystemEnvironmentPrivilege", "Verändern der Firmwareumgebungsvariablen" },
	{ "SeSecurityPrivilege", "Verwalten von Überwachungs- und Sicherheitsprotokollen" },
	{ "SeBackupPrivilege", "Sichern von Dateien und Verzeichnissen" },
	{ "SeRestorePrivilege", "Wiederherstellen von Dateien und Verzeichnissen" },
	{ "SeDenyNetworkLogonRight", "Zugriff vom Netzwerk auf diesen Computer verweigern" },
};

// ---------------------------------------------------------------------
// Kontenliste mit Hinzufuegen/Entfernen -- Grundbaustein fuer die
// Benutzerrechte-Dialog und die beiden Listen bei eingeschraenkten
// Gruppen.
// ---------------------------------------------------------------------
class AccountListPanel : public FXVerticalFrame {
	FXDECLARE(AccountListPanel)
private:
	FXList* list = nullptr;
	std::vector<std::string> tokens;
	const std::vector<GroupEntry>* principals = nullptr;
	FXString pickerTitle;
protected:
	AccountListPanel() {}
public:
	enum { ID_ADD = FXVerticalFrame::ID_LAST, ID_REMOVE };
	AccountListPanel(FXComposite* p, const std::vector<GroupEntry>& principals_, const std::vector<std::string>& initial,
	                 const FXString& pickerTitle_)
		: FXVerticalFrame(p, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,4),
		  tokens(initial), principals(&principals_), pickerTitle(pickerTitle_) {
		FXPacker* lf = new FXPacker(this, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		list = new FXList(lf, NULL, 0, LIST_EXTENDEDSELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXHorizontalFrame* btns = new FXHorizontalFrame(this, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btns, "&Hinzufügen...", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "&Entfernen", NULL, this, ID_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		reload();
	}
	void reload() {
		list->clearItems();
		for (auto& t : tokens) list->appendItem(accountTokenDisplay(t, *principals));
	}
	long onAdd(FXObject*, FXSelector, void*) {
		DomainInfo domain = detectDomain();
		GroupPickerDialog dlg(this, domain.realm, *principals, pickerTitle.text(), resico_users);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		for (int idx : dlg.getResult()) {
			std::string tok = "*" + (*principals)[idx].sid;
			if (std::find(tokens.begin(), tokens.end(), tok) == tokens.end()) tokens.push_back(tok);
		}
		reload();
		return 1;
	}
	long onRemove(FXObject*, FXSelector, void*) {
		for (FXint i = list->getNumItems() - 1; i >= 0; i--)
			if (list->isItemSelected(i) && i < (FXint)tokens.size()) tokens.erase(tokens.begin() + i);
		reload();
		return 1;
	}
	long onUpdRemove(FXObject* sender, FXSelector, void*) {
		bool any = false;
		for (FXint i = 0; i < list->getNumItems() && !any; i++) any = list->isItemSelected(i);
		sender->handle(this, FXSEL(SEL_COMMAND, any ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	const std::vector<std::string>& getTokens() const { return tokens; }
	virtual ~AccountListPanel() {}
};
FXDEFMAP(AccountListPanel) AccountListPanelMap[] = {
	FXMAPFUNC(SEL_COMMAND, AccountListPanel::ID_ADD, AccountListPanel::onAdd),
	FXMAPFUNC(SEL_COMMAND, AccountListPanel::ID_REMOVE, AccountListPanel::onRemove),
	FXMAPFUNC(SEL_UPDATE, AccountListPanel::ID_REMOVE, AccountListPanel::onUpdRemove),
};
FXIMPLEMENT(AccountListPanel, FXVerticalFrame, AccountListPanelMap, ARRAYNUMBER(AccountListPanelMap))

// Dialog "Sicherheitsrichtlinieneinstellung" fuer ein Benutzerrecht.
class UserRightDialog : public FXDialogBox {
	FXDECLARE(UserRightDialog)
private:
	FXCheckButton* defineCheck = nullptr;
	AccountListPanel* panel = nullptr;
protected:
	UserRightDialog() {}
public:
	enum { ID_DEFINE = FXDialogBox::ID_LAST };
	UserRightDialog(FXWindow* owner, const UserRightDef& def, bool defined, const std::vector<std::string>& tokens,
	                const std::vector<GroupEntry>& principals)
		: FXDialogBox(owner, "Sicherheitsrichtlinieneinstellung", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,400) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,8);
		FXHorizontalFrame* head = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,0);
		new FXLabel(head, "", sharedPngIcon(resico_key), LAYOUT_TOP);
		new FXLabel(head, SecPolicyEditDialog::wrapLabel(def.label, 50), NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		defineCheck = new FXCheckButton(main, "Diese Richtlinieneinstellungen &definieren:", this, ID_DEFINE);
		defineCheck->setCheck(defined);
		panel = new AccountListPanel(main, principals, tokens, "Benutzer oder Gruppen auswählen");
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		updateEnabled();
	}
	void updateEnabled() {
		std::vector<FXWindow*> stack = { panel };
		while (!stack.empty()) {
			FXWindow* w = stack.back(); stack.pop_back();
			if (defineCheck->getCheck()) w->enable(); else w->disable();
			for (FXWindow* c = w->getFirst(); c; c = c->getNext()) stack.push_back(c);
		}
	}
	long onDefine(FXObject*, FXSelector, void*) { updateEnabled(); return 1; }
	bool isDefined() const { return defineCheck->getCheck(); }
	const std::vector<std::string>& getTokens() const { return panel->getTokens(); }
	virtual ~UserRightDialog() {}
};
FXDEFMAP(UserRightDialog) UserRightDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, UserRightDialog::ID_DEFINE, UserRightDialog::onDefine),
};
FXIMPLEMENT(UserRightDialog, FXDialogBox, UserRightDialogMap, ARRAYNUMBER(UserRightDialogMap))

// Dialog "Konfigurieren der Mitgliedschaft für ..." bei eingeschraenkten
// Gruppen: wer Mitglied der Gruppe ist, und wovon die Gruppe Mitglied ist.
class RestrictedGroupDialog : public FXDialogBox {
	FXDECLARE(RestrictedGroupDialog)
private:
	AccountListPanel* members = nullptr, *memberOf = nullptr;
protected:
	RestrictedGroupDialog() {}
public:
	RestrictedGroupDialog(FXWindow* owner, const FXString& groupDisplay, const std::vector<std::string>& membersInit,
	                      const std::vector<std::string>& memberOfInit, const std::vector<GroupEntry>& principals,
	                      const std::vector<GroupEntry>& groups)
		: FXDialogBox(owner, "Konfigurieren der Mitgliedschaft für " + groupDisplay, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,480) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		new FXLabel(main, "Mitglieder dieser Gruppe:");
		members = new AccountListPanel(main, principals, membersInit, "Benutzer oder Gruppen auswählen");
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		new FXLabel(main, "Diese Gruppe ist Mitglied von:");
		memberOf = new AccountListPanel(main, groups, memberOfInit, "Gruppen auswählen");
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	const std::vector<std::string>& getMembers() const { return members->getTokens(); }
	const std::vector<std::string>& getMemberOf() const { return memberOf->getTokens(); }
	virtual ~RestrictedGroupDialog() {}
};
FXIMPLEMENT(RestrictedGroupDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// GptTmpl.inf speichern: Datei samt Zwischenverzeichnissen anlegen, die
// SYSVOL-Rechte vom Zweig erben lassen, die Sicherheits-Erweiterung im
// GPO registrieren und die Version erhoehen.
//
// Kontorichtlinien wirken in AD nur aus GPOs, die mit der Domaene selbst
// verknuepft sind -- ein Windows-DC uebernimmt sie dann in das
// Domaenenobjekt. Samba tut das nicht von sich aus, deshalb wird das
// hier nachgebildet: ist das GPO mit der Domaenenwurzel verknuepft,
// gehen die definierten Werte zusaetzlich an
// "samba-tool domain passwordsettings".
// ---------------------------------------------------------------------
static bool gpoLinkedToDomainRoot(const DomainInfo& domain, const std::string& guid) {
	for (auto& l : parseGpLink(ldapiReadAttr(domain.baseDN.text(), "gPLink")))
		if (lowerCopy(l.guid) == lowerCopy(guid) && !(l.options & GPLINK_OPT_DISABLE)) return true;
	return false;
}

static void syncDomainAccountPolicy(InfFile& inf, FXString& note) {
	PasswordPolicy p = getPasswordPolicy();
	auto num = [&](const char* key, int& target) {
		std::string v;
		if (!inf.get("System Access", key, v)) return;
		try { target = std::stoi(v); } catch (...) {}
	};
	std::string cplx;
	if (inf.get("System Access", "PasswordComplexity", cplx)) p.complexity = (cplx == "1");
	num("PasswordHistorySize", p.historyLength);
	num("MinimumPasswordLength", p.minPwdLength);
	num("MinimumPasswordAge", p.minPwdAgeDays);
	num("MaximumPasswordAge", p.maxPwdAgeDays);
	num("LockoutDuration", p.lockoutDurationMins);
	num("LockoutBadCount", p.lockoutThreshold);
	num("ResetLockoutCount", p.lockoutWindowMins);
	FXString errorMsg;
	if (!setPasswordPolicy(p, errorMsg))
		note = "Die Kontorichtlinie der Domäne konnte nicht angepasst werden:\n\n" + errorMsg;
}

static bool saveGptTmpl(FXWindow* owner, const DomainInfo& domain, const std::string& guid, InfFile& inf,
                        bool accountPolicyTouched, FXString& errorMsg) {
	std::string branch = gpoBranchDir(domain, guid, true);
	std::string path = gptTmplPath(domain, guid);
	const std::string dirs[] = { branch + "/Microsoft", branch + "/Microsoft/Windows NT", branch + "/Microsoft/Windows NT/SecEdit" };
	for (auto& d : dirs) {
		bool existed = runAsRoot({ FXString("test"), FXString("-d"), FXString(d.c_str()) }) == 0;
		if (existed) continue;
		if (runAsRoot({ FXString("mkdir"), FXString(d.c_str()) }) != 0) {
			errorMsg = FXString("Verzeichnis konnte nicht angelegt werden:\n") + d.c_str();
			return false;
		}
		inheritSysvolPermissions(branch, d, true);
	}

	std::string encoded = serializeInf(inf);
	FXString tmpPath = "/tmp/ice2k-gpttmpl.inf";
	{
		std::ofstream out(tmpPath.text(), std::ios::binary);
		out.write(encoded.data(), (std::streamsize)encoded.size());
	}
	bool existed = runAsRoot({ FXString("test"), FXString("-f"), FXString(path.c_str()) }) == 0;
	int rc = runAsRoot({ FXString("cp"), tmpPath, FXString(path.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });
	if (rc != 0) { errorMsg = FXString("GptTmpl.inf konnte nicht geschrieben werden:\n") + path.c_str(); return false; }
	if (!existed) inheritSysvolPermissions(branch, path, false);

	std::string gpoDn = "CN=" + guid + ",CN=Policies,CN=System," + std::string(domain.baseDN.text());
	std::string log;
	if (!ensureExtensionRegistered(owner, domain.realm, gpoDn, true, SECEDIT_CSE_GUID, SECEDIT_TOOL_GUID, log, errorMsg)) return false;

	if (accountPolicyTouched && gpoLinkedToDomainRoot(domain, guid)) {
		FXString note;
		syncDomainAccountPolicy(inf, note);
		if (!note.empty()) FXMessageBox::warning(owner, MBOX_OK, "Gruppenrichtlinie", "%s", note.text());
	}
	return true;
}

// ---------------------------------------------------------------------
// Berechtigungen als SDDL -- gemeinsam fuer Systemdienste, Registrierung
// und Dateisystem. "O:..G:..D:<Flags>(ACE)(ACE)S:..." -- bearbeitet wird
// nur die DACL; Besitzer, Gruppe und SACL gehen unveraendert durch.
// ACE: "(Typ;Flags;Rechte;Objekt-GUID;geerbte GUID;SID)".
// ---------------------------------------------------------------------
struct SddlAce {
	std::string type;      // "A" zulassen, "D" verweigern, sonst unveraendert durchreichen
	std::string flags;     // "OICI", "CI", "ID" ...
	uint32_t mask = 0;
	std::string objGuid, inhGuid;
	std::string sid;       // immer als "S-1-..." (Kuerzel beim Lesen aufgeloest)
};

struct SddlDescriptor {
	std::string prefix;    // alles vor "D:" (O:/G:)
	std::string daclFlags; // "P", "AR", "AI" ...
	std::vector<SddlAce> aces;
	std::string suffix;    // ab "S:" (SACL)
	bool hasDacl = false;
};

struct SddlAlias { const char* alias; const char* sid; };
// Relative Kuerzel ("DA", "DU" ...) haengen an die Domaenen-SID.
static const SddlAlias SDDL_ALIASES[] = {
	{ "WD", "S-1-1-0" }, { "CO", "S-1-3-0" }, { "CG", "S-1-3-1" },
	{ "NU", "S-1-5-2" }, { "IU", "S-1-5-4" }, { "SU", "S-1-5-6" }, { "AN", "S-1-5-7" },
	{ "ED", "S-1-5-9" }, { "PS", "S-1-5-10" }, { "AU", "S-1-5-11" }, { "RC", "S-1-5-12" },
	{ "SY", "S-1-5-18" }, { "LS", "S-1-5-19" }, { "NS", "S-1-5-20" },
	{ "BA", "S-1-5-32-544" }, { "BU", "S-1-5-32-545" }, { "BG", "S-1-5-32-546" }, { "PU", "S-1-5-32-547" },
	{ "AO", "S-1-5-32-548" }, { "SO", "S-1-5-32-549" }, { "PO", "S-1-5-32-550" }, { "BO", "S-1-5-32-551" },
	{ "RE", "S-1-5-32-552" }, { "RU", "S-1-5-32-554" }, { "RD", "S-1-5-32-555" },
};
static const SddlAlias SDDL_DOMAIN_ALIASES[] = {
	{ "LA", "-500" }, { "LG", "-501" }, { "DA", "-512" }, { "DU", "-513" }, { "DG", "-514" },
	{ "DC", "-515" }, { "DD", "-516" }, { "CA", "-517" }, { "SA", "-518" }, { "EA", "-519" }, { "PA", "-520" },
};

static std::string sddlSidToFull(const std::string& s, const std::string& domainSid) {
	if (s.compare(0, 2, "S-") == 0) return s;
	for (auto& a : SDDL_ALIASES) if (s == a.alias) return a.sid;
	if (!domainSid.empty())
		for (auto& a : SDDL_DOMAIN_ALIASES) if (s == a.alias) return domainSid + a.sid;
	return s; // unbekannt -- so lassen, wie es war
}

static std::string sddlSidToShort(const std::string& full, const std::string& domainSid) {
	for (auto& a : SDDL_ALIASES) if (full == a.sid) return a.alias;
	if (!domainSid.empty())
		for (auto& a : SDDL_DOMAIN_ALIASES) if (full == domainSid + a.sid) return a.alias;
	return full;
}

struct SddlRightCode { const char* code; uint32_t mask; };
// Zusammengesetzte Kuerzel zuerst -- beim Schreiben wird ein exakt
// passender Gesamtwert bevorzugt, sonst Einzelbits, sonst hexadezimal.
static const SddlRightCode SDDL_COMBINED_RIGHTS[] = {
	{ "FA", 0x1F01FF }, { "FR", 0x120089 }, { "FW", 0x120116 }, { "FX", 0x1200A0 },
	{ "KA", 0xF003F }, { "KR", 0x20019 }, { "KW", 0x20006 },
};
static const SddlRightCode SDDL_BIT_RIGHTS[] = {
	{ "CC", 0x1 }, { "DC", 0x2 }, { "LC", 0x4 }, { "SW", 0x8 }, { "RP", 0x10 }, { "WP", 0x20 },
	{ "DT", 0x40 }, { "LO", 0x80 }, { "CR", 0x100 }, { "SD", 0x10000 }, { "RC", 0x20000 },
	{ "WD", 0x40000 }, { "WO", 0x80000 },
	{ "GA", 0x10000000 }, { "GX", 0x20000000 }, { "GW", 0x40000000 }, { "GR", 0x80000000 },
};

static uint32_t sddlParseRights(const std::string& r) {
	if (r.size() > 2 && (r.compare(0, 2, "0x") == 0 || r.compare(0, 2, "0X") == 0)) {
		try { return (uint32_t)std::stoul(r.substr(2), nullptr, 16); } catch (...) { return 0; }
	}
	uint32_t m = 0;
	for (size_t i = 0; i + 1 < r.size(); i += 2) {
		std::string c = r.substr(i, 2);
		bool found = false;
		for (auto& x : SDDL_COMBINED_RIGHTS) if (c == x.code) { m |= x.mask; found = true; }
		for (auto& x : SDDL_BIT_RIGHTS) if (c == x.code) { m |= x.mask; found = true; }
		// "KX" ist identisch mit KR
		if (!found && c == "KX") m |= 0x20019;
	}
	return m;
}

static std::string sddlFormatRights(uint32_t m) {
	for (auto& x : SDDL_COMBINED_RIGHTS) if (m == x.mask) return x.code;
	uint32_t rest = m;
	std::string out;
	for (auto& x : SDDL_BIT_RIGHTS) if (rest & x.mask) { out += x.code; rest &= ~x.mask; }
	if (rest == 0 && !out.empty()) return out;
	char buf[16];
	snprintf(buf, sizeof(buf), "0x%x", m);
	return buf;
}

static SddlDescriptor parseSddl(const std::string& sddl, const std::string& domainSid) {
	SddlDescriptor d;
	size_t dpos = sddl.find("D:");
	if (dpos == std::string::npos) { d.prefix = sddl; return d; }
	d.hasDacl = true;
	d.prefix = sddl.substr(0, dpos);
	size_t i = dpos + 2;
	while (i < sddl.size() && sddl[i] != '(' && sddl.compare(i, 2, "S:") != 0) d.daclFlags += sddl[i++];
	while (i < sddl.size() && sddl[i] == '(') {
		size_t end = sddl.find(')', i);
		if (end == std::string::npos) break;
		std::vector<std::string> f;
		std::string cur;
		for (size_t k = i + 1; k < end; k++) {
			if (sddl[k] == ';') { f.push_back(cur); cur.clear(); } else cur += sddl[k];
		}
		f.push_back(cur);
		if (f.size() >= 6) {
			SddlAce a;
			a.type = f[0];
			a.flags = f[1];
			a.mask = sddlParseRights(f[2]);
			a.objGuid = f[3];
			a.inhGuid = f[4];
			a.sid = sddlSidToFull(f[5], domainSid);
			d.aces.push_back(a);
		}
		i = end + 1;
	}
	d.suffix = sddl.substr(i);
	return d;
}

static std::string formatSddl(const SddlDescriptor& d, const std::string& domainSid) {
	std::string out = d.prefix;
	if (d.hasDacl) {
		out += "D:" + d.daclFlags;
		for (auto& a : d.aces)
			out += "(" + a.type + ";" + a.flags + ";" + sddlFormatRights(a.mask) + ";" + a.objGuid + ";" + a.inhGuid + ";" +
			       sddlSidToShort(a.sid, domainSid) + ")";
	}
	return out + d.suffix;
}

// ---------------------------------------------------------------------
// Einfache Berechtigungen je Objektart, wie sie der Dialog von Windows
// 2000 anbietet. Generische Rechte (GA/GR/GW/GX) werden vor dem Abgleich
// in die objektspezifischen Bits uebersetzt.
// ---------------------------------------------------------------------
enum SecObjectKind { SECOBJ_SERVICE, SECOBJ_REGISTRY, SECOBJ_FILE };

struct SimplePermission { const char* label; uint32_t mask; };

static const std::vector<SimplePermission>& simplePermissions(SecObjectKind kind) {
	static const std::vector<SimplePermission> service = {
		{ "Vollzugriff", 0xF01FF },
		{ "Lesen", 0x2018D },
		{ "Starten, beenden und anhalten", 0x70 },
		{ "Schreiben", 0x20002 },
		{ "Löschen", 0x10000 },
	};
	static const std::vector<SimplePermission> registry = {
		{ "Vollzugriff", 0xF003F },
		{ "Lesen", 0x20019 },
	};
	static const std::vector<SimplePermission> file = {
		{ "Vollzugriff", 0x1F01FF },
		{ "Ändern", 0x1301BF },
		{ "Lesen, Ausführen", 0x1200A9 },
		{ "Lesen", 0x120089 },
		{ "Schreiben", 0x100116 },
	};
	return kind == SECOBJ_SERVICE ? service : kind == SECOBJ_REGISTRY ? registry : file;
}

static uint32_t expandGenericRights(uint32_t m, SecObjectKind kind) {
	uint32_t all = kind == SECOBJ_SERVICE ? 0xF01FF : kind == SECOBJ_REGISTRY ? 0xF003F : 0x1F01FF;
	uint32_t read = kind == SECOBJ_SERVICE ? 0x2018D : kind == SECOBJ_REGISTRY ? 0x20019 : 0x120089;
	uint32_t write = kind == SECOBJ_SERVICE ? 0x20002 : kind == SECOBJ_REGISTRY ? 0x20006 : 0x120116;
	uint32_t exec = kind == SECOBJ_SERVICE ? 0x20170 : kind == SECOBJ_REGISTRY ? 0x20019 : 0x1200A0;
	uint32_t out = m & 0x0FFFFFFF;
	if (m & 0x10000000) out |= all;
	if (m & 0x80000000) out |= read;
	if (m & 0x40000000) out |= write;
	if (m & 0x20000000) out |= exec;
	return out;
}

// Vorgabe fuer neu hinzugefuegte Konten: Dateien/Ordner und Schluessel
// vererben an Unterobjekte, Dienste haben keine.
static const char* defaultAceFlags(SecObjectKind kind) {
	return kind == SECOBJ_FILE ? "OICI" : kind == SECOBJ_REGISTRY ? "CI" : "";
}

// Domaenen-SID aus der Kontenliste (die SID von "Domain Admins" ohne -512).
static std::string domainSidFromPrincipals(const std::vector<GroupEntry>& principals) {
	for (auto& p : principals) {
		const std::string& s = p.sid;
		if (s.compare(0, 9, "S-1-5-21-") == 0 && s.size() > 4 && s.compare(s.size() - 4, 4, "-512") == 0)
			return s.substr(0, s.size() - 4);
	}
	return "";
}

// ---------------------------------------------------------------------
// Dialog "Sicherheit für ..." -- oben die Konten, unten die einfachen
// Berechtigungen mit Zulassen/Verweigern. Geerbte Eintraege werden
// angezeigt, aber nicht veraendert; Konten, an denen nichts geaendert
// wurde, behalten ihre Eintraege Byte fuer Byte (auch Flags und
// Sonderrechte, die der einfache Dialog nicht darstellen kann).
// ---------------------------------------------------------------------
class SecurityDialog : public FXDialogBox {
	FXDECLARE(SecurityDialog)
private:
	struct Entry {
		std::string sid;
		uint32_t allow = 0, deny = 0;                 // explizit
		uint32_t inheritedAllow = 0, inheritedDeny = 0;
		std::string allowFlags, denyFlags;            // Flags der ersten expliziten Eintraege
		bool dirty = false;
	};

	SecObjectKind kind;
	std::string domainSid;
	const std::vector<GroupEntry>* principals = nullptr;
	SddlDescriptor desc;
	std::vector<Entry> entries;

	FXIconList* nameList = nullptr;
	std::vector<FXCheckButton*> allowChecks, denyChecks;
	FXCheckButton* inheritCheck = nullptr;

protected:
	SecurityDialog() {}
public:
	enum { ID_NAMES = FXDialogBox::ID_LAST, ID_ADD, ID_REMOVE, ID_INHERIT, ID_ALLOW_FIRST = ID_INHERIT + 1,
	       ID_ALLOW_LAST = ID_ALLOW_FIRST + 15, ID_DENY_FIRST, ID_DENY_LAST = ID_DENY_FIRST + 15 };

	SecurityDialog(FXWindow* owner, const FXString& objectName, SecObjectKind kind_, const std::string& sddl,
	               const std::vector<GroupEntry>& principals_)
		: FXDialogBox(owner, "Sicherheit für " + objectName, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0),
		  kind(kind_), principals(&principals_) {
		domainSid = domainSidFromPrincipals(principals_);
		desc = parseSddl(sddl, domainSid);
		desc.hasDacl = true;
		buildEntries();

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		new FXLabel(main, "&Name");
		FXHorizontalFrame* top = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 8,0);
		FXPacker* lf = new FXPacker(top, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FIX_HEIGHT, 0,0,0,130, 0,0,0,0);
		nameList = new FXIconList(lf, this, ID_NAMES, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		nameList->appendHeader("Name", NULL, 280);
		FXVerticalFrame* btns = new FXVerticalFrame(top, LAYOUT_FILL_Y | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,0,0, 0,6);
		new FXButton(btns, "&Hinzufügen...", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);
		new FXButton(btns, "&Entfernen", NULL, this, ID_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);

		FXMatrix* m = new FXMatrix(main, 3, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,6,0, 10,2);
		new FXLabel(m, "&Berechtigungen:", NULL, JUSTIFY_LEFT | LAYOUT_FILL_COLUMN | LAYOUT_FILL_X);
		new FXLabel(m, "Zulassen", NULL, JUSTIFY_CENTER_X);
		new FXLabel(m, "Verweigern", NULL, JUSTIFY_CENTER_X);
		const auto& perms = simplePermissions(kind);
		for (size_t i = 0; i < perms.size(); i++) {
			new FXLabel(m, perms[i].label, NULL, JUSTIFY_LEFT | LAYOUT_FILL_COLUMN | LAYOUT_FILL_X);
			allowChecks.push_back(new FXCheckButton(m, "", this, ID_ALLOW_FIRST + (int)i, CHECKBUTTON_NORMAL | LAYOUT_CENTER_X));
			denyChecks.push_back(new FXCheckButton(m, "", this, ID_DENY_FIRST + (int)i, CHECKBUTTON_NORMAL | LAYOUT_CENTER_X));
		}

		if (kind != SECOBJ_SERVICE) {
			inheritCheck = new FXCheckButton(main, "Vererbbare übergeordnete Berechtigungen &übernehmen", this, ID_INHERIT);
			inheritCheck->setCheck(desc.daclFlags.find('P') == std::string::npos);
		}

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);

		reloadNames(0);
	}

	void buildEntries() {
		auto entryFor = [&](const std::string& sid) -> Entry& {
			for (auto& e : entries) if (e.sid == sid) return e;
			Entry e;
			e.sid = sid;
			entries.push_back(e);
			return entries.back();
		};
		for (auto& a : desc.aces) {
			if ((a.type != "A" && a.type != "D") || !a.objGuid.empty() || !a.inhGuid.empty()) continue;
			// "Nur Unterobjekte" (IO) gilt nicht fuer das Objekt selbst.
			bool inherited = a.flags.find("ID") != std::string::npos;
			uint32_t m = expandGenericRights(a.mask, kind);
			Entry& e = entryFor(a.sid);
			if (a.type == "A") {
				if (inherited) e.inheritedAllow |= m;
				else { if (e.allow == 0 && e.allowFlags.empty()) e.allowFlags = a.flags; e.allow |= m; }
			} else {
				if (inherited) e.inheritedDeny |= m;
				else { if (e.deny == 0 && e.denyFlags.empty()) e.denyFlags = a.flags; e.deny |= m; }
			}
		}
	}

	FXString displayName(const std::string& sid) const {
		return accountTokenDisplay("*" + sid, *principals);
	}

	void reloadNames(int select) {
		nameList->clearItems();
		for (auto& e : entries) {
			const unsigned char* icon = resico_users;
			for (auto& p : *principals) if (p.sid == e.sid && p.icon) icon = p.icon;
			FXIcon* ic = sharedPngIcon(icon);
			nameList->appendItem(displayName(e.sid), ic, ic);
		}
		if (!entries.empty()) {
			select = std::max(0, std::min(select, (int)entries.size() - 1));
			nameList->setCurrentItem(select);
			nameList->selectItem(select);
			nameList->makeItemVisible(select);
		}
		refreshChecks();
	}

	int currentEntry() const {
		int i = nameList->getCurrentItem();
		return (i >= 0 && i < (int)entries.size()) ? i : -1;
	}

	void refreshChecks() {
		int idx = currentEntry();
		const auto& perms = simplePermissions(kind);
		for (size_t i = 0; i < perms.size(); i++) {
			if (idx < 0) {
				allowChecks[i]->setCheck(FALSE); allowChecks[i]->disable();
				denyChecks[i]->setCheck(FALSE); denyChecks[i]->disable();
				continue;
			}
			const Entry& e = entries[idx];
			uint32_t pm = perms[i].mask;
			bool expAllow = (e.allow & pm) == pm, inhAllow = (e.inheritedAllow & pm) == pm;
			bool expDeny = (e.deny & pm) == pm, inhDeny = (e.inheritedDeny & pm) == pm;
			allowChecks[i]->setCheck(expAllow || inhAllow);
			denyChecks[i]->setCheck(expDeny || inhDeny);
			// Wie im Original: nur geerbt = grau angehakt, nicht aenderbar.
			if (inhAllow && !expAllow) allowChecks[i]->disable(); else allowChecks[i]->enable();
			if (inhDeny && !expDeny) denyChecks[i]->disable(); else denyChecks[i]->enable();
		}
	}

	long onNameSelected(FXObject*, FXSelector, void*) { refreshChecks(); return 1; }

	// Beim Abhaken einer Berechtigung nur das wegnehmen, was keine andere,
	// kleinere angehakte Berechtigung braucht -- wie im Original: "Ändern"
	// abhaken laesst "Lesen, Ausführen", "Lesen" und "Schreiben" stehen,
	// nimmt aber "Vollzugriff" mit (das "Ändern" enthaelt).
	uint32_t removePermission(uint32_t current, size_t i) const {
		const auto& perms = simplePermissions(kind);
		uint32_t pm = perms[i].mask, keep = 0, drop = pm;
		for (size_t j = 0; j < perms.size(); j++) {
			if (j == i) continue;
			uint32_t other = perms[j].mask;
			bool checked = (current & other) == other;
			bool containsThis = (other & pm) == pm;
			if (containsThis) drop |= other;          // umfassendere Rechte fallen mit weg
			else if (checked) keep |= other;          // kleinere angehakte bleiben
		}
		return (current & ~drop) | keep;
	}

	long onAllow(FXObject*, FXSelector sel, void*) {
		int idx = currentEntry();
		int i = FXSELID(sel) - ID_ALLOW_FIRST;
		if (idx < 0) return 1;
		Entry& e = entries[idx];
		uint32_t pm = simplePermissions(kind)[i].mask;
		if (allowChecks[i]->getCheck()) { e.allow |= pm; e.deny = removePermission(e.deny, i); }
		else e.allow = removePermission(e.allow, i);
		e.dirty = true;
		refreshChecks();
		return 1;
	}

	long onDeny(FXObject*, FXSelector sel, void*) {
		int idx = currentEntry();
		int i = FXSELID(sel) - ID_DENY_FIRST;
		if (idx < 0) return 1;
		Entry& e = entries[idx];
		uint32_t pm = simplePermissions(kind)[i].mask;
		if (denyChecks[i]->getCheck()) { e.deny |= pm; e.allow = removePermission(e.allow, i); }
		else e.deny = removePermission(e.deny, i);
		e.dirty = true;
		refreshChecks();
		return 1;
	}

	long onAdd(FXObject*, FXSelector, void*) {
		DomainInfo domain = detectDomain();
		GroupPickerDialog dlg(this, domain.realm, *principals, "Benutzer, Computer oder Gruppen auswählen", resico_users);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		int select = currentEntry();
		for (int pi : dlg.getResult()) {
			const std::string& sid = (*principals)[pi].sid;
			int found = -1;
			for (size_t k = 0; k < entries.size(); k++) if (entries[k].sid == sid) found = (int)k;
			if (found < 0) {
				// Wie im Original: ein neues Konto bekommt zunaechst "Lesen".
				Entry e;
				e.sid = sid;
				e.allow = kind == SECOBJ_FILE ? 0x1200A9 : simplePermissions(kind)[1].mask;
				e.allowFlags = defaultAceFlags(kind);
				e.dirty = true;
				entries.push_back(e);
				found = (int)entries.size() - 1;
			}
			select = found;
		}
		reloadNames(select);
		return 1;
	}

	long onRemove(FXObject*, FXSelector, void*) {
		int idx = currentEntry();
		if (idx < 0) return 1;
		Entry& e = entries[idx];
		if (e.inheritedAllow || e.inheritedDeny) {
			FXMessageBox::error(this, MBOX_OK, "Sicherheit",
				"Dieses Objekt kann nicht entfernt werden, da es Berechtigungen vom\n"
				"übergeordneten Objekt erbt. Deaktivieren Sie zuerst die Vererbung.");
			return 1;
		}
		std::string sid = e.sid;
		desc.aces.erase(std::remove_if(desc.aces.begin(), desc.aces.end(), [&](const SddlAce& a) {
			return a.sid == sid && (a.type == "A" || a.type == "D") && a.objGuid.empty() && a.inhGuid.empty();
		}), desc.aces.end());
		entries.erase(entries.begin() + idx);
		reloadNames(idx);
		return 1;
	}

	long onUpdRemove(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, currentEntry() >= 0 ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}

	long onInherit(FXObject*, FXSelector, void*) {
		bool inherit = inheritCheck->getCheck();
		std::string f = desc.daclFlags;
		f.erase(std::remove(f.begin(), f.end(), 'P'), f.end());
		if (!inherit) {
			// Wie im Original: geerbte Eintraege beim Abschalten der Vererbung
			// als eigene uebernehmen, statt die Berechtigungen zu verlieren.
			if (FXMessageBox::question(this, MBOX_YES_NO, "Sicherheit",
			        "Die geerbten Berechtigungen als explizite Berechtigungen übernehmen?\n\n"
			        "\"Nein\" entfernt die geerbten Berechtigungen.") == MBOX_CLICKED_YES) {
				for (auto& a : desc.aces) {
					size_t p = a.flags.find("ID");
					if (p != std::string::npos) a.flags.erase(p, 2);
				}
			} else {
				desc.aces.erase(std::remove_if(desc.aces.begin(), desc.aces.end(), [](const SddlAce& a) {
					return a.flags.find("ID") != std::string::npos;
				}), desc.aces.end());
			}
			f = "P" + f;
			desc.daclFlags = f;
			entries.clear();
			buildEntries();
			reloadNames(0);
			return 1;
		}
		desc.daclFlags = f;
		return 1;
	}

	// Setzt die DACL wieder zusammen: je geaendertem Konto erst
	// Verweigern, dann Zulassen (kanonische Reihenfolge), unveraenderte
	// Eintraege bleiben, geerbte ans Ende.
	std::string getSddl() {
		std::vector<SddlAce> explicitAces, inheritedAces;
		std::set<std::string> dirtySids;
		for (auto& e : entries) if (e.dirty) dirtySids.insert(e.sid);
		for (auto& a : desc.aces) {
			bool simple = (a.type == "A" || a.type == "D") && a.objGuid.empty() && a.inhGuid.empty();
			if (a.flags.find("ID") != std::string::npos) { inheritedAces.push_back(a); continue; }
			if (simple && dirtySids.count(a.sid)) continue; // wird neu erzeugt
			explicitAces.push_back(a);
		}
		std::vector<SddlAce> denies, allows;
		for (auto& e : entries) {
			if (!e.dirty) continue;
			if (e.deny) { SddlAce a; a.type = "D"; a.flags = e.denyFlags.empty() ? defaultAceFlags(kind) : e.denyFlags; a.mask = e.deny; a.sid = e.sid; denies.push_back(a); }
			if (e.allow) { SddlAce a; a.type = "A"; a.flags = e.allowFlags.empty() ? defaultAceFlags(kind) : e.allowFlags; a.mask = e.allow; a.sid = e.sid; allows.push_back(a); }
		}
		std::vector<SddlAce> result;
		for (auto& a : denies) result.push_back(a);
		for (auto& a : explicitAces) if (a.type == "D") result.push_back(a);
		for (auto& a : allows) result.push_back(a);
		for (auto& a : explicitAces) if (a.type != "D") result.push_back(a);
		for (auto& a : inheritedAces) result.push_back(a);
		SddlDescriptor out = desc;
		out.aces = result;
		return formatSddl(out, domainSid);
	}

	virtual ~SecurityDialog() {}
};
FXDEFMAP(SecurityDialog) SecurityDialogMap[] = {
	FXMAPFUNC(SEL_CHANGED, SecurityDialog::ID_NAMES, SecurityDialog::onNameSelected),
	FXMAPFUNC(SEL_SELECTED, SecurityDialog::ID_NAMES, SecurityDialog::onNameSelected),
	FXMAPFUNC(SEL_COMMAND, SecurityDialog::ID_ADD, SecurityDialog::onAdd),
	FXMAPFUNC(SEL_COMMAND, SecurityDialog::ID_REMOVE, SecurityDialog::onRemove),
	FXMAPFUNC(SEL_UPDATE, SecurityDialog::ID_REMOVE, SecurityDialog::onUpdRemove),
	FXMAPFUNC(SEL_COMMAND, SecurityDialog::ID_INHERIT, SecurityDialog::onInherit),
	FXMAPFUNCS(SEL_COMMAND, SecurityDialog::ID_ALLOW_FIRST, SecurityDialog::ID_ALLOW_LAST, SecurityDialog::onAllow),
	FXMAPFUNCS(SEL_COMMAND, SecurityDialog::ID_DENY_FIRST, SecurityDialog::ID_DENY_LAST, SecurityDialog::onDeny),
};
FXIMPLEMENT(SecurityDialog, FXDialogBox, SecurityDialogMap, ARRAYNUMBER(SecurityDialogMap))

// ---------------------------------------------------------------------
// Systemdienste ([Service General Setting]): je Dienst eine Zeile
// "\"Name\",Starttyp,\"SDDL\"" -- Starttyp 2 = Automatisch, 3 = Manuell,
// 4 = Deaktiviert. Die Liste der Dienste kommt wie im Original vom
// Rechner, auf dem der Editor laeuft; hier also die systemd-Dienste
// dieses Servers.
// ---------------------------------------------------------------------
static const char* SERVICE_SECTION = "Service General Setting";

// Standard-Berechtigungen, wenn ein Dienst zum ersten Mal definiert wird:
// Administratoren und SYSTEM Vollzugriff, interaktive Benutzer und
// Dienste duerfen den Status abfragen.
static const char* SERVICE_DEFAULT_SDDL =
	"D:AR(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

struct ServicePolicy { bool defined = false; int startMode = 0; std::string sddl; };

// Zerlegt "\"a\",2,\"b\"" in seine Felder (Anfuehrungszeichen entfernt).
static std::vector<std::string> splitQuotedCsv(const std::string& line) {
	std::vector<std::string> out;
	std::string cur;
	bool quoted = false;
	for (char c : line) {
		if (c == '"') { quoted = !quoted; continue; }
		if (c == ',' && !quoted) { out.push_back(trimStr(cur)); cur.clear(); continue; }
		cur += c;
	}
	out.push_back(trimStr(cur));
	return out;
}

static ServicePolicy findServicePolicy(InfFile& inf, const std::string& name) {
	ServicePolicy sp;
	auto* sec = inf.find(SERVICE_SECTION);
	if (!sec) return sp;
	for (auto& kv : *sec) {
		auto f = splitQuotedCsv(kv.first);
		if (f.size() < 2 || lowerCopy(f[0]) != lowerCopy(name)) continue;
		sp.defined = true;
		try { sp.startMode = std::stoi(f[1]); } catch (...) {}
		sp.sddl = f.size() > 2 ? f[2] : "";
		return sp;
	}
	return sp;
}

static void setServicePolicy(InfFile& inf, const std::string& name, const ServicePolicy& sp) {
	auto matches = [&](const std::pair<std::string, std::string>& kv) {
		auto f = splitQuotedCsv(kv.first);
		return !f.empty() && lowerCopy(f[0]) == lowerCopy(name);
	};
	if (auto* sec = inf.find(SERVICE_SECTION))
		sec->erase(std::remove_if(sec->begin(), sec->end(), matches), sec->end());
	if (!sp.defined) return;
	std::string line = "\"" + name + "\"," + std::to_string(sp.startMode) + ",\"" + sp.sddl + "\"";
	if (!inf.find(SERVICE_SECTION)) inf.set(SERVICE_SECTION, line, INF_BARE_LINE);
	else inf.find(SERVICE_SECTION)->push_back({ line, INF_BARE_LINE });
}

static const char* serviceModeLabel(int mode) {
	return mode == 2 ? "Automatisch" : mode == 3 ? "Manuell" : mode == 4 ? "Deaktiviert" : "Nicht definiert";
}

// Dialog "Sicherheitsrichtlinieneinstellung" fuer einen Dienst.
class ServicePolicyDialog : public FXDialogBox {
	FXDECLARE(ServicePolicyDialog)
private:
	FXCheckButton* defineCheck = nullptr;
	FXint mode = 2;
	FXDataTarget modeTarget;
	std::vector<FXWindow*> controls;
	FXString serviceName;
	std::string sddl;
	const std::vector<GroupEntry>* principals = nullptr;
protected:
	ServicePolicyDialog() {}
public:
	enum { ID_DEFINE = FXDialogBox::ID_LAST, ID_SECURITY };
	ServicePolicyDialog(FXWindow* owner, const FXString& serviceName_, const ServicePolicy& sp,
	                    const std::vector<GroupEntry>& principals_)
		: FXDialogBox(owner, "Sicherheitsrichtlinieneinstellung", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0),
		  mode(sp.defined && sp.startMode >= 2 && sp.startMode <= 4 ? sp.startMode : 2), modeTarget(mode),
		  serviceName(serviceName_), sddl(sp.sddl.empty() ? SERVICE_DEFAULT_SDDL : sp.sddl), principals(&principals_) {
		const FXString& serviceName = serviceName_;
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,8);
		FXHorizontalFrame* head = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,0);
		new FXLabel(head, "", sharedPngIcon(resico_server), LAYOUT_TOP);
		new FXLabel(head, serviceName, NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		defineCheck = new FXCheckButton(main, "Diese Richtlinieneinstellung &definieren", this, ID_DEFINE);
		defineCheck->setCheck(sp.defined);
		FXVerticalFrame* body = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 20,0,0,0, 0,4);
		controls.push_back(new FXLabel(body, "Startmodus für Dienst auswählen:"));
		controls.push_back(new FXRadioButton(body, "&Automatisch", &modeTarget, FXDataTarget::ID_OPTION + 2));
		controls.push_back(new FXRadioButton(body, "&Manuell", &modeTarget, FXDataTarget::ID_OPTION + 3));
		controls.push_back(new FXRadioButton(body, "D&eaktiviert", &modeTarget, FXDataTarget::ID_OPTION + 4));

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		controls.push_back(new FXButton(btnf, "&Sicherheit bearbeiten...", NULL, this, ID_SECURITY, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3));
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		updateEnabled();
	}
	void updateEnabled() {
		for (auto* w : controls) { if (defineCheck->getCheck()) w->enable(); else w->disable(); }
	}
	long onDefine(FXObject*, FXSelector, void*) { updateEnabled(); return 1; }
	long onSecurity(FXObject*, FXSelector, void*) {
		SecurityDialog dlg(this, serviceName, SECOBJ_SERVICE, sddl, *principals);
		if (dlg.execute(PLACEMENT_OWNER)) sddl = dlg.getSddl();
		return 1;
	}
	bool isDefined() const { return defineCheck->getCheck(); }
	int getMode() const { return mode; }
	const std::string& getSddl() const { return sddl; }
	virtual ~ServicePolicyDialog() {}
};
FXDEFMAP(ServicePolicyDialog) ServicePolicyDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, ServicePolicyDialog::ID_DEFINE, ServicePolicyDialog::onDefine),
	FXMAPFUNC(SEL_COMMAND, ServicePolicyDialog::ID_SECURITY, ServicePolicyDialog::onSecurity),
};
FXIMPLEMENT(ServicePolicyDialog, FXDialogBox, ServicePolicyDialogMap, ARRAYNUMBER(ServicePolicyDialogMap))

// ---------------------------------------------------------------------
// Registrierung ([Registry Keys]) und Dateisystem ([File Security]):
// je Objekt eine Zeile "\"Pfad\",Modus,\"SDDL\"".
//
// Modus -- hier widersprechen sich Microsofts Quellen: [MS-GPSB] 2.2.7
// nennt 0 = weitergeben, 1 = ersetzen, 2 = nicht ersetzen. Die WMI-Klasse
// RSOP_RegistryKey aus der tatsaechlichen Implementierung (SceRsop.mof)
// ordnet dagegen 0 = Inherit, 1 = Ignore, 2 = Overwrite zu, und Windows'
// eigene Vorlagen setzen kritische Eintraege (z.B. regedit.exe) auf 2.
// Wir folgen der Implementierung.
// ---------------------------------------------------------------------
static const int OBJMODE_INHERIT = 0;   // vererbbare Berechtigungen weitergeben
static const int OBJMODE_IGNORE = 1;    // Objekt nicht konfigurieren
static const int OBJMODE_OVERWRITE = 2; // Berechtigungen der Unterobjekte ersetzen

struct ObjectPolicy { std::string path; int mode = OBJMODE_INHERIT; std::string sddl; };

static const char* objectSection(SecObjectKind kind) {
	return kind == SECOBJ_REGISTRY ? "Registry Keys" : "File Security";
}

static std::vector<ObjectPolicy> listObjectPolicies(InfFile& inf, SecObjectKind kind) {
	std::vector<ObjectPolicy> out;
	auto* sec = inf.find(objectSection(kind));
	if (!sec) return out;
	for (auto& kv : *sec) {
		auto f = splitQuotedCsv(kv.first);
		if (f.size() < 2 || f[0].empty()) continue;
		ObjectPolicy op;
		op.path = f[0];
		try { op.mode = std::stoi(f[1]); } catch (...) {}
		op.sddl = f.size() > 2 ? f[2] : "";
		out.push_back(op);
	}
	std::sort(out.begin(), out.end(), [](const ObjectPolicy& a, const ObjectPolicy& b) { return germanLess(a.path, b.path); });
	return out;
}

// Ersetzt (oder mit remove=true: entfernt) den Eintrag fuer op.path.
static void storeObjectPolicy(InfFile& inf, SecObjectKind kind, const ObjectPolicy& op, bool remove) {
	const char* section = objectSection(kind);
	auto matches = [&](const std::pair<std::string, std::string>& kv) {
		auto f = splitQuotedCsv(kv.first);
		return !f.empty() && lowerCopy(f[0]) == lowerCopy(op.path);
	};
	if (auto* sec = inf.find(section))
		sec->erase(std::remove_if(sec->begin(), sec->end(), matches), sec->end());
	if (remove) return;
	std::string line = "\"" + op.path + "\"," + std::to_string(op.mode) + ",\"" + op.sddl + "\"";
	if (!inf.find(section)) inf.set(section, line, INF_BARE_LINE);
	else inf.find(section)->push_back({ line, INF_BARE_LINE });
}

// Vorgabe fuer ein neu hinzugefuegtes Objekt: Administratoren und SYSTEM
// Vollzugriff, Benutzer lesend -- vererbbar.
static std::string defaultObjectSddl(SecObjectKind kind) {
	return kind == SECOBJ_REGISTRY ? "D:AR(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;BU)"
	                               : "D:AR(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)";
}

// Registrierungspfade in der Schreibweise der Vorlage: "MACHINE\...",
// "USERS\...", "CLASSES_ROOT\..." -- HKLM/HKEY_LOCAL_MACHINE usw. werden
// umgesetzt. Leerer Rueckgabewert = ungueltig.
static std::string normalizeRegistryPath(std::string p) {
	p = trimStr(p);
	std::replace(p.begin(), p.end(), '/', '\\');
	while (!p.empty() && p.back() == '\\') p.pop_back();
	size_t bs = p.find('\\');
	std::string root = lowerCopy(p.substr(0, bs));
	std::string rest = bs == std::string::npos ? "" : p.substr(bs);
	if (root == "hklm" || root == "hkey_local_machine" || root == "machine") root = "MACHINE";
	else if (root == "hku" || root == "hkey_users" || root == "users") root = "USERS";
	else if (root == "hkcr" || root == "hkey_classes_root" || root == "classes_root") root = "CLASSES_ROOT";
	else return "";
	if (p.find('"') != std::string::npos) return "";
	return root + rest;
}

// Dialog "Sicherheitsrichtlinieneinstellung" fuer einen Schluessel bzw.
// eine Datei/einen Ordner: Modus plus "Berechtigungen bearbeiten...".
class ObjectPolicyDialog : public FXDialogBox {
	FXDECLARE(ObjectPolicyDialog)
private:
	SecObjectKind kind;
	FXString objectName;
	std::string sddl;
	const std::vector<GroupEntry>* principals = nullptr;
	FXint configure = 1;    // 1 = konfigurieren, 0 = nicht konfigurieren
	FXint propagate = OBJMODE_INHERIT;
	FXDataTarget configureTarget, propagateTarget;
	std::vector<FXWindow*> configControls;
protected:
	ObjectPolicyDialog() {}
public:
	enum { ID_CONFIGURE = FXDialogBox::ID_LAST, ID_PERMISSIONS };
	ObjectPolicyDialog(FXWindow* owner, SecObjectKind kind_, const ObjectPolicy& op, const std::vector<GroupEntry>& principals_)
		: FXDialogBox(owner, "Sicherheitsrichtlinieneinstellung", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,540,0),
		  kind(kind_), objectName(op.path.c_str()), sddl(op.sddl.empty() ? defaultObjectSddl(kind_) : op.sddl), principals(&principals_),
		  configure(op.mode == OBJMODE_IGNORE ? 0 : 1), propagate(op.mode == OBJMODE_OVERWRITE ? OBJMODE_OVERWRITE : OBJMODE_INHERIT),
		  configureTarget(configure, this, ID_CONFIGURE), propagateTarget(propagate) {
		bool reg = kind == SECOBJ_REGISTRY;
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		FXHorizontalFrame* head = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,0);
		new FXLabel(head, "", sharedPngIcon(reg ? resico_key : resico_folder), LAYOUT_TOP);
		new FXLabel(head, SecPolicyEditDialog::wrapLabel(op.path.c_str(), 55), NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		new FXRadioButton(main, reg ? "Diesen Schlüssel &konfigurieren" : "Diese Datei bzw. diesen Ordner &konfigurieren",
		                  &configureTarget, FXDataTarget::ID_OPTION + 1, RADIOBUTTON_NORMAL | JUSTIFY_LEFT);
		FXVerticalFrame* body = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 20,0,0,0, 0,4);
		configControls.push_back(new FXRadioButton(body, reg ? "Vererbbare Berechtigungen an alle &Unterschlüssel weitergeben"
		                                                     : "Vererbbare Berechtigungen an alle &Unterordner und Dateien weitergeben",
		                                           &propagateTarget, FXDataTarget::ID_OPTION + OBJMODE_INHERIT, RADIOBUTTON_NORMAL | JUSTIFY_LEFT));
		configControls.push_back(new FXRadioButton(body, reg ? "Vorhandene Berechtigungen für alle Unterschlüssel durch\nvererbbare Berechtigungen &ersetzen"
		                                                     : "Vorhandene Berechtigungen für alle Unterordner und Dateien\ndurch vererbbare Berechtigungen &ersetzen",
		                                           &propagateTarget, FXDataTarget::ID_OPTION + OBJMODE_OVERWRITE, RADIOBUTTON_NORMAL | JUSTIFY_LEFT));
		new FXRadioButton(main, reg ? "Diesen Schlüssel &nicht konfigurieren" : "Diese Datei bzw. diesen Ordner &nicht konfigurieren",
		                  &configureTarget, FXDataTarget::ID_OPTION + 0, RADIOBUTTON_NORMAL | JUSTIFY_LEFT);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		configControls.push_back(new FXButton(btnf, "&Berechtigungen bearbeiten...", NULL, this, ID_PERMISSIONS, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3));
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		updateEnabled();
	}
	void updateEnabled() {
		for (auto* w : configControls) { if (configure) w->enable(); else w->disable(); }
	}
	long onConfigure(FXObject*, FXSelector, void*) { updateEnabled(); return 1; }
	long onPermissions(FXObject*, FXSelector, void*) { editPermissions(); return 1; }
	bool editPermissions() {
		SecurityDialog dlg(this, objectName, kind, sddl, *principals);
		if (!dlg.execute(PLACEMENT_OWNER)) return false;
		sddl = dlg.getSddl();
		return true;
	}
	int getMode() const { return configure ? propagate : OBJMODE_IGNORE; }
	const std::string& getSddl() const { return sddl; }
	virtual ~ObjectPolicyDialog() {}
};
FXDEFMAP(ObjectPolicyDialog) ObjectPolicyDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, ObjectPolicyDialog::ID_CONFIGURE, ObjectPolicyDialog::onConfigure),
	FXMAPFUNC(SEL_COMMAND, ObjectPolicyDialog::ID_PERMISSIONS, ObjectPolicyDialog::onPermissions),
};
FXIMPLEMENT(ObjectPolicyDialog, FXDialogBox, ObjectPolicyDialogMap, ARRAYNUMBER(ObjectPolicyDialogMap))

// ---------------------------------------------------------------------
// Fenster "Gruppenrichtlinie" -- Nachbau des Gruppenrichtlinienobjekt-
// Editors: links der Baum mit Computer- und Benutzerkonfiguration,
// rechts der Inhalt des gewaehlten Knotens. Doppelklick bearbeitet.
// ---------------------------------------------------------------------
class GpoEditorWindow : public FXDialogBox, public SvcPanelDelegate {
	FXDECLARE(GpoEditorWindow)
private:
	enum NodeKind { GN_FOLDER, GN_SOFTWARE, GN_SCRIPTS, GN_SECPOL, GN_RIGHTS, GN_RESTRICTED, GN_SERVICES, GN_REGKEYS, GN_FILES, GN_ADM, GN_ADMCAT, GN_FOLDERREDIR, GN_TODO };
	struct Node {
		NodeKind kind = GN_FOLDER;
		bool machine = true;
		const std::vector<SecPolicyDef>* defs = nullptr;
	};

	DomainInfo domain;
	std::string guid;
	FXString gpoName;
	FXTreeList* tree = nullptr;
	FXIconList* list = nullptr;
	FXSwitcher* rightSwitcher = nullptr;   // 0 = Liste, 1 = Dienste-Panel
	SvcPanel* servicePanel = nullptr;
	FXLabel* status = nullptr;
	std::map<FXTreeItem*, Node> nodes;
	FXTreeItem* shownItem = nullptr;

	// Zustand des rechten Bereichs
	std::vector<FXTreeItem*> rowChildren;
	std::vector<SoftwarePackageInfo> rowPackages;
	std::vector<int> rowDefs;                 // GN_SECPOL/GN_RIGHTS: Zeile -> Tabellenindex
	std::vector<std::string> rowGroups;       // GN_RESTRICTED: Zeile -> "*SID" der Gruppe
	std::vector<ObjectPolicy> rowObjects;     // GN_REGKEYS/GN_FILES
	std::vector<GroupEntry> principals;       // einmal geladen, fuer SID-Namen
	std::vector<AdmPolicy*> rowPolicies;      // GN_ADMCAT: Zeilen nach den Unterkategorien
	std::vector<std::string> rowPolicyKeys;

	// Administrative Vorlagen: je Zweig (0 = Computer, 1 = Benutzer) die
	// Kategorien aus den .adm-Dateien und die Registry.pol des GPOs.
	PolHive admHive[2];
	struct AdmNodeInfo { AdmCategory* cat; std::vector<const AdmCategory*> chain; int hive; };
	std::map<FXTreeItem*, AdmNodeInfo> admNodes;
	bool principalsLoaded = false;
	InfFile inf;

protected:
	GpoEditorWindow() {}
public:
	enum { ID_TREE = FXDialogBox::ID_LAST, ID_LIST, ID_NEW_PACKAGE, ID_REMOVE_PACKAGE, ID_ADD_RGROUP, ID_DELETE_RGROUP, ID_EDIT_RGROUP, ID_ADD_OBJECT, ID_DELETE_OBJECT, ID_EDIT_OBJECT };

	GpoEditorWindow(FXWindow* owner, const DomainInfo& domain_, const std::string& guid_, const FXString& gpoName_)
		: FXDialogBox(owner, "Gruppenrichtlinie", DECOR_ALL, 0,0,900,620),
		  domain(domain_), guid(guid_), gpoName(gpoName_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
		FXSplitter* splitter = new FXSplitter(main, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
		FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,340,0, 0,0,0,0);
		tree = new FXTreeList(treeframe, this, ID_TREE,
		                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
		rightSwitcher = new FXSwitcher(splitter, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		FXPacker* listframe = new FXPacker(rightSwitcher, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		list = new FXIconList(listframe, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		// Dieselbe Dienstliste wie in "Dienste" und der Computerverwaltung --
		// nur mit den Spalten und dem Doppelklick der Gruppenrichtlinie.
		servicePanel = new SvcPanel(rightSwitcher, sharedPngIcon(resico_server), this);
		status = new FXLabel(main, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);
		buildTree();
	}

	FXTreeItem* add(FXTreeItem* parent, const char* label, const unsigned char* icon, NodeKind kind, bool machine,
	                const std::vector<SecPolicyDef>* defs = nullptr) {
		FXIcon* ic = sharedPngIcon(icon);
		FXTreeItem* it = tree->appendItem(parent, label, ic, ic);
		Node n;
		n.kind = kind;
		n.machine = machine;
		n.defs = defs;
		nodes[it] = n;
		return it;
	}

	void addAdmCategories(FXTreeItem* parent, std::vector<AdmCategory>& cats, std::vector<const AdmCategory*> chain, int hive) {
		for (auto& cat : cats) {
			FXTreeItem* item = add(parent, cat.label.c_str(), resico_folder, GN_ADMCAT, hive == 0);
			std::vector<const AdmCategory*> newChain = chain;
			newChain.push_back(&cat);
			admNodes[item] = { &cat, newChain, hive };
			addAdmCategories(item, cat.subCategories, newChain, hive);
		}
	}

	void loadAdmBranch(FXTreeItem* item, int hive) {
		PolHive& h = admHive[hive];
		h.categories = loadMergedAdmCategories(hive == 0 ? "MACHINE" : "USER");
		h.polPath = gpoBranchDir(domain, guid, hive == 0) + "/Registry.pol";
		h.file = readRegPolAsRoot(h.polPath);
		h.lookup = buildRegLookup(h.file);
		addAdmCategories(item, h.categories, {}, hive);
	}

	void buildTree() {
		FXTreeItem* root = add(NULL, (gpoName + " [" + serverFqdn(domain) + "]").text(), resico_network, GN_FOLDER, true);

		FXTreeItem* comp = add(root, "Computerkonfiguration", resico_server, GN_FOLDER, true);
		FXTreeItem* cSw = add(comp, "Softwareeinstellungen", resico_folder, GN_FOLDER, true);
		add(cSw, "Softwareinstallation", resico_folder, GN_SOFTWARE, true);
		FXTreeItem* cWin = add(comp, "Windows-Einstellungen", resico_folder, GN_FOLDER, true);
		add(cWin, "Skripts (Start/Herunterfahren)", resico_folder, GN_SCRIPTS, true);
		FXTreeItem* cSec = add(cWin, "Sicherheitseinstellungen", resico_key, GN_FOLDER, true);
		FXTreeItem* kto = add(cSec, "Kontorichtlinien", resico_key, GN_FOLDER, true);
		add(kto, "Kennwortrichtlinien", resico_key, GN_SECPOL, true, &SEC_PASSWORD_POLICIES);
		add(kto, "Kontosperrungsrichtlinien", resico_key, GN_SECPOL, true, &SEC_LOCKOUT_POLICIES);
		FXTreeItem* lok = add(cSec, "Lokale Richtlinien", resico_key, GN_FOLDER, true);
		add(lok, "Überwachungsrichtlinien", resico_key, GN_SECPOL, true, &SEC_AUDIT_POLICIES);
		add(lok, "Zuweisen von Benutzerrechten", resico_key, GN_RIGHTS, true);
		add(lok, "Sicherheitsoptionen", resico_key, GN_SECPOL, true, &SEC_OPTIONS);
		FXTreeItem* evt = add(cSec, "Ereignisprotokoll", resico_key, GN_FOLDER, true);
		add(evt, "Einstellungen für Ereignisprotokolle", resico_key, GN_SECPOL, true, &SEC_EVENTLOG_POLICIES);
		add(cSec, "Eingeschränkte Gruppen", resico_key, GN_RESTRICTED, true);
		add(cSec, "Systemdienste", resico_key, GN_SERVICES, true);
		add(cSec, "Registrierung", resico_key, GN_REGKEYS, true);
		add(cSec, "Dateisystem", resico_key, GN_FILES, true);
		FXTreeItem* pk = add(cSec, "Richtlinien öffentlicher Schlüssel", resico_folder, GN_FOLDER, true);
		add(pk, "Agenten für Wiederherstellung von verschlüsselten Daten", resico_folder, GN_TODO, true);
		add(pk, "Einstellungen der automatischen Zertifikatsanforderung", resico_folder, GN_TODO, true);
		add(pk, "Vertrauenswürdige Stammzertifizierungsstellen", resico_folder, GN_TODO, true);
		add(pk, "Organisationsvertrauen", resico_folder, GN_TODO, true);
		add(cSec, "IP-Sicherheitsrichtlinien auf Active Directory", resico_key, GN_TODO, true);
		FXTreeItem* admMachine = add(comp, "Administrative Vorlagen", resico_folder, GN_ADM, true);

		FXTreeItem* usr = add(root, "Benutzerkonfiguration", resico_user, GN_FOLDER, false);
		FXTreeItem* uSw = add(usr, "Softwareeinstellungen", resico_folder, GN_FOLDER, false);
		add(uSw, "Softwareinstallation", resico_folder, GN_SOFTWARE, false);
		FXTreeItem* uWin = add(usr, "Windows-Einstellungen", resico_folder, GN_FOLDER, false);
		add(uWin, "Internet Explorer-Wartung", resico_folder, GN_TODO, false);
		add(uWin, "Skripts (Anmelden/Abmelden)", resico_folder, GN_SCRIPTS, false);
		FXTreeItem* uSec = add(uWin, "Sicherheitseinstellungen", resico_key, GN_FOLDER, false);
		FXTreeItem* uPk = add(uSec, "Richtlinien öffentlicher Schlüssel", resico_folder, GN_FOLDER, false);
		add(uPk, "Organisationsvertrauen", resico_folder, GN_TODO, false);
		add(uWin, "Remoteinstallationsdienste", resico_folder, GN_TODO, false);
		add(uWin, "Ordnerumleitung", resico_folder, GN_FOLDERREDIR, false);
		FXTreeItem* admUser = add(usr, "Administrative Vorlagen", resico_folder, GN_ADM, false);
		if (haveAdmFiles()) {
			getApp()->beginWaitCursor();
			loadAdmBranch(admMachine, 0);
			loadAdmBranch(admUser, 1);
			getApp()->endWaitCursor();
		}

		// Aufgeklappt wie im Original beim Oeffnen: die Computerkonfiguration
		// bis in die Sicherheitseinstellungen, die Benutzerkonfiguration eine
		// Ebene tiefer.
		for (FXTreeItem* it : { root, comp, cSw, cWin, cSec, kto, lok, evt, pk, usr, uSw, uWin })
			tree->expandTree(it);
		tree->setCurrentItem(root);
		tree->selectItem(root);
		showNode(root);
	}

	void setHeaders(const std::vector<std::pair<const char*, int>>& headers) {
		while (list->getNumHeaders() > 0) list->removeHeader(0);
		for (auto& h : headers) list->appendHeader(h.first, NULL, h.second);
	}

	void showNode(FXTreeItem* item) {
		shownItem = item;
		list->clearItems();
		rowChildren.clear();
		rowPackages.clear();
		rowDefs.clear();
		rowGroups.clear();
		rowObjects.clear();
		rowPolicies.clear();
		rowPolicyKeys.clear();
		status->setText(" ");
		rightSwitcher->setCurrent(0);
		auto nit = nodes.find(item);
		if (nit == nodes.end()) return;
		const Node& node = nit->second;

		switch (node.kind) {
			case GN_FOLDER: {
				setHeaders({ { "Name", 320 } });
				for (FXTreeItem* c = item->getFirst(); c; c = c->getNext()) {
					list->appendItem(c->getText(), c->getClosedIcon(), c->getClosedIcon());
					rowChildren.push_back(c);
				}
				break;
			}
			case GN_SECPOL: {
				setHeaders({ { "Richtlinie", 330 }, { "Computereinstellung", 200 } });
				inf = loadGptTmpl(domain, guid);
				FXIcon* ic = sharedPngIcon(resico_key);
				// Wie im Original alphabetisch nach Bezeichnung.
				for (size_t i = 0; i < node.defs->size(); i++) rowDefs.push_back((int)i);
				std::sort(rowDefs.begin(), rowDefs.end(), [&](int a, int b) {
					return germanLess((*node.defs)[a].label, (*node.defs)[b].label);
				});
				for (int i : rowDefs) {
					const SecPolicyDef& def = (*node.defs)[i];
					std::string v;
					bool defined = readSecValue(inf, def, v);
					list->appendItem(FXString(def.label) + "\t" + secValueText(def, defined, v), ic, ic);
				}
				break;
			}
			case GN_RIGHTS: {
				setHeaders({ { "Richtlinie", 330 }, { "Computereinstellung", 260 } });
				inf = loadGptTmpl(domain, guid);
				ensurePrincipals();
				FXIcon* ic = sharedPngIcon(resico_key);
				for (size_t i = 0; i < USER_RIGHTS.size(); i++) rowDefs.push_back((int)i);
				std::sort(rowDefs.begin(), rowDefs.end(), [&](int a, int b) {
					return germanLess(USER_RIGHTS[a].label, USER_RIGHTS[b].label);
				});
				for (int i : rowDefs) {
					std::string v;
					FXString shown = "Nicht definiert";
					if (inf.get("Privilege Rights", USER_RIGHTS[i].key, v)) {
						shown = "";
						for (auto& t : splitAccountList(v)) {
							if (!shown.empty()) shown += ", ";
							shown += accountTokenDisplay(t, principals);
						}
					}
					list->appendItem(FXString(USER_RIGHTS[i].label) + "\t" + shown, ic, ic);
				}
				break;
			}
			case GN_REGKEYS:
			case GN_FILES: {
				setHeaders({ { "Objektname", 360 }, { "Berechtigung", 140 }, { "Überwachung", 140 } });
				inf = loadGptTmpl(domain, guid);
				SecObjectKind k = node.kind == GN_REGKEYS ? SECOBJ_REGISTRY : SECOBJ_FILE;
				rowObjects = listObjectPolicies(inf, k);
				FXIcon* ic = sharedPngIcon(k == SECOBJ_REGISTRY ? resico_key : resico_folder);
				for (auto& op : rowObjects) {
					const char* perm = op.mode == OBJMODE_IGNORE ? "Ignoriert" : op.mode == OBJMODE_OVERWRITE ? "Ersetzen" : "Vererben";
					const char* audit = op.sddl.find("S:") != std::string::npos ? "Konfiguriert" : "Nicht konfiguriert";
					list->appendItem(FXString(op.path.c_str()) + "\t" + perm + "\t" + audit, ic, ic);
				}
				status->setText(k == SECOBJ_REGISTRY ? " Rechtsklick in die Liste: Schlüssel hinzufügen, bearbeiten oder löschen."
				                                     : " Rechtsklick in die Liste: Datei hinzufügen, bearbeiten oder löschen.");
				break;
			}
			case GN_SERVICES: {
				// Jedes Mal frisch: Vorlage und alle installierten Dienste.
				inf = loadGptTmpl(domain, guid);
				rightSwitcher->setCurrent(1);
				getApp()->beginWaitCursor();
				servicePanel->reload();
				getApp()->endWaitCursor();
				break;
			}
			case GN_RESTRICTED: {
				setHeaders({ { "Gruppenname", 220 }, { "Mitglieder", 200 }, { "Mitglied von", 200 } });
				inf = loadGptTmpl(domain, guid);
				ensurePrincipals();
				FXIcon* ic = sharedPngIcon(resico_users);
				if (auto* sec = inf.find("Group Membership")) {
					for (auto& kv : *sec) {
						std::string k = kv.first;
						size_t p = lowerCopy(k).find("__member");
						if (p == std::string::npos) continue;
						std::string g = k.substr(0, p);
						if (std::find(rowGroups.begin(), rowGroups.end(), g) == rowGroups.end()) rowGroups.push_back(g);
					}
				}
				for (auto& g : rowGroups) {
					list->appendItem(accountTokenDisplay(g, principals) + "\t" + restrictedListText(g, "__Members") +
					                 "\t" + restrictedListText(g, "__Memberof"), ic, ic);
				}
				status->setText(" Rechtsklick in die Liste: Gruppe hinzufügen oder löschen.");
				break;
			}
			case GN_SOFTWARE: {
				setHeaders({ { "Name", 320 }, { "Bereitstellungsstatus", 180 } });
				getApp()->beginWaitCursor();
				rowPackages = listSoftwarePackages(this, domain, guid.c_str(), node.machine);
				getApp()->endWaitCursor();
				FXIcon* ic = sharedPngIcon(resico_folder);
				for (auto& p : rowPackages) {
					const char* st = p.pendingRemoval ? "Wird deinstalliert" : p.published ? "Veröffentlicht" : "Zugewiesen";
					list->appendItem(FXString(p.displayName.c_str()) + "\t" + st, ic, ic);
				}
				status->setText(" Rechtsklick in die Liste: Neues Paket hinzufügen oder ein Paket entfernen.");
				break;
			}
			case GN_SCRIPTS: {
				setHeaders({ { "Name", 320 } });
				FXIcon* ic = sharedPngIcon(resico_folder);
				if (node.machine) { list->appendItem("Starten", ic, ic); list->appendItem("Herunterfahren", ic, ic); }
				else { list->appendItem("Anmelden", ic, ic); list->appendItem("Abmelden", ic, ic); }
				break;
			}
			case GN_FOLDERREDIR: {
				setHeaders({ { "Name", 320 } });
				FXIcon* ic = sharedPngIcon(resico_folder);
				for (auto& t : FOLDER_REDIR_TARGETS) {
					FXString label = t.label;
					if (label.right(1) == ":") label.trunc(label.length() - 1);
					list->appendItem(label, ic, ic);
				}
				break;
			}
			case GN_ADM: {
				setHeaders({ { "Name", 320 } });
				for (FXTreeItem* c = item->getFirst(); c; c = c->getNext()) {
					list->appendItem(c->getText(), c->getClosedIcon(), c->getClosedIcon());
					rowChildren.push_back(c);
				}
				if (!item->getFirst())
					status->setText(haveAdmFiles() ? " In den .adm-Dateien gibt es für diesen Zweig keine Kategorien."
					                               : " Es sind keine administrativen Vorlagen (.adm-Dateien) eingerichtet.");
				break;
			}
			case GN_ADMCAT: {
				setHeaders({ { "Richtlinie", 330 }, { "Einstellung", 160 } });
				auto ait = admNodes.find(item);
				if (ait == admNodes.end()) break;
				FXIcon* folderIc = sharedPngIcon(resico_folder);
				for (FXTreeItem* c = item->getFirst(); c; c = c->getNext()) {
					list->appendItem(c->getText(), folderIc, folderIc);
					rowChildren.push_back(c);
				}
				PolHive& h = admHive[ait->second.hive];
				FXIcon* ic = sharedPngIcon(resico_key);
				for (auto& pol : ait->second.cat->policies) {
					std::string key = resolveEffectiveKey(pol, ait->second.chain);
					PolicyState st = determinePolicyState(pol, key, h.lookup);
					list->appendItem(FXString(pol.label.c_str()) + "\t" + admStateLabel(st), ic, ic);
					rowPolicies.push_back(&pol);
					rowPolicyKeys.push_back(key);
				}
				break;
			}
			case GN_TODO: {
				setHeaders({ { "Name", 320 } });
				status->setText(" Dieser Bereich ist in ice2k noch nicht umgesetzt.");
				break;
			}
		}
	}

	long onTreeChanged(FXObject*, FXSelector, void*) {
		FXTreeItem* cur = tree->getCurrentItem();
		if (cur && cur != shownItem) showNode(cur);
		return 1;
	}

	void editAdmPolicy(int row) {
		auto ait = admNodes.find(shownItem);
		int pIdx = row - (int)rowChildren.size();
		if (ait == admNodes.end() || pIdx < 0 || pIdx >= (int)rowPolicies.size() || !requireRoot()) return;
		int hive = ait->second.hive;
		PolHive& h = admHive[hive];
		// Frisch lesen -- ein anderes Fenster koennte inzwischen geschrieben haben.
		h.file = readRegPolAsRoot(h.polPath);
		h.lookup = buildRegLookup(h.file);

		AdmPolicy* pol = rowPolicies[pIdx];
		const std::string& key = rowPolicyKeys[pIdx];
		PolicyState curState = determinePolicyState(*pol, key, h.lookup);
		std::vector<std::string> curPartValues;
		for (auto& part : pol->parts) {
			std::string vn = !part.valuename.empty() ? part.valuename : pol->valuename;
			curPartValues.push_back(readStoredPartValue(h, key, vn));
		}

		PolicyEditDialog dlg(this, *pol, curState, curPartValues);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		PendingEdit ed;
		ed.state = dlg.getState();
		ed.partValues = dlg.getPartValues();
		ed.effectiveKey = key;
		// Unveraendert? Die Eingabefelder zaehlen nur bei "Aktiviert" -- sonst
		// zeigt der Dialog bloss Vorgabewerte an.
		if (ed.state == curState && (ed.state != POLSTATE_ENABLED || ed.partValues == curPartValues)) return;

		std::vector<RegPolEntry> entries = h.file.entries;
		applyAdmPolicyEdit(entries, h.lookup, pol, ed);

		std::string err;
		FXString tmpPath = "/tmp/ice2k-regpol-tmp";
		if (!writeRegPolFile(tmpPath.text(), entries, err)) { FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", err.c_str()); return; }
		std::string branch = gpoBranchDir(domain, guid, hive == 0);
		bool existed = runAsRoot({ FXString("test"), FXString("-f"), FXString(h.polPath.c_str()) }) == 0;
		int rc = runAsRoot({ FXString("cp"), tmpPath, FXString(h.polPath.c_str()) });
		runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });
		if (rc != 0) { FXMessageBox::error(this, MBOX_OK, "Fehler", "Konnte %s nicht schreiben.", h.polPath.c_str()); return; }
		if (!existed) inheritSysvolPermissions(branch, h.polPath, false);

		// Registry-Erweiterung eintragen und Version des Zweigs erhoehen.
		std::string gpoDn = "CN=" + guid + ",CN=Policies,CN=System," + std::string(domain.baseDN.text());
		std::string log;
		FXString errorMsg;
		if (!ensureExtensionRegistered(this, domain.realm, gpoDn, hive == 0, REGISTRY_CSE_GUID,
		                               hive == 0 ? REGISTRY_TOOL_GUID_MACHINE : REGISTRY_TOOL_GUID_USER, log, errorMsg))
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());

		h.file = readRegPolAsRoot(h.polPath);
		h.lookup = buildRegLookup(h.file);
		reselect(row);
	}

	void selectTreeItem(FXTreeItem* it) {
		if (it->getParent()) tree->expandTree(it->getParent());
		tree->selectItem(it);
		tree->setCurrentItem(it);
		tree->makeItemVisible(it);
		showNode(it);
	}

	long onListDoubleClick(FXObject*, FXSelector, void* ptr) {
		FXint idx = (FXint)(FXival)ptr;
		auto nit = nodes.find(shownItem);
		if (nit == nodes.end() || idx < 0 || idx >= list->getNumItems()) return 1;
		const Node node = nit->second;
		switch (node.kind) {
			case GN_FOLDER:
			case GN_ADM:
				if (idx < (int)rowChildren.size()) selectTreeItem(rowChildren[idx]);
				break;
			case GN_ADMCAT:
				if (idx < (int)rowChildren.size()) selectTreeItem(rowChildren[idx]);
				else editAdmPolicy(idx);
				break;
			case GN_SECPOL:
				editSecurityPolicy(node, idx);
				break;
			case GN_RIGHTS:
				editUserRight(idx);
				break;
			case GN_RESTRICTED:
				editRestrictedGroup(idx);
				break;
			case GN_REGKEYS:
			case GN_FILES:
				editObjectPolicy(idx);
				break;
			case GN_SCRIPTS: {
				ScriptsDialog dlg(this, domain, guid.c_str());
				dlg.execute(PLACEMENT_OWNER);
				break;
			}
			case GN_FOLDERREDIR:
				editFolderRedirection();
				break;
			default:
				break;
		}
		return 1;
	}

	// ---- SvcPanelDelegate: Systemdienste ------------------------------
	virtual std::vector<std::pair<FXString, FXint> > svcColumns() {
		return { { "Dienstname", 260 }, { "Starttyp", 140 }, { "Berechtigung", 140 } };
	}
	virtual FXString svcRowText(const svc::ServiceInfo& info) {
		ServicePolicy sp = findServicePolicy(inf, info.displayName());
		return FXString(info.displayName().c_str()) + "\t" + serviceModeLabel(sp.defined ? sp.startMode : 0) + "\t" +
		       (sp.defined && !sp.sddl.empty() ? "Konfiguriert" : "Nicht definiert");
	}
	virtual void svcActivate(FXWindow*, const svc::ServiceInfo& info) {
		if (!requireRoot()) return;
		inf = loadGptTmpl(domain, guid);
		std::string name = info.displayName();
		ServicePolicy sp = findServicePolicy(inf, name);
		ensurePrincipals();
		ServicePolicyDialog dlg(this, name.c_str(), sp, principals);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		if (dlg.isDefined() == sp.defined && (!sp.defined || (dlg.getMode() == sp.startMode && dlg.getSddl() == sp.sddl))) return;
		ServicePolicy changed = sp;
		changed.defined = dlg.isDefined();
		changed.startMode = dlg.getMode();
		changed.sddl = dlg.getSddl();
		setServicePolicy(inf, name, changed);
		saveTemplate(false);
		inf = loadGptTmpl(domain, guid);
	}

	SecObjectKind shownObjectKind() {
		auto nit = nodes.find(shownItem);
		return (nit != nodes.end() && nit->second.kind == GN_REGKEYS) ? SECOBJ_REGISTRY : SECOBJ_FILE;
	}

	void editObjectPolicy(int row) {
		if (row < 0 || row >= (int)rowObjects.size() || !requireRoot()) return;
		SecObjectKind k = shownObjectKind();
		ensurePrincipals();
		ObjectPolicy op = rowObjects[row];
		ObjectPolicyDialog dlg(this, k, op, principals);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		if (dlg.getMode() == op.mode && dlg.getSddl() == op.sddl) return;
		inf = loadGptTmpl(domain, guid);
		op.mode = dlg.getMode();
		op.sddl = dlg.getSddl();
		storeObjectPolicy(inf, k, op, false);
		saveTemplate(false);
		reselect(row);
	}

	long onAddObject(FXObject*, FXSelector, void*) {
		if (!requireRoot()) return 1;
		SecObjectKind k = shownObjectKind();
		bool reg = k == SECOBJ_REGISTRY;
		FXString path = reg ? "MACHINE\\SOFTWARE\\" : "%SystemRoot%\\";
		// Eine Linux-Maschine hat weder Registrierung noch Windows-Pfade zum
		// Durchsuchen -- der Pfad wird wie auf dem Client angegeben.
		if (!FXInputDialog::getString(path, this, reg ? "Schlüssel hinzufügen" : "Datei hinzufügen",
		        reg ? "Registrierungsschlüssel auf den Clients (MACHINE\\..., USERS\\... oder CLASSES_ROOT\\...):"
		            : "Datei oder Ordner auf den Clients (z.B. %SystemRoot%\\system32 oder C:\\Daten):")) return 1;
		std::string p = trimStr(path.text());
		if (reg) {
			p = normalizeRegistryPath(p);
			if (p.empty()) {
				FXMessageBox::error(this, MBOX_OK, "Schlüssel hinzufügen",
					"Der Pfad muss mit MACHINE, USERS oder CLASSES_ROOT beginnen\n(HKLM, HKU und HKCR werden umgesetzt).");
				return 1;
			}
		} else {
			std::replace(p.begin(), p.end(), '/', '\\');
			while (p.size() > 3 && p.back() == '\\') p.pop_back();
			if (p.empty() || p.find('"') != std::string::npos) {
				FXMessageBox::error(this, MBOX_OK, "Datei hinzufügen", "Bitte einen gültigen Pfad ohne Anführungszeichen angeben.");
				return 1;
			}
		}
		for (size_t i = 0; i < rowObjects.size(); i++) {
			if (lowerCopy(rowObjects[i].path) != lowerCopy(p)) continue;
			reselect((int)i);
			editObjectPolicy((int)i);
			return 1;
		}
		ensurePrincipals();
		ObjectPolicy op;
		op.path = p;
		op.sddl = defaultObjectSddl(k);
		// Wie im Original: erst die Berechtigungen, dann die Vererbung.
		{
			SecurityDialog sec(this, p.c_str(), k, op.sddl, principals);
			if (!sec.execute(PLACEMENT_OWNER)) return 1;
			op.sddl = sec.getSddl();
		}
		ObjectPolicyDialog dlg(this, k, op, principals);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		op.mode = dlg.getMode();
		op.sddl = dlg.getSddl();
		inf = loadGptTmpl(domain, guid);
		storeObjectPolicy(inf, k, op, false);
		saveTemplate(false);
		showNode(shownItem);
		for (size_t i = 0; i < rowObjects.size(); i++) if (rowObjects[i].path == p) reselect((int)i);
		return 1;
	}

	long onDeleteObject(FXObject*, FXSelector, void*) {
		int row = list->getCurrentItem();
		if (row < 0 || row >= (int)rowObjects.size() || !requireRoot()) return 1;
		if (FXMessageBox::question(this, MBOX_YES_NO, "Gruppenrichtlinie",
		        "Möchten Sie \"%s\" wirklich aus der Richtlinie löschen?", rowObjects[row].path.c_str()) != MBOX_CLICKED_YES) return 1;
		inf = loadGptTmpl(domain, guid);
		storeObjectPolicy(inf, shownObjectKind(), rowObjects[row], true);
		saveTemplate(false);
		reselect(row);
		return 1;
	}

	long onEditObject(FXObject*, FXSelector, void*) {
		editObjectPolicy(list->getCurrentItem());
		return 1;
	}

	void ensurePrincipals() {
		if (principalsLoaded) return;
		getApp()->beginWaitCursor();
		principals = listSecurityPrincipals(false);
		getApp()->endWaitCursor();
		principalsLoaded = true;
	}

	FXString restrictedListText(const std::string& group, const char* suffix) {
		std::string v;
		if (!inf.get("Group Membership", group + suffix, v)) return "Nicht definiert";
		FXString out;
		for (auto& t : splitAccountList(v)) {
			if (!out.empty()) out += ", ";
			out += accountTokenDisplay(t, principals);
		}
		return out;
	}

	bool saveTemplate(bool accountPolicy) {
		FXString errorMsg;
		getApp()->beginWaitCursor();
		bool ok = saveGptTmpl(this, domain, guid, inf, accountPolicy, errorMsg);
		getApp()->endWaitCursor();
		if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		return ok;
	}

	void reselect(int row) {
		showNode(shownItem);
		if (row >= 0 && row < list->getNumItems()) { list->setCurrentItem(row); list->selectItem(row); list->makeItemVisible(row); }
	}

	bool requireRoot() {
		if (g_haveRoot) return true;
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können keine Richtlinien geändert werden.");
		return false;
	}

	void editSecurityPolicy(const Node& node, int row) {
		if (row >= (int)rowDefs.size() || !requireRoot()) return;
		const SecPolicyDef& def = (*node.defs)[rowDefs[row]];
		inf = loadGptTmpl(domain, guid); // frisch lesen -- ein anderes Fenster koennte geschrieben haben
		std::string v;
		bool defined = readSecValue(inf, def, v);

		SecPolicyEditDialog dlg(this, def, defined, v);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		if (dlg.isDefined() == defined && (!defined || dlg.getValue() == v)) return;

		writeSecValue(inf, def, dlg.isDefined(), dlg.getValue());
		bool accountPolicy = std::string(def.section) == "System Access" && node.defs != &SEC_OPTIONS;
		saveTemplate(accountPolicy);
		reselect(row);
	}

	void editUserRight(int row) {
		if (row >= (int)rowDefs.size() || !requireRoot()) return;
		const UserRightDef& def = USER_RIGHTS[rowDefs[row]];
		inf = loadGptTmpl(domain, guid);
		ensurePrincipals();
		std::string v;
		bool defined = inf.get("Privilege Rights", def.key, v);
		std::vector<std::string> tokens = splitAccountList(v);

		UserRightDialog dlg(this, def, defined, tokens, principals);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		if (dlg.isDefined() == defined && (!defined || dlg.getTokens() == tokens)) return;

		if (dlg.isDefined()) inf.set("Privilege Rights", def.key, joinAccountList(dlg.getTokens()));
		else inf.erase("Privilege Rights", def.key);
		saveTemplate(false);
		reselect(row);
	}

	void editRestrictedGroup(int row) {
		if (row < 0 || row >= (int)rowGroups.size() || !requireRoot()) return;
		std::string g = rowGroups[row];
		inf = loadGptTmpl(domain, guid);
		ensurePrincipals();
		std::string members, memberOf;
		inf.get("Group Membership", g + "__Members", members);
		inf.get("Group Membership", g + "__Memberof", memberOf);
		std::vector<GroupEntry> groups;
		for (auto& p : principals) if (p.icon == resico_users && !p.dn.empty()) groups.push_back(p);

		RestrictedGroupDialog dlg(this, accountTokenDisplay(g, principals), splitAccountList(members), splitAccountList(memberOf),
		                          principals, groups);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		inf.set("Group Membership", g + "__Memberof", joinAccountList(dlg.getMemberOf()));
		inf.set("Group Membership", g + "__Members", joinAccountList(dlg.getMembers()));
		saveTemplate(false);
		reselect(row);
	}

	long onAddRestrictedGroup(FXObject*, FXSelector, void*) {
		if (!requireRoot()) return 1;
		getApp()->beginWaitCursor();
		std::vector<GroupEntry> groups = listSecurityPrincipals(true);
		getApp()->endWaitCursor();
		GroupPickerDialog dlg(this, domain.realm, groups, "Gruppen auswählen", resico_users);
		if (!dlg.execute(PLACEMENT_OWNER) || dlg.getResult().empty()) return 1;
		inf = loadGptTmpl(domain, guid);
		std::string added;
		for (int idx : dlg.getResult()) {
			std::string tok = "*" + groups[idx].sid;
			std::string dummy;
			if (inf.get("Group Membership", tok + "__Members", dummy) || inf.get("Group Membership", tok + "__Memberof", dummy)) continue;
			// Wie das Original: beide Listen werden angelegt, zunaechst leer.
			inf.set("Group Membership", tok + "__Memberof", "");
			inf.set("Group Membership", tok + "__Members", "");
			added = tok;
		}
		if (added.empty()) return 1;
		saveTemplate(false);
		showNode(shownItem);
		for (size_t i = 0; i < rowGroups.size(); i++) if (rowGroups[i] == added) { reselect((int)i); editRestrictedGroup((int)i); break; }
		return 1;
	}

	long onDeleteRestrictedGroup(FXObject*, FXSelector, void*) {
		int row = list->getCurrentItem();
		if (row < 0 || row >= (int)rowGroups.size() || !requireRoot()) return 1;
		std::string g = rowGroups[row];
		if (FXMessageBox::question(this, MBOX_YES_NO, "Gruppenrichtlinie",
		        "Möchten Sie die Gruppe \"%s\" wirklich aus den eingeschränkten Gruppen löschen?",
		        accountTokenDisplay(g, principals).text()) != MBOX_CLICKED_YES) return 1;
		inf = loadGptTmpl(domain, guid);
		inf.erase("Group Membership", g + "__Members");
		inf.erase("Group Membership", g + "__Memberof");
		saveTemplate(false);
		reselect(row);
		return 1;
	}

	long onEditRestrictedGroup(FXObject*, FXSelector, void*) {
		editRestrictedGroup(list->getCurrentItem());
		return 1;
	}

	void editFolderRedirection() {
		if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann die Ordnerumleitung nicht geändert werden."); return; }
		std::string userPolPath = gpoBranchDir(domain, guid, false) + "/Registry.pol";
		FolderRedirectionDialog dlg(this, getFolderRedirectionPaths(userPolPath));
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		FXString errorMsg;
		if (!setFolderRedirectionPaths(this, domain, guid.c_str(), dlg.getPaths(), errorMsg))
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}

	// ---- Softwareinstallation: Kontextmenue --------------------------
	long onListRightClick(FXObject*, FXSelector, void* ptr) {
		auto nit = nodes.find(shownItem);
		if (nit == nodes.end()) return 0;
		FXEvent* ev = (FXEvent*)ptr;
		FXint idx = list->getItemAt(ev->win_x, ev->win_y);
		if (idx >= 0) { list->setCurrentItem(idx); list->selectItem(idx); }
		if (nit->second.kind == GN_REGKEYS || nit->second.kind == GN_FILES) {
			bool reg = nit->second.kind == GN_REGKEYS;
			FXMenuPane menu(this);
			new FXMenuCommand(&menu, reg ? "&Schlüssel hinzufügen..." : "&Datei hinzufügen...", NULL, this, ID_ADD_OBJECT);
			if (idx >= 0 && idx < (int)rowObjects.size()) {
				new FXMenuSeparator(&menu);
				new FXMenuCommand(&menu, "&Sicherheit...", NULL, this, ID_EDIT_OBJECT);
				new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_OBJECT);
			}
			menu.create();
			menu.popup(NULL, ev->root_x, ev->root_y);
			getApp()->runModalWhileShown(&menu);
			return 1;
		}
		if (nit->second.kind == GN_RESTRICTED) {
			FXMenuPane menu(this);
			new FXMenuCommand(&menu, "&Gruppe hinzufügen...", NULL, this, ID_ADD_RGROUP);
			if (idx >= 0 && idx < (int)rowGroups.size()) {
				new FXMenuSeparator(&menu);
				new FXMenuCommand(&menu, "&Sicherheit...", NULL, this, ID_EDIT_RGROUP);
				new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_RGROUP);
			}
			menu.create();
			menu.popup(NULL, ev->root_x, ev->root_y);
			getApp()->runModalWhileShown(&menu);
			return 1;
		}
		if (nit->second.kind != GN_SOFTWARE) return 0;

		FXMenuPane menu(this);
		FXMenuPane neu(this);
		new FXMenuCommand(&neu, "&Paket...", NULL, this, ID_NEW_PACKAGE);
		new FXMenuCascade(&menu, "&Neu", NULL, &neu);
		if (idx >= 0 && idx < (int)rowPackages.size()) {
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "&Entfernen...", NULL, this, ID_REMOVE_PACKAGE);
		}
		menu.create();
		menu.popup(NULL, ev->root_x, ev->root_y);
		getApp()->runModalWhileShown(&menu);
		return 1;
	}

	long onNewPackage(FXObject*, FXSelector, void*) {
		auto nit = nodes.find(shownItem);
		if (nit == nodes.end() || nit->second.kind != GN_SOFTWARE) return 1;
		bool machine = nit->second.machine;
		SoftwareInstallDialog dlg(this);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		SoftwarePackageParams params = dlg.getParams();
		if (params.localMsiPath.empty() || params.msiUncPath.empty()) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte sowohl den lokalen Pfad als auch den UNC-Pfad angeben.");
			return 1;
		}
		// Der Knoten bestimmt den Zweig -- in der Computerkonfiguration
		// gibt es nur "Zugewiesen".
		params.assignedPerMachine = machine;
		if (machine) params.published = false;
		std::string log;
		FXString errorMsg;
		getApp()->beginWaitCursor();
		bool ok = addSoftwarePackage(this, domain, guid.c_str(), params, log, errorMsg);
		getApp()->endWaitCursor();
		if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s\n\nProtokoll:\n%s", errorMsg.text(), log.c_str());
		showNode(shownItem);
		return 1;
	}

	long onRemovePackage(FXObject*, FXSelector, void*) {
		auto nit = nodes.find(shownItem);
		if (nit == nodes.end() || nit->second.kind != GN_SOFTWARE) return 1;
		bool machine = nit->second.machine;
		int idx = list->getCurrentItem();
		if (idx < 0 || idx >= (int)rowPackages.size()) return 1;
		SoftwarePackageInfo pkg = rowPackages[idx];

		FXString errorMsg;
		std::string log;
		bool ok;
		if (pkg.pendingRemoval) {
			if (FXMessageBox::question(this, MBOX_YES_NO, "Eintrag löschen",
				"\"%s\" ist bereits zur Deinstallation vorgemerkt.\n\n"
				"Den Auftrag jetzt endgültig aus der Gruppenrichtlinie löschen?\n"
				"Clients, die ihn noch nicht ausgeführt haben, behalten die\n"
				"Anwendung dann.", pkg.displayName.c_str()) != MBOX_CLICKED_YES) return 1;
			ok = deleteSoftwarePackage(this, domain, guid.c_str(), machine, pkg, errorMsg);
		} else {
			RemovePackageDialog dlg(this, pkg.displayName);
			if (!dlg.execute(PLACEMENT_OWNER)) return 1;
			ok = dlg.uninstallFromClients()
			     ? markSoftwarePackageForRemoval(this, domain, guid.c_str(), machine, pkg, log, errorMsg)
			     : deleteSoftwarePackage(this, domain, guid.c_str(), machine, pkg, errorMsg);
		}
		if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		showNode(shownItem);
		return 1;
	}

	virtual ~GpoEditorWindow() {}
};
FXDEFMAP(GpoEditorWindow) GpoEditorWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, GpoEditorWindow::ID_TREE, GpoEditorWindow::onTreeChanged),
	FXMAPFUNC(SEL_DOUBLECLICKED, GpoEditorWindow::ID_LIST, GpoEditorWindow::onListDoubleClick),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, GpoEditorWindow::ID_LIST, GpoEditorWindow::onListRightClick),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_NEW_PACKAGE, GpoEditorWindow::onNewPackage),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_REMOVE_PACKAGE, GpoEditorWindow::onRemovePackage),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_ADD_RGROUP, GpoEditorWindow::onAddRestrictedGroup),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_DELETE_RGROUP, GpoEditorWindow::onDeleteRestrictedGroup),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_EDIT_RGROUP, GpoEditorWindow::onEditRestrictedGroup),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_ADD_OBJECT, GpoEditorWindow::onAddObject),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_DELETE_OBJECT, GpoEditorWindow::onDeleteObject),
	FXMAPFUNC(SEL_COMMAND, GpoEditorWindow::ID_EDIT_OBJECT, GpoEditorWindow::onEditObject),
};
FXIMPLEMENT(GpoEditorWindow, FXDialogBox, GpoEditorWindowMap, ARRAYNUMBER(GpoEditorWindowMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" eines Gruppenrichtlinienobjekts (Knopf
// "Eigenschaften" im Reiter Gruppenrichtlinie) -- Reiter Allgemein mit
// den beiden Schaltern zum Deaktivieren der Konfigurationsteile.
// ---------------------------------------------------------------------
class GpoPropertiesDialog : public FXDialogBox {
	FXDECLARE(GpoPropertiesDialog)
private:
	DomainInfo domain;
	GpoSummary gpo;
	FXCheckButton* disableMachine = nullptr, *disableUser = nullptr;
protected:
	GpoPropertiesDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST, ID_APPLY };

	GpoPropertiesDialog(FXWindow* owner, const DomainInfo& domain_, const GpoSummary& gpo_)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + gpo_.displayName.c_str(), DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0),
		  domain(domain_), gpo(gpo_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,5);

		FXHorizontalFrame* head = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
		new FXLabel(head, "", sharedPngIcon(resico_network), LAYOUT_CENTER_Y);
		new FXLabel(head, gpo.displayName.c_str(), NULL, LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		FXMatrix* m = new FXMatrix(page, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,6);
		auto row = [&](const char* label, const FXString& value) {
			new FXLabel(m, label, NULL, JUSTIFY_LEFT);
			new FXLabel(m, value, NULL, JUSTIFY_LEFT);
		};
		row("Erstellt:", formatGeneralizedTime(gpo.whenCreated));
		row("Geändert:", formatGeneralizedTime(gpo.whenChanged));
		char rev[64];
		snprintf(rev, sizeof(rev), "%u (Computer), %u (Benutzer)", gpo.version & 0xFFFF, (gpo.version >> 16) & 0xFFFF);
		row("Revisionen:", rev);
		FXString realmLower = domain.realm; realmLower.lower();
		row("Domäne:", realmLower);
		row("Eindeutiger Name:", gpo.guid.c_str());
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		FXGroupBox* g = new FXGroupBox(page, "Deaktivieren", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 8,8,6,8);
		disableMachine = new FXCheckButton(g, "Konfigurationseinstellungen des &Computers deaktivieren");
		disableUser = new FXCheckButton(g, "Konfigurationseinstellungen des &Benutzers deaktivieren");
		disableMachine->setCheck((gpo.flags & 2) != 0);
		disableUser->setCheck((gpo.flags & 1) != 0);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		const FXuint bs = BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH;
		new FXButton(btnf, "OK", NULL, this, ID_OK, bs | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, bs, 0,0,88,0, 4,4,3,3);
		(new FXButton(btnf, "Ü&bernehmen", NULL, this, ID_APPLY, bs, 0,0,88,0, 4,4,3,3))->disable(); // bis zur ersten Aenderung grau
	}

	int wantedFlags() const { return (disableUser->getCheck() ? 1 : 0) | (disableMachine->getCheck() ? 2 : 0); }

	bool apply() {
		if (wantedFlags() == gpo.flags) return true;
		std::string ldif = "dn: " + gpo.dn + "\nchangetype: modify\nreplace: flags\nflags: " + std::to_string(wantedFlags()) + "\n-\n";
		std::string log;
		FXString errorMsg;
		if (!runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
			return false;
		}
		gpo.flags = wantedFlags();
		return true;
	}
	long onUpdApply(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, wantedFlags() != gpo.flags ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	long onApply(FXObject*, FXSelector, void*) { apply(); return 1; }
	long onOk(FXObject*, FXSelector, void*) {
		if (!apply()) return 1;
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	virtual ~GpoPropertiesDialog() {}
};
FXDEFMAP(GpoPropertiesDialog) GpoPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, GpoPropertiesDialog::ID_OK, GpoPropertiesDialog::onOk),
	FXMAPFUNC(SEL_COMMAND, GpoPropertiesDialog::ID_APPLY, GpoPropertiesDialog::onApply),
	FXMAPFUNC(SEL_UPDATE, GpoPropertiesDialog::ID_APPLY, GpoPropertiesDialog::onUpdApply),
};
FXIMPLEMENT(GpoPropertiesDialog, FXDialogBox, GpoPropertiesDialogMap, ARRAYNUMBER(GpoPropertiesDialogMap))

// ---------------------------------------------------------------------
// Dialog "Gruppenrichtlinienobjekt-Verknüpfung hinzufügen" (Reiter
// "Alle"): alle GPOs der Domaene, die hier noch nicht verknuepft sind.
// ---------------------------------------------------------------------
class AddGpoLinkDialog : public FXDialogBox {
	FXDECLARE(AddGpoLinkDialog)
private:
	FXIconList* gpoList = nullptr;
	std::vector<GpoSummary> choices;
protected:
	AddGpoLinkDialog() {}
public:
	enum { ID_LIST = FXDialogBox::ID_LAST };
	AddGpoLinkDialog(FXWindow* owner, const DomainInfo& domain, const std::vector<GpoSummary>& all, const std::vector<GpLinkEntry>& linked)
		: FXDialogBox(owner, "Gruppenrichtlinienobjekt-Verknüpfung hinzufügen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,440,380) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "Alle", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 8,8,8,8, 0,4);
		FXString realmLower = domain.realm; realmLower.lower();
		new FXLabel(page, "Alle Gruppenrichtlinienobjekte, die in " + realmLower + " gespeichert sind:");
		FXPacker* lf = new FXPacker(page, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		gpoList = new FXIconList(lf, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		gpoList->appendHeader("Name", NULL, 380);
		FXIcon* ic = sharedPngIcon(resico_network);
		for (auto& g : all) {
			bool isLinked = false;
			for (auto& l : linked) if (lowerCopy(l.guid) == lowerCopy(g.guid)) isLinked = true;
			if (isLinked) continue;
			choices.push_back(g);
			gpoList->appendItem(g.displayName.c_str(), ic, ic);
		}
		if (!choices.empty()) { gpoList->setCurrentItem(0); gpoList->selectItem(0); }
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onDoubleClick(FXObject*, FXSelector, void*) { return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL); }
	const GpoSummary* selected() const {
		int i = gpoList->getCurrentItem();
		return (i >= 0 && i < (int)choices.size()) ? &choices[i] : nullptr;
	}
	virtual ~AddGpoLinkDialog() {}
};
FXDEFMAP(AddGpoLinkDialog) AddGpoLinkDialogMap[] = {
	FXMAPFUNC(SEL_DOUBLECLICKED, AddGpoLinkDialog::ID_LIST, AddGpoLinkDialog::onDoubleClick),
};
FXIMPLEMENT(AddGpoLinkDialog, FXDialogBox, AddGpoLinkDialogMap, ARRAYNUMBER(AddGpoLinkDialogMap))

// ---------------------------------------------------------------------
// Alle Benutzer als Eintraege fuer die Objektauswahl ("Verwaltet von").
// ---------------------------------------------------------------------
static std::vector<GroupEntry> listAllUsersAsEntries() {
	std::vector<FXString> plain = listNames({ FXString("samba-tool"), FXString("user"), FXString("list") });
	std::vector<FXString> dns = listNames({ FXString("samba-tool"), FXString("user"), FXString("list"), FXString("--full-dn") });
	std::vector<GroupEntry> out;
	size_t n = std::min(plain.size(), dns.size());
	for (size_t i = 0; i < n; i++) {
		GroupEntry e;
		e.sam = plain[i];
		e.dn = dns[i].text();
		e.cn = dnLeafName(e.dn);
		e.folder = dnToFolder(e.dn);
		out.push_back(e);
	}
	std::sort(out.begin(), out.end(), [](const GroupEntry& a, const GroupEntry& b) {
		return strcasecmp(a.cn.text(), b.cn.text()) < 0;
	});
	return out;
}

// ---------------------------------------------------------------------
// Beschriftete Eingabezeilen fuer Eigenschaftenseiten.
// ---------------------------------------------------------------------
static FXTextField* propLabeledField(FXComposite* p, const char* label, FXint labelWidth = 140) {
	FXHorizontalFrame* row = new FXHorizontalFrame(p, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	new FXLabel(row, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,labelWidth,0);
	return new FXTextField(row, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
}

static FXText* propLabeledText(FXComposite* p, const char* label, FXint height = 74, FXint labelWidth = 140) {
	FXHorizontalFrame* row = new FXHorizontalFrame(p, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	new FXLabel(row, label, NULL, LAYOUT_TOP | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,labelWidth,0);
	FXPacker* f = new FXPacker(row, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FIX_HEIGHT, 0,0,0,height, 0,0,0,0);
	return new FXText(f, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);
}

static std::string crlfToLf(const std::string& s) {
	std::string o;
	for (char c : s) if (c != '\r') o += c;
	return o;
}

// ---------------------------------------------------------------------
// Reiter "Verwaltet von" -- gemeinsam fuer Organisationseinheiten,
// Domaene und Gruppen. Haelt nur die Auswahl; geschrieben wird von der
// jeweiligen Eigenschaftenseite (managedBy).
// ---------------------------------------------------------------------
class ManagedByPanel : public FXVerticalFrame {
	FXDECLARE(ManagedByPanel)
private:
	DomainInfo domain;
	std::string managerDn;
	FXTextField* mgrName = nullptr, *mgrOffice = nullptr, *mgrCity = nullptr, *mgrState = nullptr,
	           *mgrCountry = nullptr, *mgrPhone = nullptr, *mgrFax = nullptr;
	FXText* mgrStreet = nullptr;
protected:
	ManagedByPanel() {}
public:
	enum { ID_MGR_CHANGE = FXVerticalFrame::ID_LAST, ID_MGR_PROPS, ID_MGR_CLEAR };

	ManagedByPanel(FXComposite* parent, const DomainInfo& domain_, const std::string& initialDn)
		: FXVerticalFrame(parent, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6),
		  domain(domain_), managerDn(initialDn) {
		mgrName = propLabeledField(this, "&Name:");
		mgrName->setEditable(FALSE);
		FXHorizontalFrame* btns = new FXHorizontalFrame(this, LAYOUT_FILL_X, 0,0,0,0, 140,0,0,4);
		new FXButton(btns, "Ä&ndern...", NULL, this, ID_MGR_CHANGE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "&Eigenschaften", NULL, this, ID_MGR_PROPS, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "&Löschen", NULL, this, ID_MGR_CLEAR, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		mgrOffice = propLabeledField(this, "Büro:");
		mgrStreet = propLabeledText(this, "Straße:");
		mgrCity = propLabeledField(this, "Stadt:");
		mgrState = propLabeledField(this, "Bundesland/Kanton:");
		mgrCountry = propLabeledField(this, "Land/Region:");
		mgrPhone = propLabeledField(this, "Rufnummer:");
		mgrFax = propLabeledField(this, "Faxnummer:");
		for (FXTextField* f : { mgrOffice, mgrCity, mgrState, mgrCountry, mgrPhone, mgrFax }) f->setEditable(FALSE);
		mgrStreet->setEditable(FALSE);
		showManager();
	}

	const std::string& getManagerDn() const { return managerDn; }

	void showManager() {
		std::multimap<std::string, std::string> rec;
		if (!managerDn.empty()) {
			auto recs = ldapiSearch(managerDn, "base", "(objectClass=*)",
			                        { "physicalDeliveryOfficeName", "streetAddress", "l", "st", "co", "telephoneNumber", "facsimileTelephoneNumber" });
			if (!recs.empty()) rec = recs[0];
		}
		mgrName->setText(managerDn.empty() ? FXString() : dnLeafName(managerDn) + " (" + dnToFolder(managerDn) + ")");
		mgrOffice->setText(ldifFirst(rec, "physicalDeliveryOfficeName").c_str());
		mgrStreet->setText(crlfToLf(ldifFirst(rec, "streetAddress")).c_str());
		mgrCity->setText(ldifFirst(rec, "l").c_str());
		mgrState->setText(ldifFirst(rec, "st").c_str());
		mgrCountry->setText(ldifFirst(rec, "co").c_str());
		mgrPhone->setText(ldifFirst(rec, "telephoneNumber").c_str());
		mgrFax->setText(ldifFirst(rec, "facsimileTelephoneNumber").c_str());
	}

	long onManagerChange(FXObject*, FXSelector, void*) {
		getApp()->beginWaitCursor();
		std::vector<GroupEntry> users = listAllUsersAsEntries();
		getApp()->endWaitCursor();
		GroupPickerDialog dlg(this, domain.realm, users, "Benutzer auswählen", resico_user);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		if (dlg.getResult().empty()) return 1;
		if (dlg.getResult().size() > 1) {
			FXMessageBox::error(this, MBOX_OK, "Active Directory", "Es kann nur ein Objekt ausgewählt werden.");
			return 1;
		}
		managerDn = users[dlg.getResult()[0]].dn;
		showManager();
		return 1;
	}

	long onManagerClear(FXObject*, FXSelector, void*) {
		managerDn.clear();
		showManager();
		return 1;
	}

	long onManagerProps(FXObject*, FXSelector, void*) {
		if (managerDn.empty()) return 1;
		std::string sam = ldapiReadAttr(managerDn, "sAMAccountName");
		if (sam.empty()) return 1;
		DirObject obj;
		obj.name = dnLeafName(managerDn);
		obj.accountName = sam.c_str();
		std::string suffix = "," + std::string(domain.baseDN.text());
		std::string rel = managerDn;
		if (rel.size() > suffix.size() && lowerCopy(rel).compare(rel.size() - suffix.size(), suffix.size(), lowerCopy(suffix)) == 0)
			rel = rel.substr(0, rel.size() - suffix.size());
		obj.dn = rel.c_str();
		obj.type = OBJ_USER;
		UserPropertiesDialog dlg(this, domain, obj);
		dlg.execute(PLACEMENT_OWNER);
		showManager();
		return 1;
	}

	long onUpdManagerButtons(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, managerDn.empty() ? ID_DISABLE : ID_ENABLE), NULL);
		return 1;
	}
	virtual ~ManagedByPanel() {}
};
FXDEFMAP(ManagedByPanel) ManagedByPanelMap[] = {
	FXMAPFUNC(SEL_COMMAND, ManagedByPanel::ID_MGR_CHANGE, ManagedByPanel::onManagerChange),
	FXMAPFUNC(SEL_COMMAND, ManagedByPanel::ID_MGR_CLEAR, ManagedByPanel::onManagerClear),
	FXMAPFUNC(SEL_UPDATE, ManagedByPanel::ID_MGR_CLEAR, ManagedByPanel::onUpdManagerButtons),
	FXMAPFUNC(SEL_COMMAND, ManagedByPanel::ID_MGR_PROPS, ManagedByPanel::onManagerProps),
	FXMAPFUNC(SEL_UPDATE, ManagedByPanel::ID_MGR_PROPS, ManagedByPanel::onUpdManagerButtons),
};
FXIMPLEMENT(ManagedByPanel, FXVerticalFrame, ManagedByPanelMap, ARRAYNUMBER(ManagedByPanelMap))

// ---------------------------------------------------------------------
// Verzeichnisobjekte, die Mitglied einer Gruppe sein koennen (Benutzer,
// Computer, Gruppen), mit passendem Symbol -- eine ldapi-Abfrage.
// ---------------------------------------------------------------------
static std::vector<GroupEntry> listMemberCandidates(const DomainInfo& domain) {
	std::vector<GroupEntry> out;
	for (auto& rec : ldapiSearch(domain.baseDN.text(), "sub", "(|(objectClass=user)(objectClass=group))",
	                             { "cn", "sAMAccountName", "objectClass", "groupType" })) {
		GroupEntry e;
		e.dn = ldifFirst(rec, "dn");
		e.cn = ldifFirst(rec, "cn").c_str();
		e.sam = ldifFirst(rec, "sAMAccountName").c_str();
		e.folder = dnToFolder(e.dn);
		std::string cls;
		auto range = rec.equal_range("objectclass");
		for (auto it = range.first; it != range.second; ++it) cls = lowerCopy(it->second);
		e.icon = cls == "group" ? resico_users : cls == "computer" ? resico_server : resico_user;
		if (e.cn.empty() || e.sam.empty()) continue;
		out.push_back(e);
	}
	std::sort(out.begin(), out.end(), [](const GroupEntry& a, const GroupEntry& b) {
		return germanLess(a.cn.text(), b.cn.text());
	});
	return out;
}

// Liste "Name | Active Directory-Ordner" mit Hinzufuegen/Entfernen -- fuer
// die Reiter Mitglieder und Mitglied von. Haelt nur DNs; geschrieben wird
// vom Dialog.
class DnListPanel : public FXVerticalFrame {
	FXDECLARE(DnListPanel)
private:
	FXIconList* list = nullptr;
	std::vector<std::string> dns;
	const std::vector<GroupEntry>* candidates = nullptr;
	FXString pickerTitle;
	bool groupsOnly = false;
	std::string excludeDn;
	FXString realm;
protected:
	DnListPanel() {}
public:
	enum { ID_ADD = FXVerticalFrame::ID_LAST, ID_REMOVE };
	DnListPanel(FXComposite* parent, const char* heading, const std::vector<std::string>& initial,
	            const std::vector<GroupEntry>& candidates_, const FXString& pickerTitle_, bool groupsOnly_,
	            const std::string& excludeDn_, const FXString& realm_)
		: FXVerticalFrame(parent, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6),
		  dns(initial), candidates(&candidates_), pickerTitle(pickerTitle_), groupsOnly(groupsOnly_), excludeDn(excludeDn_), realm(realm_) {
		new FXLabel(this, heading);
		FXPacker* lf = new FXPacker(this, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		list = new FXIconList(lf, NULL, 0, ICONLIST_DETAILED | ICONLIST_EXTENDEDSELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		list->appendHeader("Name", NULL, 160);
		list->appendHeader("Active Directory-Ordner", NULL, 220);
		FXHorizontalFrame* btns = new FXHorizontalFrame(this, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,0);
		new FXButton(btns, "Hin&zufügen...", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "En&tfernen", NULL, this, ID_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		reload();
	}
	const unsigned char* iconFor(const std::string& dn) const {
		for (auto& c : *candidates) if (lowerCopy(c.dn) == lowerCopy(dn)) return c.icon;
		return resico_folder;
	}
	void reload() {
		std::sort(dns.begin(), dns.end(), [](const std::string& a, const std::string& b) {
			return germanLess(dnLeafName(a).text(), dnLeafName(b).text());
		});
		list->clearItems();
		for (auto& dn : dns) {
			FXIcon* ic = sharedPngIcon(iconFor(dn));
			list->appendItem(dnLeafName(dn) + "\t" + dnToFolder(dn), ic, ic);
		}
	}
	long onAdd(FXObject*, FXSelector, void*) {
		std::vector<GroupEntry> choices;
		for (auto& c : *candidates) {
			if (groupsOnly && c.icon != resico_users) continue;
			if (lowerCopy(c.dn) == lowerCopy(excludeDn)) continue;
			choices.push_back(c);
		}
		GroupPickerDialog dlg(this, realm, choices, pickerTitle.text(), resico_users);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		for (int idx : dlg.getResult()) {
			bool present = false;
			for (auto& d : dns) if (lowerCopy(d) == lowerCopy(choices[idx].dn)) present = true;
			if (!present) dns.push_back(choices[idx].dn);
		}
		reload();
		return 1;
	}
	long onRemove(FXObject*, FXSelector, void*) {
		std::vector<std::string> keep;
		for (FXint i = 0; i < list->getNumItems(); i++) if (!list->isItemSelected(i)) keep.push_back(dns[i]);
		if (keep.size() == dns.size()) return 1;
		if (FXMessageBox::question(this, MBOX_YES_NO, "Active Directory",
		        "Möchten Sie die ausgewählten Objekte wirklich entfernen?") != MBOX_CLICKED_YES) return 1;
		dns = keep;
		reload();
		return 1;
	}
	long onUpdRemove(FXObject* sender, FXSelector, void*) {
		bool any = false;
		for (FXint i = 0; i < list->getNumItems() && !any; i++) any = list->isItemSelected(i);
		sender->handle(this, FXSEL(SEL_COMMAND, any ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	const std::vector<std::string>& getDns() const { return dns; }
	void setDns(const std::vector<std::string>& d) { dns = d; reload(); }
	virtual ~DnListPanel() {}
};
FXDEFMAP(DnListPanel) DnListPanelMap[] = {
	FXMAPFUNC(SEL_COMMAND, DnListPanel::ID_ADD, DnListPanel::onAdd),
	FXMAPFUNC(SEL_COMMAND, DnListPanel::ID_REMOVE, DnListPanel::onRemove),
	FXMAPFUNC(SEL_UPDATE, DnListPanel::ID_REMOVE, DnListPanel::onUpdRemove),
};
FXIMPLEMENT(DnListPanel, FXVerticalFrame, DnListPanelMap, ARRAYNUMBER(DnListPanelMap))

// Unterschiede zweier DN-Listen (ohne Gross-/Kleinschreibung).
static std::vector<std::string> dnsMissingIn(const std::vector<std::string>& from, const std::vector<std::string>& in) {
	std::vector<std::string> out;
	for (auto& a : from) {
		bool found = false;
		for (auto& b : in) if (lowerCopy(a) == lowerCopy(b)) { found = true; break; }
		if (!found) out.push_back(a);
	}
	return out;
}

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer Gruppe: Allgemein, Mitglieder, Mitglied
// von, Verwaltet von. Alles wird erst mit OK/Übernehmen geschrieben.
// ---------------------------------------------------------------------
class GroupPropertiesDialog : public FXDialogBox {
	FXDECLARE(GroupPropertiesDialog)
private:
	DomainInfo domain;
	std::string groupDn;
	FXString cn;
	std::vector<GroupEntry> candidates;

	FXTextField* samField = nullptr, *descField = nullptr, *mailField = nullptr;
	FXText* infoText = nullptr;
	std::string origSam, origDesc, origMail, origInfo;
	FXint scope = 2, secType = 1;          // 2/4/8, 1 = Sicherheit
	FXint origScope = 2, origSecType = 1;
	bool builtin = false;
	FXDataTarget scopeTarget, typeTarget;

	DnListPanel* members = nullptr, *memberOf = nullptr;
	std::vector<std::string> origMembers, origMemberOf;
	ManagedByPanel* managedBy = nullptr;
	std::string origManager;

protected:
	GroupPropertiesDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST, ID_APPLY };

	GroupPropertiesDialog(FXWindow* owner, const DomainInfo& domain_, const DirObject& obj)
		: FXDialogBox(owner, "Eigenschaften von " + obj.name, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,480,520),
		  domain(domain_), cn(obj.name), scopeTarget(scope), typeTarget(secType) {
		groupDn = std::string((obj.dn + "," + domain.baseDN).text());
		candidates = listMemberCandidates(domain);

		auto recs = ldapiSearch(groupDn, "base", "(objectClass=*)",
		                        { "sAMAccountName", "description", "mail", "info", "groupType", "member", "memberOf", "managedBy" });
		std::multimap<std::string, std::string> rec;
		if (!recs.empty()) rec = recs[0];
		origSam = ldifFirst(rec, "sAMAccountName");
		origDesc = ldifFirst(rec, "description");
		origMail = ldifFirst(rec, "mail");
		origInfo = crlfToLf(ldifFirst(rec, "info"));
		origManager = ldifFirst(rec, "managedBy");
		long gt = 0;
		try { gt = std::stol(ldifFirst(rec, "groupType")); } catch (...) {}
		uint32_t g = (uint32_t)gt;
		builtin = (g & 0x1) != 0;
		origScope = scope = (g & 0x8) ? 8 : (g & 0x4) ? 4 : 2;
		origSecType = secType = (g & 0x80000000u) ? 1 : 0;
		auto collect = [&](const char* attr, std::vector<std::string>& into) {
			auto range = rec.equal_range(attr);
			for (auto it = range.first; it != range.second; ++it) into.push_back(it->second);
		};
		collect("member", origMembers);
		collect("memberof", origMemberOf);

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		buildGeneralTab(tabs);
		new FXTabItem(tabs, "Mitglieder", NULL);
		members = new DnListPanel(tabs, "&Mitglieder:", origMembers, candidates,
		                          "Benutzer, Kontakte, Computer oder Gruppen auswählen", false, groupDn, domain.realm);
		new FXTabItem(tabs, "Mitglied von", NULL);
		memberOf = new DnListPanel(tabs, "&Mitglied von:", origMemberOf, candidates, "Gruppen auswählen", true, groupDn, domain.realm);
		new FXTabItem(tabs, "Verwaltet von", NULL);
		managedBy = new ManagedByPanel(tabs, domain, origManager);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		const FXuint bs = BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH;
		new FXButton(btnf, "OK", NULL, this, ID_OK, bs | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, bs, 0,0,88,0, 4,4,3,3);
		(new FXButton(btnf, "Ü&bernehmen", NULL, this, ID_APPLY, bs, 0,0,88,0, 4,4,3,3))->disable();
	}

	void buildGeneralTab(FXTabBook* tabs) {
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		FXHorizontalFrame* head = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
		new FXLabel(head, "", sharedPngIcon(resico_users), LAYOUT_CENTER_Y);
		new FXLabel(head, cn, NULL, LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		// Wie im Original steht der Prä-Windows-2000-Name ueber seinem Feld.
		new FXLabel(page, "Gruppenname (&Prä-Windows 2000):", NULL, JUSTIFY_LEFT);
		samField = new FXTextField(page, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		samField->setText(origSam.c_str());
		descField = propLabeledField(page, "&Beschreibung:", 110);
		descField->setText(origDesc.c_str());
		mailField = propLabeledField(page, "&E-Mail:", 110);
		mailField->setText(origMail.c_str());

		FXHorizontalFrame* boxes = new FXHorizontalFrame(page, LAYOUT_FILL_X | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,4,4, 10,0);
		FXGroupBox* scopeBox = new FXGroupBox(boxes, "Gruppenbereich", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 8,8,6,8);
		FXRadioButton* r1 = new FXRadioButton(scopeBox, "Lokal (in &Domäne)", &scopeTarget, FXDataTarget::ID_OPTION + 4);
		FXRadioButton* r2 = new FXRadioButton(scopeBox, "&Global", &scopeTarget, FXDataTarget::ID_OPTION + 2);
		FXRadioButton* r3 = new FXRadioButton(scopeBox, "&Universal", &scopeTarget, FXDataTarget::ID_OPTION + 8);
		FXGroupBox* typeBox = new FXGroupBox(boxes, "Gruppentyp", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 8,8,6,8);
		FXRadioButton* t1 = new FXRadioButton(typeBox, "&Sicherheit", &typeTarget, FXDataTarget::ID_OPTION + 1);
		FXRadioButton* t2 = new FXRadioButton(typeBox, "&Verteilung", &typeTarget, FXDataTarget::ID_OPTION + 0);
		// Vordefinierte Gruppen (Builtin) haben einen festen Bereich und Typ.
		if (builtin) for (FXWindow* w : { (FXWindow*)r1, (FXWindow*)r2, (FXWindow*)r3, (FXWindow*)t1, (FXWindow*)t2 }) w->disable();

		infoText = propLabeledText(page, "&Anmerkungen:", 90, 110);
		infoText->setText(origInfo.c_str());
	}

	std::string generalLdif() {
		std::string ldif;
		auto attr = [&](const char* name, const std::string& orig, std::string now) {
			now = trimStr(now);
			if (now == trimStr(orig)) return;
			ldif += std::string("replace: ") + name + "\n";
			if (!now.empty()) ldif += ldifAttrLine(name, now);
			ldif += "-\n";
		};
		attr("sAMAccountName", origSam, samField->getText().text());
		attr("description", origDesc, descField->getText().text());
		attr("mail", origMail, mailField->getText().text());
		std::string info = trimStr(infoText->getText().text());
		if (info != trimStr(origInfo)) {
			std::string crlf;
			for (char c : info) { if (c == '\n') crlf += '\r'; crlf += c; }
			ldif += "replace: info\n";
			if (!info.empty()) ldif += ldifAttrLine("info", crlf);
			ldif += "-\n";
		}
		if (!builtin && (scope != origScope || secType != origSecType)) {
			int32_t gt = (int32_t)((secType ? 0x80000000u : 0u) | (uint32_t)scope);
			ldif += "replace: groupType\ngroupType: " + std::to_string(gt) + "\n-\n";
		}
		if (lowerCopy(managedBy->getManagerDn()) != lowerCopy(origManager)) {
			ldif += "replace: managedBy\n";
			if (!managedBy->getManagerDn().empty()) ldif += ldifAttrLine("managedBy", managedBy->getManagerDn());
			ldif += "-\n";
		}
		return ldif;
	}

	bool isDirty() {
		return !generalLdif().empty() ||
		       !dnsMissingIn(members->getDns(), origMembers).empty() || !dnsMissingIn(origMembers, members->getDns()).empty() ||
		       !dnsMissingIn(memberOf->getDns(), origMemberOf).empty() || !dnsMissingIn(origMemberOf, memberOf->getDns()).empty();
	}

	bool runChange(const std::string& ldif) {
		std::string log;
		FXString errorMsg;
		if (runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) return true;
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		return false;
	}

	bool apply() {
		// Bereich/Typ zuerst: AD erlaubt manche Umwandlungen nur bei passenden
		// Mitgliedern -- ein Fehler soll erscheinen, bevor Mitglieder
		// geaendert werden.
		std::string ldif = generalLdif();
		if (!ldif.empty() && !runChange("dn: " + groupDn + "\nchangetype: modify\n" + ldif)) return false;
		origSam = trimStr(samField->getText().text());
		origDesc = trimStr(descField->getText().text());
		origMail = trimStr(mailField->getText().text());
		origInfo = trimStr(infoText->getText().text());
		origScope = scope;
		origSecType = secType;
		origManager = managedBy->getManagerDn();

		std::vector<std::string> addM = dnsMissingIn(members->getDns(), origMembers);
		std::vector<std::string> delM = dnsMissingIn(origMembers, members->getDns());
		if (!addM.empty() || !delM.empty()) {
			std::string m = "dn: " + groupDn + "\nchangetype: modify\n";
			if (!addM.empty()) { m += "add: member\n"; for (auto& d : addM) m += ldifAttrLine("member", d); m += "-\n"; }
			if (!delM.empty()) { m += "delete: member\n"; for (auto& d : delM) m += ldifAttrLine("member", d); m += "-\n"; }
			if (!runChange(m)) { resync(); return false; }
			origMembers = members->getDns();
		}

		// "Mitglied von" aendert das member-Attribut der jeweils anderen Gruppe.
		std::vector<std::string> addO = dnsMissingIn(memberOf->getDns(), origMemberOf);
		std::vector<std::string> delO = dnsMissingIn(origMemberOf, memberOf->getDns());
		std::string o;
		for (auto& g : addO) o += "dn: " + g + "\nchangetype: modify\nadd: member\n" + ldifAttrLine("member", groupDn) + "-\n\n";
		for (auto& g : delO) o += "dn: " + g + "\nchangetype: modify\ndelete: member\n" + ldifAttrLine("member", groupDn) + "-\n\n";
		if (!o.empty()) {
			if (!runChange(o)) { resync(); return false; }
			origMemberOf = memberOf->getDns();
		}
		return true;
	}

	// Nach einem Teilfehler den echten Stand aus AD holen.
	void resync() {
		auto recs = ldapiSearch(groupDn, "base", "(objectClass=*)", { "member", "memberOf" });
		std::vector<std::string> m, o;
		if (!recs.empty()) {
			auto r1 = recs[0].equal_range("member");
			for (auto it = r1.first; it != r1.second; ++it) m.push_back(it->second);
			auto r2 = recs[0].equal_range("memberof");
			for (auto it = r2.first; it != r2.second; ++it) o.push_back(it->second);
		}
		origMembers = m;
		origMemberOf = o;
		members->setDns(m);
		memberOf->setDns(o);
	}

	long onUpdApply(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, isDirty() ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	long onApply(FXObject*, FXSelector, void*) { apply(); return 1; }
	long onOk(FXObject*, FXSelector, void*) {
		if (isDirty() && !apply()) return 1;
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	virtual ~GroupPropertiesDialog() {}
};
FXDEFMAP(GroupPropertiesDialog) GroupPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, GroupPropertiesDialog::ID_OK, GroupPropertiesDialog::onOk),
	FXMAPFUNC(SEL_COMMAND, GroupPropertiesDialog::ID_APPLY, GroupPropertiesDialog::onApply),
	FXMAPFUNC(SEL_UPDATE, GroupPropertiesDialog::ID_APPLY, GroupPropertiesDialog::onUpdApply),
};
FXIMPLEMENT(GroupPropertiesDialog, FXDialogBox, GroupPropertiesDialogMap, ARRAYNUMBER(GroupPropertiesDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer Organisationseinheit (bzw. der Domaene
// selbst): Allgemein, Verwaltet von, Gruppenrichtlinie.
// ---------------------------------------------------------------------
class OUPropertiesDialog : public FXDialogBox {
	FXDECLARE(OUPropertiesDialog)
private:
	DomainInfo domain;
	std::string fullDN;
	FXString displayName;
	bool isDomainRoot = false;

	// Allgemein
	FXTextField* descField = nullptr, *cityField = nullptr, *stateField = nullptr, *zipField = nullptr;
	FXText* streetText = nullptr;
	FXListBox* countryBox = nullptr;
	std::string origDesc, origStreet, origCity, origState, origZip, origCountry;

	// Verwaltet von
	ManagedByPanel* managedBy = nullptr;
	std::string origManagerDn;

	// Gruppenrichtlinie
	FXIconList* linkList = nullptr;
	FXCheckButton* blockInheritance = nullptr;
	bool origBlock = false;
	std::vector<GpLinkEntry> links;      // Reihenfolge wie im Attribut
	std::vector<GpoSummary> allGpos;

protected:
	OUPropertiesDialog() {}
public:
	enum {
		ID_OK = FXDialogBox::ID_LAST, ID_APPLY,
		ID_MGR_CHANGE, ID_MGR_PROPS, ID_MGR_CLEAR,
		ID_LINKLIST, ID_GPO_NEW, ID_GPO_ADD, ID_GPO_EDIT, ID_GPO_UP, ID_GPO_OPTIONS, ID_GPO_DELETE, ID_GPO_PROPS, ID_GPO_DOWN
	};

	OUPropertiesDialog(FXWindow* owner, const DomainInfo& domain_, const FXString& relDN, const FXString& name)
		: FXDialogBox(owner, "Eigenschaften von " + name, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,520,540),
		  domain(domain_), displayName(name) {
		isDomainRoot = relDN.empty();
		fullDN = isDomainRoot ? std::string(domain.baseDN.text()) : std::string((relDN + "," + domain.baseDN).text());

		auto recs = ldapiSearch(fullDN, "base", "(objectClass=*)",
		                        { "description", "street", "l", "st", "postalCode", "c", "managedBy", "gPLink", "gPOptions", "nTMixedDomain" });
		std::multimap<std::string, std::string> rec;
		if (!recs.empty()) rec = recs[0];
		origDesc = ldifFirst(rec, "description");
		origStreet = ldifFirst(rec, "street");
		origCity = ldifFirst(rec, "l");
		origState = ldifFirst(rec, "st");
		origZip = ldifFirst(rec, "postalCode");
		origCountry = ldifFirst(rec, "c");
		origManagerDn = ldifFirst(rec, "managedBy");
		origBlock = ldifFirst(rec, "gPOptions") == "1";
		links = parseGpLink(ldifFirst(rec, "gPLink"));
		allGpos = listGposLdapi(domain.baseDN);

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		buildGeneralTab(tabs, rec);
		buildManagedByTab(tabs);
		buildGroupPolicyTab(tabs);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		const FXuint bs = BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH;
		new FXButton(btnf, "OK", NULL, this, ID_OK, bs | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, bs, 0,0,88,0, 4,4,3,3);
		(new FXButton(btnf, "Ü&bernehmen", NULL, this, ID_APPLY, bs, 0,0,88,0, 4,4,3,3))->disable(); // bis zur ersten Aenderung grau

		reloadLinks();
	}

	// ---- Allgemein ---------------------------------------------------
	FXTextField* labeledField(FXComposite* p, const char* label) { return propLabeledField(p, label); }
	FXText* labeledText(FXComposite* p, const char* label) { return propLabeledText(p, label); }

	static std::string lfToCrlf(const std::string& s) {
		std::string o;
		for (char c : s) { if (c == '\n') o += '\r'; o += c; }
		return o;
	}

	void buildGeneralTab(FXTabBook* tabs, const std::multimap<std::string, std::string>& rec) {
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		FXHorizontalFrame* head = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
		new FXLabel(head, "", sharedPngIcon(isDomainRoot ? resico_server : resico_folder), LAYOUT_CENTER_Y);
		new FXLabel(head, displayName, NULL, LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		descField = labeledField(page, "&Beschreibung:");
		descField->setText(origDesc.c_str());

		if (isDomainRoot) {
			std::string conf = readFileUnprivileged("/etc/samba/smb.conf");
			FXString nb = smbConfValue(conf, "workgroup"); nb.upper();
			new FXLabel(page, "Domänenname (Prä-Windows 2000):", NULL, JUSTIFY_LEFT);
			FXTextField* nbf = new FXTextField(page, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			nbf->setText(nb);
			nbf->setEditable(FALSE);
			new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
			FXString mode = ldifFirst(rec, "nTMixedDomain") == "0" ? "Einheitlicher Modus" : "Gemischter Modus";
			FXHorizontalFrame* row = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(row, "Domänenmodus:", NULL, LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,140,0);
			new FXLabel(row, mode, NULL, JUSTIFY_LEFT);
			return;
		}

		streetText = labeledText(page, "&Straße:");
		streetText->setText(crlfToLf(origStreet).c_str());
		cityField = labeledField(page, "S&tadt:");
		cityField->setText(origCity.c_str());
		stateField = labeledField(page, "B&undesland/Kanton:");
		stateField->setText(origState.c_str());
		zipField = labeledField(page, "&PLZ:");
		zipField->setText(origZip.c_str());

		FXHorizontalFrame* row = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(row, "&Land/Region:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,140,0);
		countryBox = new FXListBox(row, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		countryBox->appendItem("");
		int sel = 0;
		const auto& countries = countryList();
		for (size_t i = 0; i < countries.size(); i++) {
			countryBox->appendItem(countries[i].name.c_str());
			if (!origCountry.empty() && lowerCopy(countries[i].alpha2) == lowerCopy(origCountry)) sel = (int)i + 1;
		}
		// Unbekannter Code (oder iso-codes fehlt): Wert trotzdem anzeigen,
		// damit er beim Speichern nicht verlorengeht.
		if (sel == 0 && !origCountry.empty()) sel = countryBox->appendItem(origCountry.c_str());
		countryBox->setNumVisible(12);
		countryBox->setCurrentItem(sel);
	}

	std::string selectedCountryCode(std::string& name, int& numeric) const {
		int i = countryBox->getCurrentItem();
		const auto& countries = countryList();
		name.clear(); numeric = 0;
		if (i <= 0) return "";
		if (i - 1 < (int)countries.size()) {
			name = countries[i - 1].name;
			numeric = countries[i - 1].numeric;
			return countries[i - 1].alpha2;
		}
		return origCountry; // unveraenderter unbekannter Code
	}

	// ---- Verwaltet von -----------------------------------------------
	void buildManagedByTab(FXTabBook* tabs) {
		new FXTabItem(tabs, "Verwaltet von", NULL);
		managedBy = new ManagedByPanel(tabs, domain, origManagerDn);
	}

	// ---- Gruppenrichtlinie -------------------------------------------
	void buildGroupPolicyTab(FXTabBook* tabs) {
		new FXTabItem(tabs, "Gruppenrichtlinie", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		FXHorizontalFrame* head = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
		new FXLabel(head, "", sharedPngIcon(resico_network), LAYOUT_CENTER_Y);
		new FXLabel(head, "Aktuelle Gruppenrichtlinienobjekt-Verknüpfungen für " + displayName, NULL, LAYOUT_CENTER_Y | JUSTIFY_LEFT);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);

		FXPacker* lf = new FXPacker(page, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		linkList = new FXIconList(lf, this, ID_LINKLIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		linkList->appendHeader("Gruppenrichtlinienobjekt-Verknüpfungen", NULL, 260);
		linkList->appendHeader("Kein Vorrang", NULL, 95);
		linkList->appendHeader("Deaktiviert", NULL, 85);

		new FXLabel(page, "Das Gruppenrichtlinienobjekt mit der höchsten Priorität steht an erster Stelle.\n"
		                  "Die Liste wurde von " + serverFqdn(domain) + " erhalten.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

		FXMatrix* m = new FXMatrix(page, 4, MATRIX_BY_COLUMNS | LAYOUT_FILL_X | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,4,0, 6,6);
		const FXuint bs = BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X;
		new FXButton(m, "&Neu", NULL, this, ID_GPO_NEW, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "&Hinzufügen...", NULL, this, ID_GPO_ADD, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "B&earbeiten", NULL, this, ID_GPO_EDIT, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "Nach &oben", NULL, this, ID_GPO_UP, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "O&ptionen...", NULL, this, ID_GPO_OPTIONS, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "&Löschen...", NULL, this, ID_GPO_DELETE, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "E&igenschaften", NULL, this, ID_GPO_PROPS, bs, 0,0,0,0, 4,4,3,3);
		new FXButton(m, "Nach &unten", NULL, this, ID_GPO_DOWN, bs, 0,0,0,0, 4,4,3,3);

		blockInheritance = new FXCheckButton(page, "&Richtlinienvererbung deaktivieren");
		blockInheritance->setCheck(origBlock);
	}

	const GpoSummary* gpoByGuid(const std::string& g) const {
		for (auto& x : allGpos) if (lowerCopy(x.guid) == lowerCopy(g)) return &x;
		return nullptr;
	}

	// Anzeigeindex -> Index in "links" (Anzeige ist umgekehrt: hoechste
	// Prioritaet = letzter Block = erste Zeile).
	int linkIndexForRow(int row) const { return (int)links.size() - 1 - row; }

	void reloadLinks(int selectRow = 0) {
		linkList->clearItems();
		FXIcon* ic = sharedPngIcon(resico_network);
		for (int row = 0; row < (int)links.size(); row++) {
			const GpLinkEntry& l = links[linkIndexForRow(row)];
			const GpoSummary* g = gpoByGuid(l.guid);
			FXString name = g ? FXString(g->displayName.c_str()) : FXString(l.guid.c_str());
			linkList->appendItem(name + "\t" + ((l.options & GPLINK_OPT_ENFORCE) ? "\u2713" : "") +
			                     "\t" + ((l.options & GPLINK_OPT_DISABLE) ? "\u2713" : ""), ic, ic);
		}
		if (!links.empty()) {
			selectRow = std::max(0, std::min(selectRow, (int)links.size() - 1));
			linkList->setCurrentItem(selectRow);
			linkList->selectItem(selectRow);
		}
	}

	void refreshLinksFromDirectory(int selectRow = 0) {
		links = parseGpLink(ldapiReadAttr(fullDN, "gPLink"));
		allGpos = listGposLdapi(domain.baseDN);
		reloadLinks(selectRow);
	}

	int currentRow() const {
		int r = linkList->getCurrentItem();
		return (r >= 0 && r < (int)links.size()) ? r : -1;
	}

	long onUpdNeedsLink(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, currentRow() >= 0 ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	long onUpdUp(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, currentRow() > 0 ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	long onUpdDown(FXObject* sender, FXSelector, void*) {
		int r = currentRow();
		sender->handle(this, FXSEL(SEL_COMMAND, (r >= 0 && r + 1 < (int)links.size()) ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}

	long onGpoNew(FXObject*, FXSelector, void*) {
		FXString name = "Neues Gruppenrichtlinienobjekt";
		if (!FXInputDialog::getString(name, this, "Neues Gruppenrichtlinienobjekt", "Name:")) return 1;
		name.trim();
		if (name.empty()) return 1;
		for (auto& g : allGpos) {
			if (strcasecmp(g.displayName.c_str(), name.text()) == 0) {
				if (FXMessageBox::question(this, MBOX_YES_NO, "Gruppenrichtlinie",
				        "Es gibt bereits ein Gruppenrichtlinienobjekt mit dem Namen \"%s\".\n\n"
				        "Soll das vorhandene Objekt mit diesem Container verknüpft werden?", name.text()) != MBOX_CLICKED_YES) return 1;
				FXString errorMsg;
				if (!linkGpo(this, g.guid.c_str(), fullDN.c_str(), errorMsg))
					FXMessageBox::error(this, MBOX_OK, "Verknüpfen fehlgeschlagen", "%s", errorMsg.text());
				refreshLinksFromDirectory((int)links.size());
				return 1;
			}
		}
		FXString errorMsg;
		getApp()->beginWaitCursor();
		bool ok = createGpo(this, name, errorMsg);
		getApp()->endWaitCursor();
		if (!ok) { FXMessageBox::error(this, MBOX_OK, "Anlegen fehlgeschlagen", "%s", errorMsg.text()); return 1; }
		allGpos = listGposLdapi(domain.baseDN);
		for (auto& g : allGpos) {
			if (g.displayName != name.text()) continue;
			if (!linkGpo(this, g.guid.c_str(), fullDN.c_str(), errorMsg))
				FXMessageBox::error(this, MBOX_OK, "Verknüpfen fehlgeschlagen", "%s", errorMsg.text());
			break;
		}
		// Neue Verknuepfung hat die niedrigste Prioritaet -- letzte Zeile.
		refreshLinksFromDirectory((int)links.size());
		return 1;
	}

	long onGpoAdd(FXObject*, FXSelector, void*) {
		allGpos = listGposLdapi(domain.baseDN);
		AddGpoLinkDialog dlg(this, domain, allGpos, links);
		if (!dlg.execute(PLACEMENT_OWNER) || !dlg.selected()) return 1;
		FXString errorMsg;
		if (!linkGpo(this, dlg.selected()->guid.c_str(), fullDN.c_str(), errorMsg))
			FXMessageBox::error(this, MBOX_OK, "Verknüpfen fehlgeschlagen", "%s", errorMsg.text());
		refreshLinksFromDirectory((int)links.size());
		return 1;
	}

	long onGpoEdit(FXObject*, FXSelector, void*) {
		int r = currentRow();
		if (r < 0) return 1;
		const GpLinkEntry& l = links[linkIndexForRow(r)];
		const GpoSummary* g = gpoByGuid(l.guid);
		GpoEditorWindow win(this, domain, l.guid, g ? FXString(g->displayName.c_str()) : FXString(l.guid.c_str()));
		win.execute(PLACEMENT_SCREEN);
		refreshLinksFromDirectory(r);
		return 1;
	}

	long onLinkDoubleClick(FXObject*, FXSelector, void*) { return onGpoEdit(NULL, 0, NULL); }

	long moveLink(int rowDelta) {
		int r = currentRow();
		if (r < 0) return 1;
		int target = r + rowDelta;
		if (target < 0 || target >= (int)links.size()) return 1;
		std::vector<GpLinkEntry> changed = links;
		std::swap(changed[linkIndexForRow(r)], changed[linkIndexForRow(target)]);
		FXString errorMsg;
		if (!writeGpLink(this, domain.realm, fullDN, changed, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Reihenfolge ändern fehlgeschlagen", "%s", errorMsg.text());
			return 1;
		}
		refreshLinksFromDirectory(target);
		return 1;
	}
	long onGpoUp(FXObject*, FXSelector, void*) { return moveLink(-1); }
	long onGpoDown(FXObject*, FXSelector, void*) { return moveLink(+1); }

	long onGpoOptions(FXObject*, FXSelector, void*) {
		int r = currentRow();
		if (r < 0) return 1;
		int li = linkIndexForRow(r);
		const GpoSummary* g = gpoByGuid(links[li].guid);
		FXString name = g ? FXString(g->displayName.c_str()) : FXString(links[li].guid.c_str());

		FXDialogBox dlg(this, name + " - Optionen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,0,0, 10,10,10,10);
		FXVerticalFrame* main = new FXVerticalFrame(&dlg, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(main, "Verknüpfungsoptionen:");
		FXCheckButton* noOverride = new FXCheckButton(main, "&Kein Vorrang: Andere Gruppenrichtlinienobjekte können die hier\n"
		                                                    "festgelegten Richtlinien nicht außer Kraft setzen");
		FXCheckButton* disabled = new FXCheckButton(main, "&Deaktiviert: Das Gruppenrichtlinienobjekt wird nicht auf diesen\n"
		                                                  "Container angewendet");
		noOverride->setCheck((links[li].options & GPLINK_OPT_ENFORCE) != 0);
		disabled->setCheck((links[li].options & GPLINK_OPT_DISABLE) != 0);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;

		if (disabled->getCheck() && !(links[li].options & GPLINK_OPT_DISABLE)) {
			if (FXMessageBox::question(this, MBOX_YES_NO, "Gruppenrichtlinie",
			        "Möchten Sie diese Gruppenrichtlinienobjekt-Verknüpfung wirklich deaktivieren?\n"
			        "Das Gruppenrichtlinienobjekt wird dann nicht mehr auf diesen Container angewendet.") != MBOX_CLICKED_YES) return 1;
		}
		std::vector<GpLinkEntry> changed = links;
		changed[li].options = (noOverride->getCheck() ? GPLINK_OPT_ENFORCE : 0) | (disabled->getCheck() ? GPLINK_OPT_DISABLE : 0);
		if (changed[li].options == links[li].options) return 1;
		FXString errorMsg;
		if (!writeGpLink(this, domain.realm, fullDN, changed, errorMsg))
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		refreshLinksFromDirectory(r);
		return 1;
	}

	long onGpoDelete(FXObject*, FXSelector, void*) {
		int r = currentRow();
		if (r < 0) return 1;
		std::string guid = links[linkIndexForRow(r)].guid;
		const GpoSummary* g = gpoByGuid(guid);
		FXString name = g ? FXString(g->displayName.c_str()) : FXString(guid.c_str());

		FXDialogBox dlg(this, "Löschen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,0,0, 10,10,10,10);
		FXVerticalFrame* main = new FXVerticalFrame(&dlg, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(main, "Wie möchten Sie dieses Gruppenrichtlinienobjekt löschen?", NULL, JUSTIFY_LEFT);
		FXint choice = 0;
		FXDataTarget target(choice);
		new FXRadioButton(main, "&Verknüpfung aus der Liste entfernen", &target, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(main, "Verknüpfung entfernen und das Gruppenrichtlinienobjekt &dauerhaft löschen", &target, FXDataTarget::ID_OPTION + 1);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;

		FXString errorMsg;
		if (choice == 1) {
			if (FXMessageBox::warning(this, MBOX_YES_NO, "Gruppenrichtlinie",
			        "\"%s\" wird endgültig gelöscht -- mit allen Einstellungen und allen\n"
			        "Verknüpfungen zu anderen Containern.\n\nFortfahren?", name.text()) != MBOX_CLICKED_YES) return 1;
			unlinkGpo(this, guid.c_str(), fullDN.c_str(), errorMsg);
			if (!deleteGpoCompletely(this, guid.c_str(), errorMsg))
				FXMessageBox::error(this, MBOX_OK, "Löschen fehlgeschlagen", "%s", errorMsg.text());
		} else if (!unlinkGpo(this, guid.c_str(), fullDN.c_str(), errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Entfernen fehlgeschlagen", "%s", errorMsg.text());
		}
		refreshLinksFromDirectory(r);
		return 1;
	}

	long onGpoProps(FXObject*, FXSelector, void*) {
		int r = currentRow();
		if (r < 0) return 1;
		const GpoSummary* g = gpoByGuid(links[linkIndexForRow(r)].guid);
		if (!g) return 1;
		GpoPropertiesDialog dlg(this, domain, *g);
		dlg.execute(PLACEMENT_OWNER);
		refreshLinksFromDirectory(r);
		return 1;
	}

	// ---- OK / Übernehmen ---------------------------------------------
	void collectGeneralChanges(std::string& ldif) {
		auto attr = [&](const char* name, const std::string& orig, std::string now) {
			now = trimStr(now);
			if (now == trimStr(orig)) return;
			ldif += std::string("replace: ") + name + "\n";
			if (!now.empty()) ldif += ldifAttrLine(name, now);
			ldif += "-\n";
		};
		attr("description", origDesc, descField->getText().text());
		if (isDomainRoot) return;
		attr("street", crlfToLf(origStreet), streetText->getText().text());
		attr("l", origCity, cityField->getText().text());
		attr("st", origState, stateField->getText().text());
		attr("postalCode", origZip, zipField->getText().text());
		std::string cname;
		int cnum;
		std::string code = selectedCountryCode(cname, cnum);
		if (lowerCopy(code) != lowerCopy(origCountry)) {
			if (code.empty()) {
				ldif += "replace: c\n-\nreplace: co\n-\nreplace: countryCode\ncountryCode: 0\n-\n";
			} else {
				ldif += "replace: c\n" + ldifAttrLine("c", code) + "-\n";
				ldif += "replace: co\n" + ldifAttrLine("co", cname) + "-\n";
				ldif += "replace: countryCode\ncountryCode: " + std::to_string(cnum) + "\n-\n";
			}
		}
	}

	bool isDirty() {
		std::string ldif;
		collectGeneralChanges(ldif);
		return !ldif.empty() || lowerCopy(managedBy->getManagerDn()) != lowerCopy(origManagerDn) || blockInheritance->getCheck() != origBlock;
	}

	bool apply() {
		std::string ldif;
		collectGeneralChanges(ldif);
		if (lowerCopy(managedBy->getManagerDn()) != lowerCopy(origManagerDn)) {
			ldif += "replace: managedBy\n";
			if (!managedBy->getManagerDn().empty()) ldif += ldifAttrLine("managedBy", managedBy->getManagerDn());
			ldif += "-\n";
		}
		if (blockInheritance->getCheck() != origBlock)
			ldif += std::string("replace: gPOptions\ngPOptions: ") + (blockInheritance->getCheck() ? "1" : "0") + "\n-\n";
		if (ldif.empty()) return true;

		ldif = "dn: " + fullDN + "\nchangetype: modify\n" + ldif;
		std::string log;
		FXString errorMsg;
		if (!runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
			return false;
		}
		origDesc = trimStr(descField->getText().text());
		if (!isDomainRoot) {
			origStreet = lfToCrlf(trimStr(streetText->getText().text()));
			origCity = trimStr(cityField->getText().text());
			origState = trimStr(stateField->getText().text());
			origZip = trimStr(zipField->getText().text());
			std::string cname; int cnum;
			origCountry = selectedCountryCode(cname, cnum);
		}
		origManagerDn = managedBy->getManagerDn();
		origBlock = blockInheritance->getCheck();
		return true;
	}

	long onUpdApply(FXObject* sender, FXSelector, void*) {
		sender->handle(this, FXSEL(SEL_COMMAND, isDirty() ? ID_ENABLE : ID_DISABLE), NULL);
		return 1;
	}
	long onApply(FXObject*, FXSelector, void*) { apply(); return 1; }
	long onOk(FXObject*, FXSelector, void*) {
		if (!apply()) return 1;
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}

	virtual ~OUPropertiesDialog() {}
};
FXDEFMAP(OUPropertiesDialog) OUPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_OK, OUPropertiesDialog::onOk),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_APPLY, OUPropertiesDialog::onApply),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_APPLY, OUPropertiesDialog::onUpdApply),
	FXMAPFUNC(SEL_DOUBLECLICKED, OUPropertiesDialog::ID_LINKLIST, OUPropertiesDialog::onLinkDoubleClick),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_NEW, OUPropertiesDialog::onGpoNew),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_ADD, OUPropertiesDialog::onGpoAdd),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_EDIT, OUPropertiesDialog::onGpoEdit),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_GPO_EDIT, OUPropertiesDialog::onUpdNeedsLink),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_UP, OUPropertiesDialog::onGpoUp),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_GPO_UP, OUPropertiesDialog::onUpdUp),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_DOWN, OUPropertiesDialog::onGpoDown),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_GPO_DOWN, OUPropertiesDialog::onUpdDown),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_OPTIONS, OUPropertiesDialog::onGpoOptions),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_GPO_OPTIONS, OUPropertiesDialog::onUpdNeedsLink),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_DELETE, OUPropertiesDialog::onGpoDelete),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_GPO_DELETE, OUPropertiesDialog::onUpdNeedsLink),
	FXMAPFUNC(SEL_COMMAND, OUPropertiesDialog::ID_GPO_PROPS, OUPropertiesDialog::onGpoProps),
	FXMAPFUNC(SEL_UPDATE, OUPropertiesDialog::ID_GPO_PROPS, OUPropertiesDialog::onUpdNeedsLink),
};
FXIMPLEMENT(OUPropertiesDialog, FXDialogBox, OUPropertiesDialogMap, ARRAYNUMBER(OUPropertiesDialogMap))

// ---------------------------------------------------------------------
// LDAP-Filterwerte maskieren (RFC 4515), damit Eingaben wie "(" oder "*"
// die Suche nicht verbiegen.
// ---------------------------------------------------------------------
static std::string ldapFilterEscape(const std::string& v) {
	std::string out;
	for (unsigned char c : v) {
		switch (c) {
			case '*': out += "\\2a"; break;
			case '(': out += "\\28"; break;
			case ')': out += "\\29"; break;
			case '\\': out += "\\5c"; break;
			case 0: out += "\\00"; break;
			default: out += (char)c;
		}
	}
	return out;
}

// Objekt aus einer vollen DN fuer die Eigenschaftendialoge zusammenbauen.
static DirObject dirObjectFromDn(const std::string& dn, const DomainInfo& domain, ObjType type, const std::string& sam) {
	DirObject obj;
	obj.name = dnLeafName(dn);
	obj.accountName = sam.c_str();
	std::string suffix = "," + std::string(domain.baseDN.text());
	std::string rel = dn;
	if (rel.size() > suffix.size() && lowerCopy(rel).compare(rel.size() - suffix.size(), suffix.size(), lowerCopy(suffix)) == 0)
		rel = rel.substr(0, rel.size() - suffix.size());
	obj.dn = rel.c_str();
	obj.type = type;
	return obj;
}

// ---------------------------------------------------------------------
// Dialog "Benutzer, Kontakte und Gruppen suchen".
// ---------------------------------------------------------------------
class FindObjectsDialog : public FXDialogBox {
	FXDECLARE(FindObjectsDialog)
private:
	DomainInfo domain;
	FXTextField* nameField = nullptr, *descField = nullptr;
	FXIconList* results = nullptr;
	FXLabel* countLabel = nullptr;
	struct Hit { std::string dn, sam; ObjType type; };
	std::vector<Hit> hits;
protected:
	FindObjectsDialog() {}
public:
	enum { ID_FIND = FXDialogBox::ID_LAST, ID_CLEAR, ID_RESULTS };
	FindObjectsDialog(FXWindow* owner, const DomainInfo& domain_)
		: FXDialogBox(owner, "Benutzer, Kontakte und Gruppen suchen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,620,460),
		  domain(domain_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 8,8,8,8, 0,6);
		FXHorizontalFrame* top = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,0);
		FXVerticalFrame* left = new FXVerticalFrame(top, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 0,6);
		FXHorizontalFrame* scope = new FXHorizontalFrame(left, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(scope, "Suchen:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,60,0);
		FXListBox* what = new FXListBox(scope, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		what->appendItem("Benutzer, Kontakte und Gruppen");
		what->disable();
		new FXLabel(scope, "  In:", NULL, LAYOUT_CENTER_Y);
		FXListBox* where = new FXListBox(scope, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		FXString realmLower = domain.realm; realmLower.lower();
		where->appendItem(realmLower, sharedPngIcon(resico_server));
		where->disable();

		FXTabBook* tabs = new FXTabBook(left, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X);
		new FXTabItem(tabs, "Benutzer, Kontakte und Gruppen", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X, 0,0,0,0, 10,10,10,10, 0,6);
		nameField = propLabeledField(page, "&Name:", 100);
		descField = propLabeledField(page, "&Beschreibung:", 100);

		FXVerticalFrame* btns = new FXVerticalFrame(top, PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,24,0, 0,6);
		new FXButton(btns, "&Jetzt suchen", NULL, this, ID_FIND, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "&Beenden", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "N&eue Suche", NULL, this, ID_CLEAR, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);

		FXPacker* rf = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		results = new FXIconList(rf, this, ID_RESULTS, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		results->appendHeader("Name", NULL, 180);
		results->appendHeader("Typ", NULL, 220);
		results->appendHeader("Beschreibung", NULL, 200);
		countLabel = new FXLabel(main, " ", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
	}

	virtual void create() {
		FXDialogBox::create();
		nameField->setFocus();
	}

	long onFind(FXObject*, FXSelector, void*) {
		std::string name = trimStr(nameField->getText().text());
		std::string desc = trimStr(descField->getText().text());
		std::string filter = "(&(|(objectClass=user)(objectClass=group)(objectClass=contact))(!(objectClass=computer))";
		if (!name.empty()) {
			std::string n = ldapFilterEscape(name);
			filter += "(|(cn=*" + n + "*)(sAMAccountName=*" + n + "*)(displayName=*" + n + "*))";
		}
		if (!desc.empty()) filter += "(description=*" + ldapFilterEscape(desc) + "*)";
		filter += ")";
		getApp()->beginWaitCursor();
		auto recs = ldapiSearch(domain.baseDN.text(), "sub", filter, { "sAMAccountName", "objectClass", "groupType", "description" });
		getApp()->endWaitCursor();
		std::sort(recs.begin(), recs.end(), [](const std::multimap<std::string, std::string>& a, const std::multimap<std::string, std::string>& b) {
			return germanLess(dnLeafName(ldifFirst(a, "dn")).text(), dnLeafName(ldifFirst(b, "dn")).text());
		});
		results->clearItems();
		hits.clear();
		for (auto& rec : recs) {
			std::string cls;
			auto range = rec.equal_range("objectclass");
			for (auto it = range.first; it != range.second; ++it) cls = lowerCopy(it->second);
			Hit h;
			h.dn = ldifFirst(rec, "dn");
			h.sam = ldifFirst(rec, "sAMAccountName");
			FXString typeName;
			const unsigned char* icon;
			if (cls == "group") {
				long gt = 0;
				try { gt = std::stol(ldifFirst(rec, "groupType")); } catch (...) {}
				typeName = groupTypeName(gt); h.type = OBJ_GROUP; icon = resico_users;
			} else if (cls == "contact") {
				typeName = "Kontakt"; h.type = OBJ_OTHER; icon = resico_user;
			} else {
				typeName = "Benutzer"; h.type = OBJ_USER; icon = resico_user;
			}
			FXIcon* ic = sharedPngIcon(icon);
			results->appendItem(dnLeafName(h.dn) + "\t" + typeName + "\t" + ldifFirst(rec, "description").c_str(), ic, ic);
			hits.push_back(h);
		}
		countLabel->setText((std::to_string(hits.size()) + " Element(e) gefunden").c_str());
		return 1;
	}

	long onClear(FXObject*, FXSelector, void*) {
		nameField->setText("");
		descField->setText("");
		results->clearItems();
		hits.clear();
		countLabel->setText(" ");
		nameField->setFocus();
		return 1;
	}

	long onResultDoubleClick(FXObject*, FXSelector, void* ptr) {
		FXint idx = (FXint)(FXival)ptr;
		if (idx < 0 || idx >= (int)hits.size()) return 1;
		const Hit& h = hits[idx];
		DirObject obj = dirObjectFromDn(h.dn, domain, h.type, h.sam);
		if (h.type == OBJ_USER) { UserPropertiesDialog dlg(this, domain, obj); dlg.execute(PLACEMENT_OWNER); }
		else if (h.type == OBJ_GROUP) { GroupPropertiesDialog dlg(this, domain, obj); dlg.execute(PLACEMENT_OWNER); }
		return 1;
	}
	virtual ~FindObjectsDialog() {}
};
FXDEFMAP(FindObjectsDialog) FindObjectsDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, FindObjectsDialog::ID_FIND, FindObjectsDialog::onFind),
	FXMAPFUNC(SEL_COMMAND, FindObjectsDialog::ID_CLEAR, FindObjectsDialog::onClear),
	FXMAPFUNC(SEL_DOUBLECLICKED, FindObjectsDialog::ID_RESULTS, FindObjectsDialog::onResultDoubleClick),
};
FXIMPLEMENT(FindObjectsDialog, FXDialogBox, FindObjectsDialogMap, ARRAYNUMBER(FindObjectsDialogMap))

// ---------------------------------------------------------------------
// "Neues Objekt - Kontakt" und "Neues Objekt - Freigegebener Ordner".
// Kopfzeile "Erstellen in: <Ordner>" wie im Original.
// ---------------------------------------------------------------------
static void newObjectHeader(FXComposite* p, const unsigned char* icon, const FXString& containerFolder) {
	FXHorizontalFrame* head = new FXHorizontalFrame(p, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
	new FXLabel(head, "", sharedPngIcon(icon), LAYOUT_CENTER_Y);
	new FXLabel(head, "Erstellen in:   " + containerFolder, NULL, LAYOUT_CENTER_Y);
	new FXHorizontalSeparator(p, SEPARATOR_GROOVE | LAYOUT_FILL_X);
}

class NewContactDialog : public FXDialogBox {
	FXDECLARE(NewContactDialog)
private:
	FXTextField* given = nullptr, *initials = nullptr, *surname = nullptr, *fullName = nullptr, *display = nullptr;
	bool fullNameTouched = false;
protected:
	NewContactDialog() {}
public:
	enum { ID_NAMEPART = FXDialogBox::ID_LAST, ID_FULLNAME };
	NewContactDialog(FXWindow* owner, const FXString& containerFolder)
		: FXDialogBox(owner, "Neues Objekt - Kontakt", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		newObjectHeader(main, resico_user, containerFolder);
		FXHorizontalFrame* row = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(row, "&Vorname:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,130,0);
		given = new FXTextField(row, 14, this, ID_NAMEPART, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		new FXLabel(row, "&Initialen:", NULL, LAYOUT_CENTER_Y);
		initials = new FXTextField(row, 4, this, ID_NAMEPART, FRAME_SUNKEN | FRAME_THICK);
		surname = propLabeledField(main, "&Nachname:", 130);
		surname->setTarget(this); surname->setSelector(ID_NAMEPART);
		fullName = propLabeledField(main, "&Vollständiger Name:", 130);
		fullName->setTarget(this); fullName->setSelector(ID_FULLNAME);
		display = propLabeledField(main, "&Anzeigename:", 130);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	// Wie im Original setzt sich der vollstaendige Name aus Vorname,
	// Initialen und Nachname zusammen, bis man ihn selbst aendert.
	long onNamePart(FXObject*, FXSelector, void*) {
		if (fullNameTouched) return 1;
		FXString v = given->getText();
		if (!initials->getText().empty()) v += " " + initials->getText() + ".";
		if (!surname->getText().empty()) v += (v.empty() ? "" : " ") + surname->getText();
		fullName->setText(v.trim());
		return 1;
	}
	long onFullName(FXObject*, FXSelector, void*) { fullNameTouched = true; return 1; }
	std::string getGiven() const { return trimStr(given->getText().text()); }
	std::string getInitials() const { return trimStr(initials->getText().text()); }
	std::string getSurname() const { return trimStr(surname->getText().text()); }
	std::string getFullName() const { return trimStr(fullName->getText().text()); }
	std::string getDisplay() const { return trimStr(display->getText().text()); }
	virtual ~NewContactDialog() {}
};
FXDEFMAP(NewContactDialog) NewContactDialogMap[] = {
	FXMAPFUNC(SEL_CHANGED, NewContactDialog::ID_NAMEPART, NewContactDialog::onNamePart),
	FXMAPFUNC(SEL_CHANGED, NewContactDialog::ID_FULLNAME, NewContactDialog::onFullName),
};
FXIMPLEMENT(NewContactDialog, FXDialogBox, NewContactDialogMap, ARRAYNUMBER(NewContactDialogMap))

class NewSharedFolderDialog : public FXDialogBox {
	FXDECLARE(NewSharedFolderDialog)
private:
	FXTextField* name = nullptr, *unc = nullptr;
protected:
	NewSharedFolderDialog() {}
public:
	NewSharedFolderDialog(FXWindow* owner, const FXString& containerFolder)
		: FXDialogBox(owner, "Neues Objekt - Freigegebener Ordner", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		newObjectHeader(main, resico_folder, containerFolder);
		new FXLabel(main, "&Name:");
		name = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		new FXLabel(main, "&Netzwerkpfad (\\\\Server\\Freigabe):");
		unc = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	std::string getName() const { return trimStr(name->getText().text()); }
	std::string getUnc() const { return trimStr(unc->getText().text()); }
	virtual ~NewSharedFolderDialog() {}
};
FXIMPLEMENT(NewSharedFolderDialog, FXDialogBox, NULL, 0)

// Wert fuer eine RDN maskieren (RFC 4514): , + " \ < > ; = und Rand-Leerzeichen.
static std::string rdnEscape(const std::string& v) {
	std::string out;
	for (size_t i = 0; i < v.size(); i++) {
		char c = v[i];
		bool edgeSpace = c == ' ' && (i == 0 || i + 1 == v.size());
		if (strchr(",+\"\\<>;=", c) || edgeSpace || (i == 0 && c == '#')) out += '\\';
		out += c;
	}
	return out;
}

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
class DsAdminWindow : public FXMainWindow {
	FXDECLARE(DsAdminWindow)
private:
	FXMenuBar* menubar;
	FXMenuPane *konsolemenu, *vorgangmenu, *ansichtmenu, *hilfemenu;
	FXToolBar* toolbar;
	FXSplitter* splitter;
	FXPacker* treeframe = nullptr;
	// Verlauf fuer Zurueck/Vor -- relative DNs der besuchten Container.
	std::vector<FXString> history;
	int historyPos = -1;
	bool navigatingHistory = false;
	FXTreeList* tree;
	FXIconList* list;

	FXIcon *icoRoot, *icoFolder, *icoUser, *icoUsers, *icoServer;

	DomainInfo domain;
	std::map<FXTreeItem*, FXString> itemToRelDN; // Baum-Item -> relative DN des Containers
	FXTreeItem* domainRootItem;
	FXString currentContainerRelDN;
	std::vector<DirObject> currentObjects;
	FXString statusText;
	bool propertiesFromList = false; // steuert onProperties(): Baum- oder Listen-Rechtsklick war die Quelle
	FXLabel* statusLabel;

protected:
	DsAdminWindow() {}
public:
	enum {
		ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_REFRESH, ID_ABOUT,
		ID_NEW_USER, ID_NEW_GROUP, ID_NEW_OU, ID_NEW_COMPUTER, ID_DELETE_OBJECT, ID_PROPERTIES, ID_GROUP_PROPS,
		ID_USER_PROPS, ID_MOVE_OBJECT, ID_RENAME_OBJECT, ID_RESET_PASSWORD, ID_ADVANCED_VIEW,
		ID_BACK, ID_FORWARD, ID_UP, ID_TOGGLE_TREE, ID_TOOL_PROPERTIES, ID_EXPORT_LIST, ID_FIND,
		ID_ADD_TO_GROUP, ID_NEW_CONTACT, ID_NEW_SHARED_FOLDER, ID_SEL_OBJECT
	};
	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onListDoubleClick(FXObject*, FXSelector, void*);
	long onResetPassword(FXObject*, FXSelector, void*);
	long onAdvancedView(FXObject*, FXSelector, void*);
	long onUpdAdvancedView(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	long onNewUser(FXObject*, FXSelector, void*);
	long onNewGroup(FXObject*, FXSelector, void*);
	long onNewOU(FXObject*, FXSelector, void*);
	long onNewComputer(FXObject*, FXSelector, void*);
	long onDeleteObject(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onGroupProperties(FXObject*, FXSelector, void*);
	long onUserProperties(FXObject*, FXSelector, void*);
	long onMoveObject(FXObject*, FXSelector, void*);
	long onRenameObject(FXObject*, FXSelector, void*);
	long onBack(FXObject*, FXSelector, void*);
	long onForward(FXObject*, FXSelector, void*);
	long onUp(FXObject*, FXSelector, void*);
	long onUpdBack(FXObject*, FXSelector, void*);
	long onUpdForward(FXObject*, FXSelector, void*);
	long onUpdUp(FXObject*, FXSelector, void*);
	long onToggleTree(FXObject*, FXSelector, void*);
	long onToolProperties(FXObject*, FXSelector, void*);
	long onExportList(FXObject*, FXSelector, void*);
	long onFind(FXObject*, FXSelector, void*);
	long onAddToGroup(FXObject*, FXSelector, void*);
	long onUpdAddToGroup(FXObject*, FXSelector, void*);
	long onUpdSelObject(FXObject*, FXSelector, void*);
	long onNewContact(FXObject*, FXSelector, void*);
	long onNewSharedFolder(FXObject*, FXSelector, void*);
	void selectContainer(const FXString& relDN);
	int selectedListIndex() const;
	void fillNewMenu(FXMenuPane* pane);

	DsAdminWindow(FXApp* a);
	void loadTree();
	void showContainer(FXString relDN);
	virtual void create();
	virtual ~DsAdminWindow() {}
};

FXDEFMAP(DsAdminWindow) DsAdminWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, DsAdminWindow::ID_TREE, DsAdminWindow::onTreeChanged),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, DsAdminWindow::ID_TREE, DsAdminWindow::onTreeRightClick),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, DsAdminWindow::ID_LIST, DsAdminWindow::onListRightClick),
	FXMAPFUNC(SEL_DOUBLECLICKED, DsAdminWindow::ID_LIST, DsAdminWindow::onListDoubleClick),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_RESET_PASSWORD, DsAdminWindow::onResetPassword),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_ADVANCED_VIEW, DsAdminWindow::onAdvancedView),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_ADVANCED_VIEW, DsAdminWindow::onUpdAdvancedView),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_REFRESH, DsAdminWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_ABOUT, DsAdminWindow::onAbout),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_NEW_USER, DsAdminWindow::onNewUser),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_NEW_GROUP, DsAdminWindow::onNewGroup),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_NEW_OU, DsAdminWindow::onNewOU),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_NEW_COMPUTER, DsAdminWindow::onNewComputer),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_DELETE_OBJECT, DsAdminWindow::onDeleteObject),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_PROPERTIES, DsAdminWindow::onProperties),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_GROUP_PROPS, DsAdminWindow::onGroupProperties),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_USER_PROPS, DsAdminWindow::onUserProperties),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_MOVE_OBJECT, DsAdminWindow::onMoveObject),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_RENAME_OBJECT, DsAdminWindow::onRenameObject),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_BACK, DsAdminWindow::onBack),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_BACK, DsAdminWindow::onUpdBack),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_FORWARD, DsAdminWindow::onForward),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_FORWARD, DsAdminWindow::onUpdForward),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_UP, DsAdminWindow::onUp),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_UP, DsAdminWindow::onUpdUp),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_TOGGLE_TREE, DsAdminWindow::onToggleTree),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_TOOL_PROPERTIES, DsAdminWindow::onToolProperties),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_EXPORT_LIST, DsAdminWindow::onExportList),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_FIND, DsAdminWindow::onFind),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_ADD_TO_GROUP, DsAdminWindow::onAddToGroup),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_ADD_TO_GROUP, DsAdminWindow::onUpdAddToGroup),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_MOVE_OBJECT, DsAdminWindow::onUpdSelObject),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_RENAME_OBJECT, DsAdminWindow::onUpdSelObject),
	FXMAPFUNC(SEL_UPDATE, DsAdminWindow::ID_DELETE_OBJECT, DsAdminWindow::onUpdSelObject),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_NEW_CONTACT, DsAdminWindow::onNewContact),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_NEW_SHARED_FOLDER, DsAdminWindow::onNewSharedFolder),
};
FXIMPLEMENT(DsAdminWindow, FXMainWindow, DsAdminWindowMap, ARRAYNUMBER(DsAdminWindowMap))

DsAdminWindow::DsAdminWindow(FXApp* a)
	: FXMainWindow(a, "Active Directory-Benutzer und -Computer", NULL, NULL, DECOR_ALL, 0, 0, 820, 480) {

	domain = detectDomain();
	g_advancedView = a->reg().readBoolEntry("Ansicht", "ErweiterteFunktionen", false);

	FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);

	menubar = new FXMenuBar(main, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
	konsolemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Konsole", NULL, konsolemenu);
	new FXMenuCommand(konsolemenu, "&Beenden", NULL, getApp(), FXApp::ID_QUIT);
	vorgangmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Suchen...", NULL, this, ID_FIND);
	FXMenuPane* vorgangNeu = new FXMenuPane(this);
	fillNewMenu(vorgangNeu);
	new FXMenuCascade(vorgangmenu, "&Neu", NULL, vorgangNeu);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "Zu &Gruppe hinzufügen...", NULL, this, ID_ADD_TO_GROUP);
	new FXMenuCommand(vorgangmenu, "&Verschieben...", NULL, this, ID_MOVE_OBJECT);
	new FXMenuCommand(vorgangmenu, "U&mbenennen...", NULL, this, ID_RENAME_OBJECT);
	new FXMenuCommand(vorgangmenu, "&Löschen", NULL, this, ID_DELETE_OBJECT);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuCommand(vorgangmenu, "Liste e&xportieren...", NULL, this, ID_EXPORT_LIST);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Eigenschaften", NULL, this, ID_TOOL_PROPERTIES);
	ansichtmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Ansicht", NULL, ansichtmenu);
	new FXMenuCheck(ansichtmenu, "&Erweiterte Funktionen", this, ID_ADVANCED_VIEW);
	hilfemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&?", NULL, hilfemenu);
	new FXMenuCommand(hilfemenu, "&Info...", NULL, this, ID_ABOUT);

	// Werkzeugleiste wie im Original: MMC-Standardknoepfe, dann die des
	// Snap-Ins. Die Snap-In-Symbole (res/dsa) sind vorlaeufig.
	toolbar = new FXToolBar(main, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
	auto tbButton = [&](const char* tip, FXIcon* icon, FXSelector sel) {
		new FXButton(toolbar, tip, icon, this, sel, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	};
	auto tbSeparator = [&]() { new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2); };
	auto gif = [&](const unsigned char* data) { return new FXGIFIcon(getApp(), data); };
	auto png = [&](const unsigned char* data) { return new FXPNGIcon(getApp(), data, IMAGE_NEAREST); };
	tbButton("\tZurück", gif(resico_mmc_back), ID_BACK);
	tbButton("\tVor", gif(resico_mmc_forward), ID_FORWARD);
	tbSeparator();
	tbButton("\tEbene nach oben", gif(resico_mmc_up), ID_UP);
	tbButton("\tStruktur anzeigen/ausblenden", gif(resico_mmc_contree), ID_TOGGLE_TREE);
	tbSeparator();
	tbButton("\tEigenschaften", gif(resico_mmc_properties), ID_TOOL_PROPERTIES);
	tbButton("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
	tbButton("\tListe exportieren", gif(resico_mmc_export), ID_EXPORT_LIST);
	tbSeparator();
	tbButton("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	tbSeparator();
	tbButton("\tNeuen Benutzer im aktuellen Container erstellen", png(resico_dsa_newuser), ID_NEW_USER);
	tbButton("\tNeue Gruppe im aktuellen Container erstellen", png(resico_dsa_newgroup), ID_NEW_GROUP);
	tbButton("\tNeue Organisationseinheit im aktuellen Container erstellen", png(resico_dsa_newou), ID_NEW_OU);
	tbButton("\tObjekte in Active Directory suchen", png(resico_dsa_find), ID_FIND);
	tbButton("\tAusgewählte Objekte zu einer Gruppe hinzufügen", png(resico_dsa_addtogroup), ID_ADD_TO_GROUP);
	new FXToolTip(getApp());

	splitter = new FXSplitter(main, LAYOUT_FILL_X|LAYOUT_FILL_Y|SPLITTER_TRACKING);
	treeframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y, 0,0,260,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                       SCROLLERS_DONT_TRACK|FRAME_NORMAL|LAYOUT_FILL_X|LAYOUT_FILL_Y|
	                       TREELIST_SHOWS_BOXES|TREELIST_SHOWS_LINES|TREELIST_BROWSESELECT|TREELIST_ROOT_BOXES);
	FXPacker* listframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y|LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(listframe, this, ID_LIST,
	                       ICONLIST_DETAILED|ICONLIST_BROWSESELECT|LAYOUT_FILL_X|LAYOUT_FILL_Y|FRAME_NORMAL);
	list->appendHeader("Name", NULL, 200);
	list->appendHeader("Typ", NULL, 260);
	list->appendHeader("Beschreibung", NULL, 260);

	statusLabel = new FXLabel(main, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);

	icoRoot = new FXPNGIcon(getApp(), resico_network, IMAGE_NEAREST); icoRoot->create();
	icoFolder = new FXPNGIcon(getApp(), resico_folder, IMAGE_NEAREST); icoFolder->create();
	icoUser = new FXPNGIcon(getApp(), resico_user, IMAGE_NEAREST); icoUser->create();
	icoUsers = new FXPNGIcon(getApp(), resico_users, IMAGE_NEAREST); icoUsers->create();
	icoServer = new FXPNGIcon(getApp(), resico_server, IMAGE_NEAREST); icoServer->create();

	loadTree();
}

void DsAdminWindow::loadTree() {
	tree->clearItems();
	itemToRelDN.clear();
	if (!domain.isDC) {
		FXTreeItem* it = tree->appendItem(0, "Kein Domänencontroller -- dieser Server hat keine Active-Directory-Domäne.", icoRoot, icoRoot);
		(void)it;
		return;
	}
	FXString rootLabel = "Active Directory-Benutzer und -Computer [" + domain.realm + "]";
	FXTreeItem* rootIt = tree->appendItem(0, rootLabel, icoRoot, icoRoot);
	domainRootItem = tree->appendItem(rootIt, domain.realm, icoServer, icoServer);
	itemToRelDN[domainRootItem] = "";

	std::map<std::string, FXTreeItem*> itemByRelDN;
	std::vector<FXString> topContainers;
	bool ldapOk;
	std::vector<LdapChildInfo> rootChildren = ldapListChildren(domain.baseDN, ldapOk);
	if (ldapOk) {
		FXString suffix = "," + domain.baseDN;
		for (auto& c : rootChildren) {
			if (c.advancedOnly && !g_advancedView) continue;
			bool isOu = lowerCopy(c.objectClass) == "organizationalunit";
			if (!isOu && !isContainerClass(c.objectClass)) continue;
			FXString rel = c.dn.c_str();
			if (rel.length() > suffix.length()) rel = rel.left(rel.length() - suffix.length());
			topContainers.push_back(rel);
		}
		std::sort(topContainers.begin(), topContainers.end(), [](const FXString& a, const FXString& b) {
			return strcasecmp(dnLeafLabel(a).text(), dnLeafLabel(b).text()) < 0;
		});
	} else {
		topContainers = listTopContainers();
	}
	for (auto& cont : topContainers) {
		FXTreeItem* it = tree->appendItem(domainRootItem, dnLeafLabel(cont), icoFolder, icoFolder);
		itemToRelDN[it] = cont;
		itemByRelDN[cont.text()] = it;
	}

	// Verschachtelte Organisationseinheiten: nach Tiefe sortiert
	// einhaengen, dann existiert die Elternebene garantiert schon, wenn
	// ein Kind an die Reihe kommt. Die oberste Ebene steckt bereits in
	// listTopContainers() und wird hier uebersprungen.
	std::vector<FXString> ous = listAllOURelDNs(domain);
	std::sort(ous.begin(), ous.end(), [](const FXString& a, const FXString& b) {
		int ca = dnComponentCount(a), cb = dnComponentCount(b);
		if (ca != cb) return ca < cb;
		return strcmp(a.text(), b.text()) < 0;
	});
	for (auto& ou : ous) {
		if (itemByRelDN.count(ou.text())) continue;
		auto parent = itemByRelDN.find(dnParent(ou).text());
		// Eine OU, deren Elternebene nicht im Baum steht (z.B. unterhalb
		// eines ausgeblendeten Containers), lassen wir lieber weg, statt
		// sie faelschlich an die Domaenenwurzel zu haengen.
		if (parent == itemByRelDN.end()) continue;
		FXTreeItem* it = tree->appendItem(parent->second, dnLeafLabel(ou), icoFolder, icoFolder);
		itemToRelDN[it] = ou;
		itemByRelDN[ou.text()] = it;
	}

	tree->expandTree(rootIt);
	tree->expandTree(domainRootItem);
}

void DsAdminWindow::showContainer(FXString relDN) {
	if (!navigatingHistory && (historyPos < 0 || history[historyPos] != relDN)) {
		history.resize(historyPos + 1);
		history.push_back(relDN);
		historyPos = (int)history.size() - 1;
	}
	currentContainerRelDN = relDN;
	currentObjects = listContainerObjects(relDN, domain);
	enrichFromLdap(currentObjects, relDN.empty() ? domain.baseDN : relDN + "," + domain.baseDN, domain.baseDN);
	if (!g_advancedView) {
		currentObjects.erase(std::remove_if(currentObjects.begin(), currentObjects.end(),
		                     [](const DirObject& o) { return o.advancedOnly; }), currentObjects.end());
	}

	// Container, die (noch) nicht im Baum stehen -- z.B. unterhalb von
	// CN=System in der erweiterten Ansicht --, beim Oeffnen einhaengen,
	// damit man per Doppelklick weiter hinabsteigen kann.
	FXTreeItem* parentItem = nullptr;
	std::set<std::string> knownRelDNs;
	for (auto& kv : itemToRelDN) {
		knownRelDNs.insert(lowerCopy(kv.second.text()));
		if (kv.second == relDN) parentItem = kv.first;
	}
	if (parentItem) {
		for (auto& obj : currentObjects) {
			if (obj.type != OBJ_CONTAINER && obj.type != OBJ_OU) continue;
			if (knownRelDNs.count(lowerCopy(obj.dn.text()))) continue;
			FXTreeItem* it = tree->appendItem(parentItem, obj.name, icoFolder, icoFolder);
			itemToRelDN[it] = obj.dn;
		}
	}

	list->clearItems();
	for (auto& obj : currentObjects) {
		const char* typeName = "Objekt";
		FXIcon* ic = icoFolder;
		switch (obj.type) {
			case OBJ_USER: typeName = "Benutzer"; ic = icoUser; break;
			case OBJ_GROUP: typeName = groupTypeName(obj.groupType); ic = icoUsers; break;
			case OBJ_COMPUTER: typeName = "Computer"; ic = icoServer; break;
			case OBJ_OU: typeName = "Organisationseinheit"; ic = icoFolder; break;
			case OBJ_CONTAINER: typeName = "Container"; ic = icoFolder; break;
			default: {
				std::string cls = lowerCopy(obj.objectClass.text());
				if (cls == "contact") { typeName = "Kontakt"; ic = icoUser; }
				else if (cls == "volume") { typeName = "Freigegebener Ordner"; ic = icoFolder; }
				else if (cls == "printqueue") { typeName = "Drucker"; ic = icoServer; }
				else { typeName = obj.objectClass.empty() ? "Objekt" : obj.objectClass.text(); ic = icoFolder; }
				break;
			}
		}
		FXString txt = obj.name + "\t" + typeName + "\t" + obj.description;
		list->appendItem(txt, ic, ic);
	}
	char buf[64];
	snprintf(buf, sizeof(buf), "%d Objekt(e)", (int)currentObjects.size());
	statusLabel->setText(buf);
}

long DsAdminWindow::onTreeChanged(FXObject*, FXSelector, void*) {
	FXTreeItem* cur = tree->getCurrentItem();
	if (!cur || !itemToRelDN.count(cur)) return 1;
	showContainer(itemToRelDN[cur]);
	return 1;
}

long DsAdminWindow::onRefresh(FXObject*, FXSelector, void*) {
	domain = detectDomain();
	loadTree();
	if (!currentContainerRelDN.empty() || currentContainerRelDN == "") showContainer(currentContainerRelDN);
	return 1;
}

long DsAdminWindow::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Über Active Directory-Benutzer und -Computer",
		"Active Directory-Benutzer und -Computer für ice2k\n\n"
		"Verwaltet Domänenkonten (Benutzer/Gruppen/Organisationseinheiten)\n"
		"und Gruppenrichtlinien-Verknüpfungen einer Samba-AD-Domäne.");
	return 1;
}

static bool isOU(const FXString& relDN) { return relDN.left(3) == "OU="; }

static FXString relDNToFullDN(const FXString& relDN, const DomainInfo& domain) {
	if (relDN.empty()) return domain.baseDN;
	return relDN + "," + domain.baseDN;
}

// ---------------------------------------------------------------------
// Benutzer-Eigenschaften bearbeiten: Anzeigename/Beschreibung ueber
// LDAP-Modify (samba-tool bietet dafuer bei bestehenden Benutzern kein
// eigenes Kommandozeilen-Flag -- nur "user edit" oeffnet einen
// interaktiven Texteditor), Aktivieren/Deaktivieren und Kennwort
// zuruecksetzen ueber die entsprechenden samba-tool-Unterbefehle.
// ---------------------------------------------------------------------

long DsAdminWindow::onTreeRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item || !itemToRelDN.count(item)) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);
	FXString relDN = itemToRelDN[item];

	// Wichtig: setCurrentItem() loest KEIN SEL_CHANGED aus, also liefe
	// showContainer() nie -- und currentContainerRelDN zeigte weiter auf
	// den zuletzt mit links angeklickten Knoten. "Neu -> ..." haette die
	// Objekte dann im falschen Container angelegt: bei einer OU unter
	// CN=Computers scheitert das sichtbar, bei Benutzer/Gruppe/Computer
	// waere es still schiefgegangen.
	if (relDN != currentContainerRelDN) showContainer(relDN);

	FXMenuPane menu(this);
	FXMenuPane neuMenu(this);
	fillNewMenu(&neuMenu);
	new FXMenuCascade(&menu, "&Neu", NULL, &neuMenu);
	new FXMenuSeparator(&menu);
	if (relDN.empty() || isOU(relDN)) {
		propertiesFromList = false;
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_PROPERTIES);
		new FXMenuSeparator(&menu);
	}
	new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DsAdminWindow::onListRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	list->setCurrentItem(idx);
	list->selectItem(idx);

	FXMenuPane menu(this);
	DirObject& obj = currentObjects[idx];
	if (obj.type == OBJ_OU) {
		propertiesFromList = true;
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_PROPERTIES);
		new FXMenuSeparator(&menu);
	} else if (obj.type == OBJ_GROUP) {
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_GROUP_PROPS);
		new FXMenuSeparator(&menu);
	} else if (obj.type == OBJ_USER) {
		new FXMenuCommand(&menu, "&Kennwort zurücksetzen...", NULL, this, ID_RESET_PASSWORD);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_USER_PROPS);
		new FXMenuSeparator(&menu);
	}
	if (obj.type == OBJ_USER || obj.type == OBJ_GROUP || obj.type == OBJ_COMPUTER || obj.type == OBJ_OU) {
		new FXMenuCommand(&menu, "&Verschieben...", NULL, this, ID_MOVE_OBJECT);
		new FXMenuCommand(&menu, "U&mbenennen...", NULL, this, ID_RENAME_OBJECT);
		new FXMenuSeparator(&menu);
	}
	new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_OBJECT);
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DsAdminWindow::onNewUser(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Benutzer angelegt werden."); return 1; }
	NewUserDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (dlg.getUsername().trim().empty()) return 1;
	if (dlg.getPassword() != dlg.getConfirm()) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "Die Kennwörter stimmen nicht überein.");
		return 1;
	}
	FXString errorMsg;
	if (!createUser(dlg.getUsername().trim(), dlg.getPassword(), dlg.getFullName(), currentContainerRelDN, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onNewGroup(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann keine Gruppe angelegt werden."); return 1; }
	NewGroupDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (dlg.getName().trim().empty()) return 1;
	FXString errorMsg;
	if (!createGroup(dlg.getName().trim(), currentContainerRelDN, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onNewOU(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann keine Organisationseinheit angelegt werden."); return 1; }
	NewOUDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString name = dlg.getName().trim();
	if (name.empty()) return 1;
	FXString ouDN = FXString("OU=") + name;
	if (!currentContainerRelDN.empty()) ouDN += "," + currentContainerRelDN;
	FXString errorMsg;
	if (!createOU(ouDN, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onDeleteObject(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject obj = currentObjects[idx];
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts gelöscht werden."); return 1; }
	if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen",
	        "\"%s\" wirklich löschen?", obj.name.text()) != MBOX_CLICKED_YES) return 1;

	FXString errorMsg;
	bool ok = false;
	switch (obj.type) {
		case OBJ_USER: ok = deleteUser(obj.accountName, errorMsg); break;
		case OBJ_GROUP: ok = deleteGroup(obj.accountName, errorMsg); break;
		case OBJ_OU: ok = deleteOU(relDNToFullDN(obj.dn, domain), errorMsg); break;
		case OBJ_COMPUTER: ok = deleteComputer(obj.accountName, errorMsg); break;
		default: errorMsg = "Dieser Objekttyp kann hier noch nicht gelöscht werden."; break;
	}
	if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onNewComputer(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Computer angelegt werden."); return 1; }
	NewComputerDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString name = dlg.getName().trim();
	if (name.empty()) return 1;
	FXString errorMsg;
	if (!createComputer(name, currentContainerRelDN, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onUserProperties(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject obj = currentObjects[idx];
	if (obj.type != OBJ_USER) return 1;

	getApp()->beginWaitCursor();
	UserPropertiesDialog dlg(this, domain, obj);
	getApp()->endWaitCursor();
	dlg.execute(PLACEMENT_OWNER);
	// Auch nach "Abbrechen" neu laden -- "Übernehmen" kann vorher schon
	// geschrieben haben.
	onRefresh(NULL, 0, NULL);
	return 1;
}

// Im Original steht "Kennwort zurücksetzen..." im Kontextmenue des
// Benutzers, nicht in dessen Eigenschaften.
long DsAdminWindow::onResetPassword(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject obj = currentObjects[idx];
	if (obj.type != OBJ_USER) return 1;
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Kennwort gesetzt werden."); return 1; }

	SetPasswordDialog dlg(this, obj.name);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString pw = dlg.getPassword(), confirm = dlg.getConfirm();
	if (pw != confirm) { FXMessageBox::error(this, MBOX_OK, "Active Directory", "Die Kennwörter stimmen nicht überein."); return 1; }
	FXString errorMsg;
	if (setUserPassword(obj.accountName, pw, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Active Directory", "Das Kennwort für %s wurde geändert.", obj.name.text());
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

// Doppelklick in der Liste: Benutzer und Gruppen oeffnen ihre
// Eigenschaften, Container und Organisationseinheiten werden -- wie im
// Original -- im Baum geoeffnet.
long DsAdminWindow::onListDoubleClick(FXObject*, FXSelector, void* ptr) {
	FXint idx = (FXint)(FXival)ptr;
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	list->setCurrentItem(idx);
	DirObject obj = currentObjects[idx];
	switch (obj.type) {
		case OBJ_USER:
			return onUserProperties(NULL, 0, NULL);
		case OBJ_GROUP:
			return onGroupProperties(NULL, 0, NULL);
		case OBJ_OU:
		case OBJ_CONTAINER:
			for (auto& kv : itemToRelDN) {
				if (kv.second != obj.dn) continue;
				FXTreeItem* item = kv.first;
				if (item->getParent()) tree->expandTree(item->getParent());
				tree->selectItem(item);
				tree->setCurrentItem(item);
				tree->makeItemVisible(item);
				showContainer(obj.dn);
				return 1;
			}
			return 1;
		default:
			return 1;
	}
}

long DsAdminWindow::onMoveObject(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject obj = currentObjects[idx];
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts verschoben werden."); return 1; }

	MoveObjectDialog dlg(this, obj.name, domain.realm);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString targetDN = dlg.getTargetFullDN();
	if (targetDN.empty()) targetDN = domain.baseDN; // Domaenenwurzel gewaehlt

	FXString errorMsg;
	FXString identifier = (obj.type == OBJ_OU) ? relDNToFullDN(obj.dn, domain) : obj.accountName;
	if (!moveObject(obj.type, identifier, targetDN, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onRenameObject(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject obj = currentObjects[idx];
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts umbenannt werden."); return 1; }

	FXString newName = obj.name;
	if (!FXInputDialog::getString(newName, this, "Umbenennen", "Neuer Name für \"" + obj.name + "\":")) return 1;
	newName = newName.trim();
	if (newName.empty() || newName == obj.name) return 1;

	FXString errorMsg;
	FXString currentFullDN = relDNToFullDN(obj.dn, domain);
	if (!renameObject(this, domain, obj.type, obj.accountName, currentFullDN, newName, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onProperties(FXObject*, FXSelector, void*) {
	// propertiesFromList unterscheidet, ob der Rechtsklick im Baum
	// (Domänenwurzel/OU-Container) oder in der Liste (OU-Objekt) war --
	// ohne das wuerde hier faelschlich der zuletzt in der Liste
	// ausgewaehlte Eintrag herangezogen, auch wenn der Baum die
	// eigentliche Quelle war.
	FXString name, relDN;
	if (propertiesFromList) {
		int listIdx = list->getCurrentItem();
		if (listIdx < 0 || listIdx >= (int)currentObjects.size()) return 1;
		DirObject& obj = currentObjects[listIdx];
		name = obj.name;
		relDN = obj.dn;
	} else {
		FXTreeItem* cur = tree->getCurrentItem();
		if (!cur || !itemToRelDN.count(cur)) return 1;
		relDN = itemToRelDN[cur];
		FXString realmLower = domain.realm; realmLower.lower();
		name = relDN.empty() ? realmLower : dnLeafLabel(relDN);
	}
	getApp()->beginWaitCursor();
	OUPropertiesDialog dlg(this, domain, relDN, name);
	getApp()->endWaitCursor();
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DsAdminWindow::onGroupProperties(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject obj = currentObjects[idx];
	if (obj.type != OBJ_GROUP) return 1;
	getApp()->beginWaitCursor();
	GroupPropertiesDialog dlg(this, domain, obj);
	getApp()->endWaitCursor();
	dlg.execute(PLACEMENT_OWNER);
	// Auch nach "Abbrechen" neu laden -- "Übernehmen" kann vorher schon
	// geschrieben haben.
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onAdvancedView(FXObject*, FXSelector, void*) {
	g_advancedView = !g_advancedView;
	getApp()->reg().writeBoolEntry("Ansicht", "ErweiterteFunktionen", g_advancedView);
	getApp()->reg().write();   // sofort sichern, nicht erst beim Beenden
	FXString keep = currentContainerRelDN;
	loadTree();
	// Den zuletzt offenen Container wieder anwaehlen, sofern er in der
	// neuen Ansicht noch existiert -- sonst zur Domaenenwurzel.
	FXTreeItem* target = domainRootItem;
	for (auto& kv : itemToRelDN) if (kv.second == keep) { target = kv.first; break; }
	if (target) {
		tree->selectItem(target);
		tree->setCurrentItem(target);
		tree->makeItemVisible(target);
		showContainer(itemToRelDN[target]);
	}
	return 1;
}

long DsAdminWindow::onUpdAdvancedView(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, g_advancedView ? ID_CHECK : ID_UNCHECK), NULL);
	return 1;
}

void DsAdminWindow::fillNewMenu(FXMenuPane* pane) {
	// Reihenfolge wie im deutschen Original.
	new FXMenuCommand(pane, "&Computer", NULL, this, ID_NEW_COMPUTER);
	new FXMenuCommand(pane, "&Kontakt", NULL, this, ID_NEW_CONTACT);
	new FXMenuCommand(pane, "&Gruppe", NULL, this, ID_NEW_GROUP);
	new FXMenuCommand(pane, "&Organisationseinheit", NULL, this, ID_NEW_OU);
	new FXMenuCommand(pane, "&Benutzer", NULL, this, ID_NEW_USER);
	new FXMenuCommand(pane, "&Freigegebener Ordner", NULL, this, ID_NEW_SHARED_FOLDER);
}

void DsAdminWindow::selectContainer(const FXString& relDN) {
	for (auto& kv : itemToRelDN) {
		if (kv.second != relDN) continue;
		if (kv.first->getParent()) tree->expandTree(kv.first->getParent());
		tree->selectItem(kv.first);
		tree->setCurrentItem(kv.first);
		tree->makeItemVisible(kv.first);
		break;
	}
	showContainer(relDN);
}

long DsAdminWindow::onBack(FXObject*, FXSelector, void*) {
	if (historyPos <= 0) return 1;
	historyPos--;
	navigatingHistory = true;
	selectContainer(history[historyPos]);
	navigatingHistory = false;
	return 1;
}

long DsAdminWindow::onForward(FXObject*, FXSelector, void*) {
	if (historyPos + 1 >= (int)history.size()) return 1;
	historyPos++;
	navigatingHistory = true;
	selectContainer(history[historyPos]);
	navigatingHistory = false;
	return 1;
}

long DsAdminWindow::onUp(FXObject*, FXSelector, void*) {
	if (currentContainerRelDN.empty()) return 1;
	std::vector<std::string> parts = splitDnEscaped(currentContainerRelDN.text());
	std::string parent;
	for (size_t i = 1; i < parts.size(); i++) parent += (parent.empty() ? "" : ",") + parts[i];
	selectContainer(parent.c_str());
	return 1;
}

long DsAdminWindow::onUpdBack(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, historyPos > 0 ? ID_ENABLE : ID_DISABLE), NULL);
	return 1;
}
long DsAdminWindow::onUpdForward(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, historyPos + 1 < (int)history.size() ? ID_ENABLE : ID_DISABLE), NULL);
	return 1;
}
long DsAdminWindow::onUpdUp(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, (domain.isDC && !currentContainerRelDN.empty()) ? ID_ENABLE : ID_DISABLE), NULL);
	return 1;
}

long DsAdminWindow::onToggleTree(FXObject*, FXSelector, void*) {
	if (treeframe->shown()) treeframe->hide(); else treeframe->show();
	splitter->recalc();
	return 1;
}

int DsAdminWindow::selectedListIndex() const {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size() || !list->isItemSelected(idx)) return -1;
	return idx;
}

// "Eigenschaften" aus Werkzeugleiste/Vorgang: markiertes Objekt der Liste,
// sonst der geoeffnete Container.
long DsAdminWindow::onToolProperties(FXObject*, FXSelector, void*) {
	int idx = selectedListIndex();
	if (idx >= 0) {
		switch (currentObjects[idx].type) {
			case OBJ_USER: return onUserProperties(NULL, 0, NULL);
			case OBJ_GROUP: return onGroupProperties(NULL, 0, NULL);
			case OBJ_OU: propertiesFromList = true; return onProperties(NULL, 0, NULL);
			default: return 1;
		}
	}
	if (currentContainerRelDN.empty() || isOU(currentContainerRelDN)) {
		propertiesFromList = false;
		return onProperties(NULL, 0, NULL);
	}
	return 1;
}

long DsAdminWindow::onExportList(FXObject*, FXSelector, void*) {
	FXString file = FXFileDialog::getSaveFilename(this, "Liste exportieren", "Liste.txt",
	                                              "Text (Tabstopp-getrennt) (*.txt)\nText (kommagetrennt) (*.csv)\nAlle Dateien (*)");
	if (file.empty()) return 1;
	bool csv = FXPath::extension(file).lower() == "csv";
	auto field = [&](const FXString& v) -> std::string {
		std::string t = v.text();
		if (!csv) return t;
		std::string q = "\"";
		for (char c : t) { if (c == '"') q += '"'; q += c; }
		return q + "\"";
	};
	std::string sep = csv ? "," : "\t";
	std::string out = field("Name") + sep + field("Typ") + sep + field("Beschreibung") + "\r\n";
	for (FXint i = 0; i < list->getNumItems(); i++) {
		FXString t = list->getItemText(i);
		out += field(t.section('\t', 0)) + sep + field(t.section('\t', 1)) + sep + field(t.section('\t', 2)) + "\r\n";
	}
	FILE* f = fopen(file.text(), "wb");
	if (!f) { FXMessageBox::error(this, MBOX_OK, "Liste exportieren", "Die Datei %s konnte nicht geschrieben werden.", file.text()); return 1; }
	fwrite(out.data(), 1, out.size(), f);
	fclose(f);
	return 1;
}

long DsAdminWindow::onFind(FXObject*, FXSelector, void*) {
	if (!domain.isDC) return 1;
	FindObjectsDialog dlg(this, domain);
	dlg.execute(PLACEMENT_OWNER);
	onRefresh(NULL, 0, NULL);
	return 1;
}

long DsAdminWindow::onAddToGroup(FXObject*, FXSelector, void*) {
	int idx = selectedListIndex();
	if (idx < 0) return 1;
	DirObject obj = currentObjects[idx];
	std::string objDn = std::string((obj.dn + "," + domain.baseDN).text());
	getApp()->beginWaitCursor();
	std::vector<GroupEntry> groups;
	for (auto& c : listMemberCandidates(domain))
		if (c.icon == resico_users && lowerCopy(c.dn) != lowerCopy(objDn)) groups.push_back(c);
	getApp()->endWaitCursor();
	GroupPickerDialog dlg(this, domain.realm, groups, "Gruppen auswählen", resico_users);
	if (!dlg.execute(PLACEMENT_OWNER) || dlg.getResult().empty()) return 1;
	std::string ldif;
	for (int gi : dlg.getResult())
		ldif += "dn: " + groups[gi].dn + "\nchangetype: modify\nadd: member\n" + ldifAttrLine("member", objDn) + "-\n\n";
	std::string log;
	FXString errorMsg;
	if (!runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Active Directory", "%s", errorMsg.text());
		return 1;
	}
	FXMessageBox::information(this, MBOX_OK, "Active Directory", "Der Vorgang \"Zu Gruppe hinzufügen\" wurde erfolgreich abgeschlossen.");
	return 1;
}

long DsAdminWindow::onUpdAddToGroup(FXObject* sender, FXSelector, void*) {
	int idx = selectedListIndex();
	bool ok = idx >= 0 && (currentObjects[idx].type == OBJ_USER || currentObjects[idx].type == OBJ_GROUP ||
	                       currentObjects[idx].type == OBJ_COMPUTER);
	sender->handle(this, FXSEL(SEL_COMMAND, ok ? ID_ENABLE : ID_DISABLE), NULL);
	return 1;
}

long DsAdminWindow::onUpdSelObject(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, selectedListIndex() >= 0 ? ID_ENABLE : ID_DISABLE), NULL);
	return 1;
}

long DsAdminWindow::onNewContact(FXObject*, FXSelector, void*) {
	if (!domain.isDC) return 1;
	FXString container = currentContainerRelDN.empty() ? domain.baseDN : currentContainerRelDN + "," + domain.baseDN;
	NewContactDialog dlg(this, dnToFolder(("CN=x," + container).text()));
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	std::string cn = dlg.getFullName();
	if (cn.empty()) { FXMessageBox::error(this, MBOX_OK, "Neues Objekt - Kontakt", "Bitte einen vollständigen Namen angeben."); return 1; }
	std::string ldif = "dn: CN=" + rdnEscape(cn) + "," + std::string(container.text()) + "\nchangetype: add\nobjectClass: contact\n";
	if (!dlg.getGiven().empty()) ldif += ldifAttrLine("givenName", dlg.getGiven());
	if (!dlg.getInitials().empty()) ldif += ldifAttrLine("initials", dlg.getInitials());
	if (!dlg.getSurname().empty()) ldif += ldifAttrLine("sn", dlg.getSurname());
	if (!dlg.getDisplay().empty()) ldif += ldifAttrLine("displayName", dlg.getDisplay());
	std::string log;
	FXString errorMsg;
	if (!runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) { FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text()); return 1; }
	showContainer(currentContainerRelDN);
	return 1;
}

long DsAdminWindow::onNewSharedFolder(FXObject*, FXSelector, void*) {
	if (!domain.isDC) return 1;
	FXString container = currentContainerRelDN.empty() ? domain.baseDN : currentContainerRelDN + "," + domain.baseDN;
	NewSharedFolderDialog dlg(this, dnToFolder(("CN=x," + container).text()));
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	std::string name = dlg.getName(), unc = dlg.getUnc();
	if (name.empty() || unc.size() < 5 || unc.compare(0, 2, "\\\\") != 0) {
		FXMessageBox::error(this, MBOX_OK, "Neues Objekt - Freigegebener Ordner",
			"Bitte einen Namen und einen Netzwerkpfad der Form \\\\Server\\Freigabe angeben.");
		return 1;
	}
	std::string ldif = "dn: CN=" + rdnEscape(name) + "," + std::string(container.text()) +
	                   "\nchangetype: add\nobjectClass: volume\n" + ldifAttrLine("uNCName", unc);
	std::string log;
	FXString errorMsg;
	if (!runLdapChange(this, domain.realm, ldif, false, log, errorMsg)) { FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text()); return 1; }
	showContainer(currentContainerRelDN);
	return 1;
}

void DsAdminWindow::create() {
	FXMainWindow::create();
	show(PLACEMENT_SCREEN);
}

// ---------------------------------------------------------------------
// ADM-Vorlagen (Administrative Vorlagen fuer Gruppenrichtlinien) --
// Microsoft bietet diese fuer Windows 2000/XP/2003 kostenlos zum
// Download an: https://www.microsoft.com/en-us/download/details.aspx?id=18664
// ("Group Policy ADM Files"), Paket "2000admsetup.msi" enthaelt
// system.adm/inetres.adm/conf.adm/wmp.adm/wuau.adm fuer Windows 2000 SP4.
// Das .msi selbst ist ein Windows-Installer-Paket -- wir entpacken es
// unter Linux mit "msiextract" (aus dem Paket "msitools").
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Richtlinienzustand-Ableitung: bereits oben (vor den Dialog-Klassen)
// definiert, siehe PolicyState/RegLookup/determinePolicyState.
// ---------------------------------------------------------------------

int main(int argc, char* argv[]) {
	FXApp application("DsAdmin", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	DsAdminWindow* win = new DsAdminWindow(&application);
	application.create();
	win->show(PLACEMENT_SCREEN);

	if (!g_haveRoot) {
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\n"
			"Domänenobjekte können weiterhin angezeigt, aber nicht verändert werden.");
	} else if (!haveAdmFiles()) {
		if (FXMessageBox::question(win, MBOX_YES_NO, "ADM-Vorlagen nicht gefunden",
		        "Für den Gruppenrichtlinien-Editor werden die administrativen\n"
		        "Vorlagen (.adm-Dateien) von Windows 2000 benötigt.\n\n"
		        "Microsoft bietet diese kostenlos zum Download an. Jetzt\n"
		        "herunterladen und einrichten?") == MBOX_CLICKED_YES) {
			std::string log;
			FXString errorMsg;
			if (!downloadAndExtractAdmFiles(win, log, errorMsg)) {
				FXMessageBox::error(win, MBOX_OK, "Fehler", "%s\n\nProtokoll:\n%s", errorMsg.text(), log.c_str());
			} else {
				FXMessageBox::information(win, MBOX_OK, "Fertig", "ADM-Vorlagen wurden erfolgreich eingerichtet.");
			}
		}
	}

	return application.run();
}
