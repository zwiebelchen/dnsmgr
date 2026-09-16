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

// ---------------------------------------------------------------------
// Gruppenmitgliedschaft.
// ---------------------------------------------------------------------
static std::vector<FXString> listGroupMembers(const FXString& groupname) {
	return listNames({ FXString("samba-tool"), FXString("group"), FXString("listmembers"), groupname });
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
struct GpoInfo {
	FXString guid, displayName;
};

static std::vector<GpoInfo> listAllGpos() {
	std::vector<GpoInfo> out;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("listall") }, raw);
	GpoInfo cur;
	for (auto& l : splitLines(raw)) {
		if (l.rfind("GPO", 0) == 0) {
			size_t p = l.find(':');
			if (p != std::string::npos) cur.guid = trimStr(l.substr(p + 1)).c_str();
		} else if (l.rfind("display name", 0) == 0) {
			size_t p = l.find(':');
			if (p != std::string::npos) cur.displayName = trimStr(l.substr(p + 1)).c_str();
			out.push_back(cur);
			cur = GpoInfo();
		}
	}
	return out;
}

// Verknuepfte GPOs (in Verknuepfungsreihenfolge) fuer eine Domaene/OU (volle DN).
static std::vector<FXString> listLinkedGpoGuids(const FXString& fullDN) {
	std::vector<FXString> out;
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("getlink"), fullDN }, raw);
	for (auto& l : splitLines(raw)) {
		size_t p = l.find('{');
		size_t q = l.find('}');
		if (p != std::string::npos && q != std::string::npos && q > p) {
			out.push_back(FXString(l.substr(p, q - p + 1).c_str()));
		}
	}
	return out;
}

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

// Loescht das Gruppenrichtlinienobjekt selbst -- samt SYSVOL-Anteil und
// allen Verknuepfungen. Nicht zu verwechseln mit unlinkGpo(), das nur
// die Verknuepfung zu einem Container loest.
static bool deleteGpo(FXWindow* owner, const FXString& guid, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann kein GPO gelöscht werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("del"), guid, cred }, out);
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

// delta: -1 = eine Position nach oben, +1 = eine nach unten. Steht die
// Verknuepfung bereits am Rand, passiert nichts (kein Fehler).
static bool moveGpoLink(FXWindow* owner, const FXString& realm, const FXString& containerFullDN,
                        const FXString& guid, int delta, FXString& errorMsg) {
	std::string raw = readLdapAttribute(owner, realm, containerFullDN.text(), "gPLink");
	std::vector<std::string> blocks = parseGpLinkBlocks(raw);
	if (blocks.size() < 2) return true;

	std::string needle = lowerCopy(guid.text());
	int idx = -1;
	for (size_t i = 0; i < blocks.size(); i++)
		if (lowerCopy(blocks[i]).find(needle) != std::string::npos) { idx = (int)i; break; }
	if (idx < 0) { errorMsg = "Die Verknüpfung wurde im gPLink-Attribut nicht gefunden."; return false; }

	int target = idx + delta;
	if (target < 0 || target >= (int)blocks.size()) return true;
	std::swap(blocks[idx], blocks[target]);

	std::string joined;
	for (auto& b : blocks) joined += b;
	std::string ldif = "dn: " + std::string(containerFullDN.text()) + "\n"
	                    "changetype: modify\n"
	                    "replace: gPLink\n"
	                    "gPLink: " + joined + "\n";
	std::string log;
	return runLdapChange(owner, realm, ldif, false, log, errorMsg);
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

// Basis-DN aus dem Realm ableiten: LINUX.ZWIEBELCHEN.ORG ->
// DC=linux,DC=zwiebelchen,DC=org
static std::string baseDnFromRealm(const FXString& realm) {
	FXString lower = realm; lower.lower();
	std::string out;
	for (FXint i = 0; i <= lower.contains('.'); i++) {
		FXString part = lower.section('.', i);
		if (part.empty()) continue;
		if (!out.empty()) out += ",";
		out += "DC=" + std::string(part.text());
	}
	return out;
}

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

static bool registerExtensionOnly(FXWindow* owner, const FXString& realm, const std::string& gpoObjectDn, bool isMachine,
                                   const std::string& cseGuid, const std::string& toolGuid, std::string& log, FXString& errorMsg) {
	std::string attrName = isMachine ? "gPCMachineExtensionNames" : "gPCUserExtensionNames";
	std::string ourPair = std::string("[") + cseGuid + toolGuid + "]";

	std::string curVal = readLdapAttribute(owner, realm, gpoObjectDn, attrName);
	if (curVal.find(cseGuid) != std::string::npos) return true; // schon registriert

	std::string newVal = curVal + ourPair;
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

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer Gruppe -- Mitgliederliste mit
// Hinzufuegen/Entfernen (analog zu compmgmt, aber gegen die
// AD-Domaene statt gegen lokale Linux-Gruppen).
// ---------------------------------------------------------------------
class GroupMembersDialog : public FXDialogBox {
	FXDECLARE(GroupMembersDialog)
private:
	FXString groupname;
	FXList* memberList;
	FXTextField* addField;
public:
	enum { ID_ADDMEMBER = FXDialogBox::ID_LAST, ID_REMOVEMEMBER };
	void reloadList() {
		memberList->clearItems();
		for (auto& m : listGroupMembers(groupname)) memberList->appendItem(m);
	}
	long onAddMember(FXObject*, FXSelector, void*) {
		FXString name = addField->getText().trim();
		if (name.empty()) return 1;
		FXString errorMsg;
		if (!addGroupMember(this, groupname, name, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
			return 1;
		}
		addField->setText("");
		reloadList();
		return 1;
	}
	long onRemoveMember(FXObject*, FXSelector, void*) {
		int sel = memberList->getCurrentItem();
		if (sel < 0) return 1;
		FXString name = memberList->getItemText(sel);
		FXString errorMsg;
		if (!removeGroupMember(this, groupname, name, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
			return 1;
		}
		reloadList();
		return 1;
	}
protected:
	GroupMembersDialog() {}
public:
	GroupMembersDialog(FXWindow* owner, const FXString& groupName_)
		: FXDialogBox(owner, "Eigenschaften von " + groupName_, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,360,420),
		  groupname(groupName_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Mitglieder:");
		memberList = new FXList(main, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		FXHorizontalFrame* addf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		addField = new FXTextField(addf, 20, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXButton(addf, "&Hinzufügen", NULL, this, ID_ADDMEMBER, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(addf, "&Entfernen", NULL, this, ID_REMOVEMEMBER, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "Schließen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

		reloadList();
	}
	virtual ~GroupMembersDialog() {}
};
FXDEFMAP(GroupMembersDialog) GroupMembersDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, GroupMembersDialog::ID_ADDMEMBER, GroupMembersDialog::onAddMember),
	FXMAPFUNC(SEL_COMMAND, GroupMembersDialog::ID_REMOVEMEMBER, GroupMembersDialog::onRemoveMember),
};
FXIMPLEMENT(GroupMembersDialog, FXDialogBox, GroupMembersDialogMap, ARRAYNUMBER(GroupMembersDialogMap))

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

	GroupPickerDialog(FXWindow* owner, const FXString& realm, const std::vector<GroupEntry>& groups_)
		: FXDialogBox(owner, "Gruppen auswählen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,566,440),
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
		FXIcon* ic = sharedPngIcon(resico_users);
		for (auto& g : *groups) groupList->appendItem(g.cn + "\t" + g.folder, ic, ic);

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
					"Überprüfen Sie die Schreibweise, oder wählen Sie die Gruppe in der Liste aus.", n.text());
				return false;
			}
			if (idx == -2) {
				FXMessageBox::error(this, MBOX_OK, "Mehrere Namen gefunden",
					"Der Name \"%s\" passt auf mehrere Gruppen.\n\n"
					"Geben Sie den Namen genauer ein, oder wählen Sie die Gruppe in der Liste aus.", n.text());
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
		new FXButton(btnf, "Ü&bernehmen", NULL, this, ID_APPLY, bstyle, 0,0,88,0, 4,4,3,3);

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

class AdmEditorDialog : public FXDialogBox {
	FXDECLARE(AdmEditorDialog)
private:
	FXTreeList* tree;
	FXIconList* list;
	PolHive machineHive, userHive;
	std::string gptIniPath;
	std::string gpoObjectDn;   // fuer das Hochzaehlen von versionNumber in AD
	FXString realm;
	std::map<FXTreeItem*, std::tuple<AdmCategory*, std::vector<const AdmCategory*>, PolHive*>> itemInfo;
	std::vector<AdmPolicy*> currentPolicies;
	std::vector<std::string> currentEffectiveKeys;
	PolHive* currentHive = NULL;
	std::map<AdmPolicy*, PendingEdit> edits;
	std::map<AdmPolicy*, PolHive*> editHive; // welcher Zweig zu jedem Eintrag in "edits" gehoert
	FXIcon *icoFolder, *icoPolicy;
protected:
	AdmEditorDialog() {}
public:
	enum { ID_TREE = FXDialogBox::ID_LAST, ID_LIST, ID_SAVE, ID_SET_ENABLED, ID_SET_DISABLED, ID_SET_NOTCONF };

	void collectCategoryChildren(FXTreeItem* parentItem, std::vector<AdmCategory>& cats, std::vector<const AdmCategory*> chain, PolHive* hive) {
		for (auto& cat : cats) {
			FXTreeItem* item = tree->appendItem(parentItem, cat.label.c_str(), icoFolder, icoFolder);
			std::vector<const AdmCategory*> newChain = chain;
			newChain.push_back(&cat);
			itemInfo[item] = { &cat, newChain, hive };
			collectCategoryChildren(item, cat.subCategories, newChain, hive);
		}
	}

	const char* stateLabel(PolicyState st) {
		return st == POLSTATE_ENABLED ? "Aktiviert" : st == POLSTATE_DISABLED ? "Deaktiviert" : "Nicht konfiguriert";
	}

	// Liest den aktuell in der Registry.pol gespeicherten Wert eines Parts
	// (fuer die Anzeige beim Oeffnen des Bearbeiten-Dialogs).
	std::string readStoredPartValue(PolHive* hive, const std::string& key, const std::string& vn) {
		auto it = hive->lookup.values.find({ lowerCopy(key), lowerCopy(vn) });
		if (it == hive->lookup.values.end()) return "";
		if (it->second.type == REG_TYPE_DWORD && it->second.data.size() >= 4) {
			uint32_t v = (uint32_t)it->second.data[0] | ((uint32_t)it->second.data[1] << 8)
			           | ((uint32_t)it->second.data[2] << 16) | ((uint32_t)it->second.data[3] << 24);
			return std::to_string(v);
		} else if (it->second.type == REG_TYPE_SZ) {
			return std::string((const char*)it->second.data.data(), it->second.data.size());
		}
		return "";
	}

	void showCategoryPolicies(AdmCategory* cat, const std::vector<const AdmCategory*>& chain, PolHive* hive) {
		list->clearItems();
		currentPolicies.clear();
		currentEffectiveKeys.clear();
		currentHive = hive;
		for (auto& pol : cat->policies) {
			std::string key = resolveEffectiveKey(pol, chain);
			PolicyState st = edits.count(&pol) ? edits[&pol].state : determinePolicyState(pol, key, hive->lookup);
			FXString txt = FXString(pol.label.c_str()) + "\t" + stateLabel(st);
			list->appendItem(txt, icoPolicy, icoPolicy);
			currentPolicies.push_back(&pol);
			currentEffectiveKeys.push_back(key);
		}
	}

	long onTreeChanged(FXObject*, FXSelector, void*) {
		FXTreeItem* cur = tree->getCurrentItem();
		if (!cur || !itemInfo.count(cur)) return 1;
		auto& info = itemInfo[cur];
		showCategoryPolicies(std::get<0>(info), std::get<1>(info), std::get<2>(info));
		return 1;
	}

	long onListDoubleClick(FXObject*, FXSelector, void*) {
		int idx = list->getCurrentItem();
		if (idx < 0 || idx >= (int)currentPolicies.size()) return 1;
		AdmPolicy* pol = currentPolicies[idx];
		std::string key = currentEffectiveKeys[idx];
		PolHive* hive = currentHive;
		PolicyState curState = edits.count(pol) ? edits[pol].state : determinePolicyState(*pol, key, hive->lookup);
		std::vector<std::string> curPartValues;
		if (edits.count(pol)) {
			curPartValues = edits[pol].partValues;
		} else {
			for (auto& part : pol->parts) {
				std::string vn = !part.valuename.empty() ? part.valuename : pol->valuename;
				curPartValues.push_back(readStoredPartValue(hive, key, vn));
			}
		}

		PolicyEditDialog dlg(this, *pol, curState, curPartValues);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;

		PendingEdit ed;
		ed.state = dlg.getState();
		ed.partValues = dlg.getPartValues();
		ed.effectiveKey = key;
		edits[pol] = ed;
		editHive[pol] = hive;

		FXString txt = FXString(pol->label.c_str()) + "\t" + stateLabel(ed.state);
		list->setItemText(idx, txt);
		return 1;
	}

	// Setzt alle markierten Richtlinien der aktuellen Kategorie auf
	// denselben Status -- derselbe Weg wie beim Einzeldialog, nur eben
	// fuer mehrere Eintraege auf einmal. Gespeichert wird erst beim
	// Klick auf "Speichern".
	long onSetSelectionState(FXObject*, FXSelector sel, void*) {
		if (!currentHive) return 1;
		FXuint id = FXSELID(sel);
		PolicyState target = (id == ID_SET_ENABLED) ? POLSTATE_ENABLED
		                   : (id == ID_SET_DISABLED) ? POLSTATE_DISABLED
		                   : POLSTATE_NOT_CONFIGURED;

		int applied = 0, skipped = 0;
		int n = list->getNumItems();
		if (n > (int)currentPolicies.size()) n = (int)currentPolicies.size();
		for (int i = 0; i < n; i++) {
			if (!list->isItemSelected(i)) continue;
			AdmPolicy* pol = currentPolicies[i];
			// "Aktiviert" braucht bei Richtlinien mit Eingabefeldern
			// konkrete Werte -- die kann eine Sammelaktion nicht raten,
			// also bleiben die dem Einzeldialog vorbehalten.
			if (target == POLSTATE_ENABLED && !pol->parts.empty()) { skipped++; continue; }

			PendingEdit ed;
			ed.state = target;
			ed.effectiveKey = currentEffectiveKeys[i];
			if (edits.count(pol)) {
				ed.partValues = edits[pol].partValues;
			} else {
				for (auto& part : pol->parts) {
					std::string vn = !part.valuename.empty() ? part.valuename : pol->valuename;
					ed.partValues.push_back(readStoredPartValue(currentHive, ed.effectiveKey, vn));
				}
			}
			edits[pol] = ed;
			editHive[pol] = currentHive;
			list->setItemText(i, FXString(pol->label.c_str()) + "\t" + stateLabel(target));
			applied++;
		}

		if (applied == 0 && skipped == 0) {
			FXMessageBox::information(this, MBOX_OK, "Keine Auswahl",
				"Bitte zuerst eine oder mehrere Richtlinien in der Liste markieren.");
		} else if (skipped > 0) {
			char buf[320];
			snprintf(buf, sizeof(buf),
				"%d Richtlinie(n) auf \"Aktiviert\" gesetzt.\n\n"
				"%d Richtlinie(n) mit Eingabefeldern wurden übersprungen --\n"
				"diese bitte einzeln per Doppelklick aktivieren, damit die\n"
				"Werte gesetzt werden können.", applied, skipped);
			FXMessageBox::information(this, MBOX_OK, "Sammeländerung", "%s", buf);
		}
		return 1;
	}

	// Baut die finalen Eintraege eines Zweigs (Computer/Benutzer) aus
	// dessen Original-Registry.pol + allen Sitzungs-Aenderungen, die zu
	// diesem Zweig gehoeren.
	std::vector<RegPolEntry> buildFinalEntries(PolHive* hive) {
		std::vector<RegPolEntry> finalEntries = hive->file.entries;
		auto removeEntry = [&](const std::string& key, const std::string& valuename) {
			std::string lk = lowerCopy(key), lv = lowerCopy(valuename);
			finalEntries.erase(std::remove_if(finalEntries.begin(), finalEntries.end(), [&](const RegPolEntry& e) {
				return lowerCopy(e.key) == lk && lowerCopy(e.valuename) == lv;
			}), finalEntries.end());
		};

		for (auto& kv : edits) {
			AdmPolicy* pol = kv.first;
			if (editHive[pol] != hive) continue;
			PendingEdit& ed = kv.second;
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
				bool wasConfigured = hive->lookup.values.count({ lowerCopy(key), lowerCopy(vn) }) > 0;
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
		return finalEntries;
	}

	bool saveHive(PolHive* hive, std::string& errorMsg) {
		std::vector<RegPolEntry> finalEntries = buildFinalEntries(hive);
		FXString tmpPath = "/tmp/ice2k-regpol-tmp";
		if (!writeRegPolFile(tmpPath.text(), finalEntries, errorMsg)) return false;
		runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(hive->polPath.substr(0, hive->polPath.find_last_of('/')).c_str()) });
		int rc = runAsRoot({ FXString("cp"), tmpPath, FXString(hive->polPath.c_str()) });
		runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });
		if (rc != 0) { errorMsg = "Konnte " + hive->polPath + " nicht schreiben (Root-Rechte?)."; return false; }
		hive->file = parseRegPolFile(hive->polPath);
		hive->lookup = buildRegLookup(hive->file);
		return true;
	}

	long onSave(FXObject*, FXSelector, void*) {
		bool touchedMachine = false, touchedUser = false;
		for (auto& kv : editHive) {
			if (kv.second == &machineHive) touchedMachine = true;
			if (kv.second == &userHive) touchedUser = true;
		}
		if (!touchedMachine && !touchedUser) {
			FXMessageBox::information(this, MBOX_OK, "Nichts zu speichern", "Es wurden keine Richtlinien geändert.");
			return 1;
		}
		std::string errorMsg;
		if (touchedMachine && !saveHive(&machineHive, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.c_str());
			return 1;
		}
		if (touchedUser && !saveHive(&userHive, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.c_str());
			return 1;
		}
		std::string versionLog;
		bumpGpoVersion(this, realm, gpoObjectDn, touchedMachine, touchedUser, versionLog);

		edits.clear();
		editHive.clear();
		FXTreeItem* cur = tree->getCurrentItem();
		if (cur && itemInfo.count(cur)) {
			auto& info = itemInfo[cur];
			showCategoryPolicies(std::get<0>(info), std::get<1>(info), std::get<2>(info));
		}

		FXMessageBox::information(this, MBOX_OK, "Gespeichert", "Die Gruppenrichtlinie wurde gespeichert.");
		return 1;
	}

	AdmEditorDialog(FXWindow* owner, std::vector<AdmCategory>&& machineCats, std::vector<AdmCategory>&& userCats,
	                const std::string& machinePolPath, const std::string& userPolPath, const std::string& gptIniPath_,
	                const std::string& gpoObjectDn_, const FXString& realm_)
		: FXDialogBox(owner, "Gruppenrichtlinienobjekt-Editor", DECOR_ALL, 0,0,760,480),
		  gptIniPath(gptIniPath_), gpoObjectDn(gpoObjectDn_), realm(realm_) {
		machineHive.categories = std::move(machineCats);
		machineHive.polPath = machinePolPath;
		machineHive.file = parseRegPolFile(machinePolPath); // leer/fehlend ist okay -- noch keine Einstellungen
		machineHive.lookup = buildRegLookup(machineHive.file);

		userHive.categories = std::move(userCats);
		userHive.polPath = userPolPath;
		userHive.file = parseRegPolFile(userPolPath);
		userHive.lookup = buildRegLookup(userHive.file);

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
		FXSplitter* splitter = new FXSplitter(main, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
		FXPacker* treeframe = new FXPacker(splitter, FRAME_NORMAL | LAYOUT_FILL_Y, 0,0,280,0, 0,0,0,0);
		tree = new FXTreeList(treeframe, this, ID_TREE,
		                       SCROLLERS_DONT_TRACK | FRAME_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y |
		                       TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
		FXPacker* listframe = new FXPacker(splitter, FRAME_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		list = new FXIconList(listframe, this, ID_LIST,
		                       ICONLIST_DETAILED | ICONLIST_EXTENDEDSELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y | FRAME_NORMAL);
		list->appendHeader("Richtlinie", NULL, 400);
		list->appendHeader("Status", NULL, 160);

		icoFolder = new FXPNGIcon(getApp(), resico_folder, IMAGE_NEAREST); icoFolder->create();
		icoPolicy = new FXPNGIcon(getApp(), resico_key, IMAGE_NEAREST); icoPolicy->create();

		FXTreeItem* machineRoot = tree->appendItem(NULL, "Computerkonfiguration\\Administrative Vorlagen", icoFolder, icoFolder);
		collectCategoryChildren(machineRoot, machineHive.categories, {}, &machineHive);
		tree->expandTree(machineRoot);

		FXTreeItem* userRoot = tree->appendItem(NULL, "Benutzerkonfiguration\\Administrative Vorlagen", icoFolder, icoFolder);
		collectCategoryChildren(userRoot, userHive.categories, {}, &userHive);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 10,10,6,6);
		new FXLabel(btnf, "Auswahl setzen auf:");
		new FXButton(btnf, "&Aktiviert", NULL, this, ID_SET_ENABLED, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btnf, "&Deaktiviert", NULL, this, ID_SET_DISABLED, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btnf, "&Nicht konfiguriert", NULL, this, ID_SET_NOTCONF, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Speichern", NULL, this, ID_SAVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Schließen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	virtual ~AdmEditorDialog() {}
};
FXDEFMAP(AdmEditorDialog) AdmEditorDialogMap[] = {
	FXMAPFUNC(SEL_CHANGED, AdmEditorDialog::ID_TREE, AdmEditorDialog::onTreeChanged),
	FXMAPFUNC(SEL_DOUBLECLICKED, AdmEditorDialog::ID_LIST, AdmEditorDialog::onListDoubleClick),
	FXMAPFUNC(SEL_COMMAND, AdmEditorDialog::ID_SAVE, AdmEditorDialog::onSave),
	FXMAPFUNC(SEL_COMMAND, AdmEditorDialog::ID_SET_ENABLED, AdmEditorDialog::onSetSelectionState),
	FXMAPFUNC(SEL_COMMAND, AdmEditorDialog::ID_SET_DISABLED, AdmEditorDialog::onSetSelectionState),
	FXMAPFUNC(SEL_COMMAND, AdmEditorDialog::ID_SET_NOTCONF, AdmEditorDialog::onSetSelectionState),
};
FXIMPLEMENT(AdmEditorDialog, FXDialogBox, AdmEditorDialogMap, ARRAYNUMBER(AdmEditorDialogMap))

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

class PropertiesDialog : public FXDialogBox {
	FXDECLARE(PropertiesDialog)
private:
	FXString containerFullDN;
	FXString realm;
	FXList* gpoList;
	std::vector<FXString> linkedGuids;
	std::map<FXString, FXString> guidToName;
public:
	enum { ID_NEW_GPO = FXDialogBox::ID_LAST, ID_ADD_GPO, ID_REMOVE_GPO, ID_EDIT_GPO, ID_INSTALL_SOFTWARE, ID_SECURITY_SETTINGS, ID_SCRIPTS, ID_FOLDER_REDIR, ID_LINK_UP, ID_LINK_DOWN, ID_DELETE_GPO };
	long onNewGpo(FXObject*, FXSelector, void*);
	long onAddGpo(FXObject*, FXSelector, void*);
	long onRemoveGpo(FXObject*, FXSelector, void*);
	long onEditGpo(FXObject*, FXSelector, void*);
	long onInstallSoftware(FXObject*, FXSelector, void*);
	long onSecuritySettings(FXObject*, FXSelector, void*);
	long onScripts(FXObject*, FXSelector, void*);
	long onFolderRedirection(FXObject*, FXSelector, void*);
	long onDeleteGpo(FXObject*, FXSelector, void*);
	long onLinkUp(FXObject*, FXSelector, void*);
	long onLinkDown(FXObject*, FXSelector, void*);
	long moveSelectedLink(int delta);

	void reloadList() {
		gpoList->clearItems();
		linkedGuids = listLinkedGpoGuids(containerFullDN);
		auto allGpos = listAllGpos();
		guidToName.clear();
		for (auto& g : allGpos) guidToName[g.guid] = g.displayName;
		for (auto& guid : linkedGuids) {
			FXString label = guidToName.count(guid) ? guidToName[guid] : guid;
			gpoList->appendItem(label);
		}
	}
protected:
	PropertiesDialog() {}
public:
	PropertiesDialog(FXWindow* owner, const FXString& title, const FXString& fullDN, const FXString& realm_)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,580,420),
		  containerFullDN(fullDN), realm(realm_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);

		new FXTabItem(tabs, "Gruppenrichtlinie");
		FXVerticalFrame* gpoPage = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(gpoPage, "Aktuelle Gruppenrichtlinienobjekt-Verknüpfungen für\n" + title + ":");
		gpoList = new FXList(gpoPage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXHorizontalFrame* gpoBtns = new FXHorizontalFrame(gpoPage, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,2);
		new FXButton(gpoBtns, "&Neu", NULL, this, ID_NEW_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Hinzufügen...", NULL, this, ID_ADD_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Entfernen", NULL, this, ID_REMOVE_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Bearbeiten...", NULL, this, ID_EDIT_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Löschen...", NULL, this, ID_DELETE_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "Nach &oben", NULL, this, ID_LINK_UP, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "Nach &unten", NULL, this, ID_LINK_DOWN, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		FXHorizontalFrame* gpoBtns2 = new FXHorizontalFrame(gpoPage, LAYOUT_FILL_X, 0,0,0,0, 0,0,2,4);
		new FXButton(gpoBtns2, "&Software...", NULL, this, ID_INSTALL_SOFTWARE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns2, "S&icherheit...", NULL, this, ID_SECURITY_SETTINGS, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns2, "S&kripte...", NULL, this, ID_SCRIPTS, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns2, "Or&dnerumleitung...", NULL, this, ID_FOLDER_REDIR, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "Schließen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

		reloadList();
	}
	virtual ~PropertiesDialog() {}
};
FXDEFMAP(PropertiesDialog) PropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_NEW_GPO, PropertiesDialog::onNewGpo),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_ADD_GPO, PropertiesDialog::onAddGpo),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_REMOVE_GPO, PropertiesDialog::onRemoveGpo),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_EDIT_GPO, PropertiesDialog::onEditGpo),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_INSTALL_SOFTWARE, PropertiesDialog::onInstallSoftware),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_SECURITY_SETTINGS, PropertiesDialog::onSecuritySettings),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_SCRIPTS, PropertiesDialog::onScripts),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_FOLDER_REDIR, PropertiesDialog::onFolderRedirection),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_DELETE_GPO, PropertiesDialog::onDeleteGpo),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_LINK_UP, PropertiesDialog::onLinkUp),
	FXMAPFUNC(SEL_COMMAND, PropertiesDialog::ID_LINK_DOWN, PropertiesDialog::onLinkDown),
};
FXIMPLEMENT(PropertiesDialog, FXDialogBox, PropertiesDialogMap, ARRAYNUMBER(PropertiesDialogMap))

long PropertiesDialog::onNewGpo(FXObject*, FXSelector, void*) {
	FXString name;
	if (FXInputDialog::getString(name, this, "Neues Gruppenrichtlinienobjekt", "Name des neuen GPO:") ) {
		if (name.trim().empty()) return 1;
		FXString errorMsg;
		if (!createGpo(this, name, errorMsg)) {
			// Haeufigster Fall: unter dem Namen gibt es schon ein GPO.
			// Das passiert regelmaessig, weil "Entfernen" im
			// Gruppenrichtlinie-Reiter nur die Verknuepfung loest -- das
			// GPO selbst bleibt bestehen. Statt der Rohmeldung anbieten,
			// das vorhandene zu verknuepfen.
			if (errorMsg.find("already existing with name") >= 0) {
				FXString existingGuid;
				for (auto& g : listAllGpos()) if (g.displayName == name) existingGuid = g.guid;
				if (!existingGuid.empty()) {
					if (FXMessageBox::question(this, MBOX_YES_NO, "Name bereits vergeben",
						"Es gibt bereits ein Gruppenrichtlinienobjekt mit dem Namen\n\"%s\".\n\n"
						"Beim Entfernen wird nur die Verknüpfung gelöst, das Objekt\nselbst bleibt bestehen.\n\n"
						"Soll das vorhandene Objekt mit diesem Container verknüpft werden?",
						name.text()) == MBOX_CLICKED_YES) {
						if (!linkGpo(this, existingGuid, containerFullDN, errorMsg))
							FXMessageBox::error(this, MBOX_OK, "Verknüpfen fehlgeschlagen", "%s", errorMsg.text());
						reloadList();
					}
					return 1;
				}
			}
			FXMessageBox::error(this, MBOX_OK, "Anlegen fehlgeschlagen", "%s", errorMsg.text());
			return 1;
		}
		auto all = listAllGpos();
		FXString guid;
		for (auto& g : all) if (g.displayName == name) guid = g.guid;
		if (!guid.empty() && !linkGpo(this, guid, containerFullDN, errorMsg))
			FXMessageBox::error(this, MBOX_OK, "Verknüpfen fehlgeschlagen", "%s", errorMsg.text());
		reloadList();
	}
	return 1;
}

long PropertiesDialog::onAddGpo(FXObject*, FXSelector, void*) {
	auto all = listAllGpos();
	FXString choices;
	std::vector<FXString> guids;
	for (auto& g : all) {
		if (std::find(linkedGuids.begin(), linkedGuids.end(), g.guid) != linkedGuids.end()) continue;
		if (!choices.empty()) choices += "\n";
		choices += g.displayName;
		guids.push_back(g.guid);
	}
	if (guids.empty()) {
		FXMessageBox::information(this, MBOX_OK, "Hinzufügen", "Es gibt keine weiteren, noch nicht verknüpften Gruppenrichtlinienobjekte.");
		return 1;
	}
	FXint sel = FXMessageBox::information(this, MBOX_YES_NO, "GPO verknüpfen", "%s\n\nDas erste in der Liste jetzt verknüpfen?", choices.text());
	if (sel == MBOX_CLICKED_YES) {
		FXString errorMsg;
		linkGpo(this, guids[0], containerFullDN, errorMsg);
		reloadList();
	}
	return 1;
}

long PropertiesDialog::onRemoveGpo(FXObject*, FXSelector, void*) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) return 1;
	FXString guid = linkedGuids[idx];
	FXString name = guidToName.count(guid) ? guidToName[guid] : guid;

	// Wie im Original nachfragen, was gemeint ist. Ohne die Frage loest
	// "Entfernen" nur die Verknuepfung, das Objekt bleibt bestehen --
	// und beim naechsten Anlegen unter demselben Namen scheitert man an
	// "A GPO already existing with name". Vorgabe ist, ebenfalls wie im
	// Original, das blosse Loesen der Verknuepfung.
	FXDialogBox dlg(this, "Gruppenrichtlinienobjekt entfernen",
	                 DECOR_TITLE | DECOR_BORDER, 0,0,0,0, 10,10,10,10);
	FXVerticalFrame* main = new FXVerticalFrame(&dlg, LAYOUT_FILL_X | LAYOUT_FILL_Y);
	new FXLabel(main, FXString("Was soll mit \"") + name + "\" geschehen?", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
	new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);

	FXint choice = 0;
	FXDataTarget target(choice);
	new FXRadioButton(main, "Die &Verknüpfung aus der Liste entfernen",
	                   &target, FXDataTarget::ID_OPTION + 0);
	new FXRadioButton(main, "Die Verknüpfung entfernen und das Gruppenrichtlinienobjekt\n&dauerhaft löschen",
	                   &target, FXDataTarget::ID_OPTION + 1);

	FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
	new FXFrame(btns, LAYOUT_FILL_X);
	new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT,
	              BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL,
	              BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	FXString errorMsg;
	if (!unlinkGpo(this, guid, containerFullDN, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Entfernen fehlgeschlagen", "%s", errorMsg.text());
		return 1;
	}

	if (choice == 1) {
		if (FXMessageBox::question(this, MBOX_YES_NO, "Dauerhaft löschen",
			"\"%s\" wird endgültig gelöscht -- mit allen Einstellungen und\n"
			"allen Verknüpfungen zu anderen Containern.\n\nFortfahren?",
			name.text()) != MBOX_CLICKED_YES) {
			reloadList();
			return 1;
		}
		if (!deleteGpo(this, guid, errorMsg))
			FXMessageBox::error(this, MBOX_OK, "Löschen fehlgeschlagen", "%s", errorMsg.text());
	}
	reloadList();
	return 1;
}

// Verschiebt die markierte Verknuepfung um eine Position und laesst sie
// danach markiert, damit sich mehrere Schritte hintereinander klicken
// lassen.
long PropertiesDialog::moveSelectedLink(int delta) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) return 1;
	int target = idx + delta;
	if (target < 0 || target >= (int)linkedGuids.size()) return 1;

	FXString errorMsg;
	if (!moveGpoLink(this, realm, containerFullDN, linkedGuids[idx], delta, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Reihenfolge ändern fehlgeschlagen", "%s", errorMsg.text());
		return 1;
	}
	reloadList();
	if (target < gpoList->getNumItems()) {
		gpoList->setCurrentItem(target);
		gpoList->selectItem(target);
	}
	return 1;
}

long PropertiesDialog::onDeleteGpo(FXObject*, FXSelector, void*) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) return 1;
	FXString guid = linkedGuids[idx];
	FXString name = guidToName.count(guid) ? guidToName[guid] : guid;

	// Deutlich vom blossen "Entfernen" abgrenzen: das hier ist endgueltig
	// und betrifft auch alle anderen Container, die das GPO verknuepft
	// haben.
	if (FXMessageBox::warning(this, MBOX_YES_NO, "Gruppenrichtlinienobjekt löschen",
		"\"%s\" wird vollständig gelöscht -- das Objekt in Active Directory\n"
		"und sein Verzeichnis im SYSVOL, mit allen Einstellungen darin.\n\n"
		"Das wirkt sich auch auf alle anderen Container aus, die dieses\n"
		"Objekt verknüpft haben. Soll nur die Verknüpfung hier entfernt\n"
		"werden, ist \"Entfernen\" die richtige Schaltfläche.\n\n"
		"Endgültig löschen?", name.text()) != MBOX_CLICKED_YES) return 1;

	// Erst die Verknuepfung hier loesen, dann loeschen -- sonst bleibt in
	// gPLink ein Verweis auf ein Objekt stehen, das es nicht mehr gibt.
	FXString errorMsg;
	unlinkGpo(this, guid, containerFullDN, errorMsg);

	if (!deleteGpoCompletely(this, guid, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Löschen fehlgeschlagen", "%s", errorMsg.text());
		return 1;
	}
	reloadList();
	return 1;
}

long PropertiesDialog::onLinkUp(FXObject*, FXSelector, void*) { return moveSelectedLink(-1); }
long PropertiesDialog::onLinkDown(FXObject*, FXSelector, void*) { return moveSelectedLink(+1); }

long PropertiesDialog::onEditGpo(FXObject*, FXSelector, void*) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) return 1;
	if (!haveAdmFiles()) {
		FXMessageBox::error(this, MBOX_OK, "ADM-Vorlagen fehlen",
			"Es sind keine administrativen Vorlagen (.adm-Dateien) eingerichtet.\n"
			"Bitte starte das Programm neu und lade sie herunter.");
		return 1;
	}
	FXString guid = linkedGuids[idx];
	FXString realmLower = realm; realmLower.lower();
	std::string sysvolBase = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + guid.text();
	std::string machinePolPath = sysvolBase + "/" + SYSVOL_MACHINE_DIR + "/Registry.pol";
	std::string userPolPath = sysvolBase + "/" + SYSVOL_USER_DIR + "/Registry.pol";
	std::string gptIniPath = sysvolBase + "/GPT.INI";

	std::vector<AdmCategory> machineCats = loadMergedAdmCategories("MACHINE");
	std::vector<AdmCategory> userCats = loadMergedAdmCategories("USER");
	if (machineCats.empty() && userCats.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "Keine Kategorien aus den ADM-Dateien geladen (Parserfehler oder leeres ADM-Verzeichnis?).");
		return 1;
	}
	std::string gpoObjectDn = "CN=" + std::string(guid.text()) + ",CN=Policies,CN=System," + baseDnFromRealm(realm);
	AdmEditorDialog dlg(this, std::move(machineCats), std::move(userCats), machinePolPath, userPolPath, gptIniPath,
	                     gpoObjectDn, realm);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long PropertiesDialog::onInstallSoftware(FXObject*, FXSelector, void*) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) {
		FXMessageBox::information(this, MBOX_OK, "Kein GPO ausgewählt", "Bitte zuerst ein Gruppenrichtlinienobjekt aus der Liste auswählen.");
		return 1;
	}
	FXString guid = linkedGuids[idx];
	DomainInfo domain = detectDomain();
	if (domain.realm.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "Domäne konnte nicht ermittelt werden.");
		return 1;
	}
	SoftwarePackageListDialog dlg(this, domain, guid);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long PropertiesDialog::onSecuritySettings(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können die Sicherheitseinstellungen nicht geändert werden.");
		return 1;
	}
	PasswordPolicy current = getPasswordPolicy();
	SecuritySettingsDialog dlg(this, current);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!setPasswordPolicy(dlg.getPolicy(), errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		return 1;
	}
	FXMessageBox::information(this, MBOX_OK, "Fertig",
		"Die Kennwort- und Kontosperrungsrichtlinie wurde aktualisiert.\n\n"
		"Hinweis: Diese Einstellungen gelten domänenweit (wie unter\n"
		"Windows 2000/2003) und werden über die Default Domain Policy\n"
		"durchgesetzt, unabhängig davon, welches GPO gerade geöffnet ist.");
	return 1;
}

long PropertiesDialog::onScripts(FXObject*, FXSelector, void*) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) {
		FXMessageBox::information(this, MBOX_OK, "Kein GPO ausgewählt", "Bitte zuerst ein Gruppenrichtlinienobjekt aus der Liste auswählen.");
		return 1;
	}
	FXString guid = linkedGuids[idx];
	DomainInfo domain = detectDomain();
	if (domain.realm.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "Domäne konnte nicht ermittelt werden.");
		return 1;
	}
	ScriptsDialog dlg(this, domain, guid);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long PropertiesDialog::onFolderRedirection(FXObject*, FXSelector, void*) {
	int idx = gpoList->getCurrentItem();
	if (idx < 0 || idx >= (int)linkedGuids.size()) {
		FXMessageBox::information(this, MBOX_OK, "Kein GPO ausgewählt", "Bitte zuerst ein Gruppenrichtlinienobjekt aus der Liste auswählen.");
		return 1;
	}
	FXString guid = linkedGuids[idx];
	DomainInfo domain = detectDomain();
	if (domain.realm.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "Domäne konnte nicht ermittelt werden.");
		return 1;
	}
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann die Ordnerumleitung nicht geändert werden.");
		return 1;
	}
	FXString realmLower = domain.realm; realmLower.lower();
	std::string userPolPath = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + std::string(guid.text()) + "/" + SYSVOL_USER_DIR + "/Registry.pol";
	auto current = getFolderRedirectionPaths(userPolPath);
	FolderRedirectionDialog dlg(this, current);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!setFolderRedirectionPaths(this, domain, guid, dlg.getPaths(), errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		return 1;
	}
	FXMessageBox::information(this, MBOX_OK, "Gespeichert", "Die Ordnerumleitung wurde gespeichert.");
	return 1;
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
		ID_USER_PROPS, ID_MOVE_OBJECT, ID_RENAME_OBJECT, ID_RESET_PASSWORD, ID_ADVANCED_VIEW
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
	new FXMenuCommand(vorgangmenu, "&Aktualisieren", NULL, this, ID_REFRESH);
	ansichtmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Ansicht", NULL, ansichtmenu);
	new FXMenuCheck(ansichtmenu, "&Erweiterte Funktionen", this, ID_ADVANCED_VIEW);
	hilfemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&?", NULL, hilfemenu);
	new FXMenuCommand(hilfemenu, "&Info...", NULL, this, ID_ABOUT);

	toolbar = new FXToolBar(main, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
	FXGIFIcon* icoRefresh = new FXGIFIcon(getApp(), resico_mmc_refresh);
	new FXButton(toolbar, "\tAktualisieren", icoRefresh, this, ID_REFRESH, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);

	splitter = new FXSplitter(main, LAYOUT_FILL_X|LAYOUT_FILL_Y|SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y, 0,0,260,0, 0,0,0,0);
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
			default: typeName = obj.objectClass.empty() ? "Objekt" : obj.objectClass.text(); ic = icoFolder; break;
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
	new FXMenuCommand(&neuMenu, "&Benutzer...", NULL, this, ID_NEW_USER);
	new FXMenuCommand(&neuMenu, "&Gruppe...", NULL, this, ID_NEW_GROUP);
	new FXMenuCommand(&neuMenu, "&Organisationseinheit...", NULL, this, ID_NEW_OU);
	new FXMenuCommand(&neuMenu, "&Computer...", NULL, this, ID_NEW_COMPUTER);
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
	FXString title, fullDN;
	if (propertiesFromList) {
		int listIdx = list->getCurrentItem();
		if (listIdx < 0 || listIdx >= (int)currentObjects.size()) return 1;
		DirObject& obj = currentObjects[listIdx];
		title = obj.name;
		fullDN = relDNToFullDN(obj.dn, domain);
	} else {
		FXTreeItem* cur = tree->getCurrentItem();
		if (!cur || !itemToRelDN.count(cur)) return 1;
		FXString relDN = itemToRelDN[cur];
		title = relDN.empty() ? domain.realm : relDN;
		fullDN = relDNToFullDN(relDN, domain);
	}
	PropertiesDialog dlg(this, title, fullDN, domain.realm);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DsAdminWindow::onGroupProperties(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)currentObjects.size()) return 1;
	DirObject& obj = currentObjects[idx];
	if (obj.type != OBJ_GROUP) return 1;
	GroupMembersDialog dlg(this, obj.accountName);
	dlg.execute(PLACEMENT_OWNER);
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
