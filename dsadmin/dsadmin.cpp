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
};

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
static bool createUser(const FXString& username, const FXString& password, const FXString& fullName,
                        const FXString& ouRelDN, FXString& errorMsg) {
	std::vector<FXString> args = { FXString("samba-tool"), FXString("user"), FXString("create"), username, password };
	if (!fullName.empty()) { args.push_back(FXString("--given-name=") + fullName); }
	if (!ouRelDN.empty()) { args.push_back(FXString("--userou=") + ouRelDN); }
	std::string out;
	int rc = runAsRootCaptured(args, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool deleteUser(const FXString& username, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("delete"), username }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool createGroup(const FXString& groupname, const FXString& ouRelDN, FXString& errorMsg) {
	std::vector<FXString> args = { FXString("samba-tool"), FXString("group"), FXString("add"), groupname };
	if (!ouRelDN.empty()) args.push_back(FXString("--groupou=") + ouRelDN);
	std::string out;
	int rc = runAsRootCaptured(args, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool deleteGroup(const FXString& groupname, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("delete"), groupname }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool deleteOU(const FXString& ouDN, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("delete"), ouDN }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
		if (cred.empty()) { errorMsg = out.c_str(); return false; }
		out.clear();
		rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("addmembers"), groupname, member, cred }, out);
		if (rc != 0) { errorMsg = out.c_str(); return false; }
	}
	return true;
}

static bool removeGroupMember(FXWindow* owner, const FXString& groupname, const FXString& member, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("removemembers"), groupname, member }, out);
	if (rc != 0) {
		FXString cred = ensureAdminCreds(owner);
		if (cred.empty()) { errorMsg = out.c_str(); return false; }
		out.clear();
		rc = runAsRootCaptured({ FXString("samba-tool"), FXString("group"), FXString("removemembers"), groupname, member, cred }, out);
		if (rc != 0) { errorMsg = out.c_str(); return false; }
	}
	return true;
}

static bool createGpo(FXWindow* owner, const FXString& displayName, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann kein GPO angelegt werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("create"), displayName, cred }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool linkGpo(FXWindow* owner, const FXString& guid, const FXString& containerFullDN, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann kein GPO verknüpft werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("setlink"), containerFullDN, guid, cred }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool unlinkGpo(FXWindow* owner, const FXString& guid, const FXString& containerFullDN, FXString& errorMsg) {
	FXString cred = ensureAdminCreds(owner);
	if (cred.empty()) { errorMsg = "Ohne Administrator-Anmeldedaten kann die Verknüpfung nicht entfernt werden."; return false; }
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("gpo"), FXString("dellink"), containerFullDN, guid, cred }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
		errorMsg = "LDAP-Änderung fehlgeschlagen (siehe Protokoll).";
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
	std::string userScopeDir = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + std::string(gpoGuid.text()) + "/USER";
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
	std::string ldif1 = "dn: " + classStoreDn + "\n"
	                     "changetype: add\n"
	                     "objectClass: classStore\n"
	                     "description: Application Store\n";
	if (!runLdapChange(owner, realm, ldif1, true, log, errorMsg)) return false;

	std::string packagesDn = "CN=Packages," + classStoreDn;
	std::string ldif2 = "dn: " + packagesDn + "\n"
	                     "changetype: add\n"
	                     "objectClass: classStore\n"
	                     "description: Application Packages\n";
	if (!runLdapChange(owner, realm, ldif2, true, log, errorMsg)) return false;
	return true;
}

// Aktualisiert den Zeitstempel von "CN=Class Store", damit andere
// Clients/Werkzeuge den Container als gueltig ansehen.
static bool bumpClassStoreConfirmation(FXWindow* owner, const FXString& realm, const std::string& classStoreDn, std::string& log, FXString& errorMsg) {
	std::string ldif = "dn: " + classStoreDn + "\n"
	                    "changetype: modify\n"
	                    "replace: lastUpdateSequence\n"
	                    "lastUpdateSequence: " + std::to_string((long long)time(NULL)) + "\n-\n"
	                    "replace: displayName\n"
	                    "displayName: Application Store\n";
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

struct SoftwarePackageParams {
	std::string localMsiPath;   // lokal lesbarer Pfad zur .msi (fuer msiinfo)
	std::string msiUncPath;     // vollstaendiger UNC-Pfad, wie ein Client ihn erreicht
	bool assignedPerMachine;    // true = Computerkonfiguration, false = Benutzerkonfiguration
	bool published;             // nur relevant fuer Benutzerkonfiguration (assignedPerMachine=false)
};

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
	info.packageCodeGuid = generateNewGuidUpper(); // eigener Package Code fuer diese Bereitstellung
	info.versionString = props.count("ProductVersion") ? props["ProductVersion"] : "1.0.0";
	info.msiUncPath = params.msiUncPath;
	info.assignedPerMachine = params.assignedPerMachine;
	info.langId = 1031;

	std::string packageGuid = generateNewGuidUpper();
	FXString realmLower = domain.realm; realmLower.lower();
	std::string scope = params.assignedPerMachine ? "Machine" : "User";
	std::string scopedGpoDn = "CN=" + scope + ",CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string gpoObjectDn = "CN=" + std::string(gpoGuid.text()) + ",CN=Policies,CN=System," + domain.baseDN.text();
	std::string classStoreDn = "CN=Class Store," + scopedGpoDn;
	std::string packagesDn = "CN=Packages," + classStoreDn;
	std::string packageDn = "CN=" + packageGuid + "," + packagesDn;

	if (!ensureClassStoreAndPackages(owner, domain.realm, scopedGpoDn, log, errorMsg)) return false;

	// .aas-Datei schreiben -- lokal, dann als root nach SYSVOL kopieren.
	std::string sysvolScopeDir = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" +
	                              std::string(gpoGuid.text()) + "/" + (params.assignedPerMachine ? "MACHINE" : "USER");
	std::string appsDir = sysvolScopeDir + "/Applications";
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(appsDir.c_str()) });
	std::string aasLocalTmp = "/tmp/ice2k-package.aas";
	std::string aasErrorMsg;
	if (!writeAasFile(aasLocalTmp, info, aasErrorMsg)) { errorMsg = aasErrorMsg.c_str(); return false; }
	std::string aasDestPath = appsDir + "/" + packageGuid + ".aas";
	int rc = runAsRoot({ FXString("cp"), FXString(aasLocalTmp.c_str()), FXString(aasDestPath.c_str()) });
	runAsRoot({ FXString("rm"), FXString("-f"), FXString(aasLocalTmp.c_str()) });
	if (rc != 0) { errorMsg = "Konnte .aas-Datei nicht nach SYSVOL kopieren."; return false; }

	// UNC-Pfad zur .aas-Datei fuer das msiScriptPath-Attribut.
	std::string msiScriptPath = "\\\\" + std::string(realmLower.text()) + "\\sysvol\\" + std::string(realmLower.text()) +
	                             "\\Policies\\" + std::string(gpoGuid.text()) + "\\" + scope + "\\Applications\\" + packageGuid + ".aas";

	std::string msiScriptName = params.assignedPerMachine ? "A" : (params.published ? "P" : "A");
	// packageFlags: Bit 0x10 MUSS immer gesetzt sein; dazu Assigned (0x800)
	// oder Published (0x8), je nach Bereitstellungsart.
	uint32_t packageFlags = 0x10;
	if (!params.assignedPerMachine && params.published) packageFlags |= 0x8; // ACTFLG_Published
	else packageFlags |= 0x800; // ACTFLG_Assigned

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
	                    "versionNumberHi: 0\n"
	                    "versionNumberLo: 0\n"
	                    "revision: 1\n"
	                    "localeID: " + std::to_string(info.langId) + "\n"
	                    "machineArchitecture: 0\n";
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
			"' -w '" + g_adminPass + "' -b '" + packagesDn.c_str() + "' -s one '(objectClass=packageRegistration)' cn displayName packageFlags msiScriptPath 2>/dev/null"
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
			uint32_t flags = 0;
			try { flags = (uint32_t)std::stoul(line.substr(14)); } catch (...) {}
			cur.assigned = (flags & 0x800) != 0;
			cur.published = (flags & 0x8) != 0;
			continue;
		}
	}
	flush();
	return out;
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
	                       std::string(gpoGuid.text()) + "/" + (isMachine ? "MACHINE" : "USER") +
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

static bool setUserAttributes(FXWindow* owner, const FXString& realm, const FXString& userFullDN,
                               const FXString& displayName, const FXString& description, FXString& errorMsg) {
	std::string ldif = "dn: " + std::string(userFullDN.text()) + "\n"
	                    "changetype: modify\n"
	                    "replace: displayName\n"
	                    "displayName: " + std::string(displayName.text()) + "\n-\n"
	                    "replace: description\n"
	                    "description: " + std::string(description.text()) + "\n";
	std::string log;
	return runLdapChange(owner, realm, ldif, false, log, errorMsg);
}

static bool setUserEnabled(const FXString& username, bool enabled, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString(enabled ? "enable" : "disable"), username }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool setUserPassword(const FXString& username, const FXString& password, FXString& errorMsg) {
	std::string input = std::string(password.text()) + "\n" + password.text() + "\n";
	std::string out;
	int rc = runAsRootCapturedWithStdin({ FXString("samba-tool"), FXString("user"), FXString("setpassword"), username }, input, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
	if (rc != 0) { errorMsg = out.c_str(); return false; }
	return true;
}

static bool deleteComputer(const FXString& name, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("computer"), FXString("delete"), name }, out);
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
			if (rc != 0) { errorMsg = out.c_str(); return false; }
			return true;
		}
		case OBJ_OU: {
			int comma = currentFullDN.find(',');
			if (comma < 0) { errorMsg = "Konnte übergeordneten Container nicht bestimmen."; return false; }
			FXString parentPart = currentFullDN.mid(comma + 1, currentFullDN.length() - comma - 1);
			FXString newFullDN = "OU=" + newName + "," + parentPart;
			std::string out;
			int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("ou"), FXString("rename"), currentFullDN, newFullDN }, out);
			if (rc != 0) { errorMsg = out.c_str(); return false; }
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
	if (rc != 0) { errorMsg = out.c_str(); return false; }
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
// Dialog "Eigenschaften" eines Benutzers -- Anzeigename/Beschreibung,
// Konto ist deaktiviert, sowie ein "Kennwort zurücksetzen..."-Knopf.
// ---------------------------------------------------------------------
class UserPropertiesDialog : public FXDialogBox {
	FXDECLARE(UserPropertiesDialog)
private:
	FXTextField *displayNameField, *descriptionField;
	FXCheckButton* disabledCheck;
	FXString username;
protected:
	UserPropertiesDialog() {}
public:
	enum { ID_RESET_PW = FXDialogBox::ID_LAST };
	long onResetPassword(FXObject*, FXSelector, void*) {
		SetPasswordDialog dlg(this, username);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		FXString pw = dlg.getPassword(), confirm = dlg.getConfirm();
		if (pw.empty()) { FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte ein Kennwort eingeben."); return 1; }
		if (pw != confirm) { FXMessageBox::error(this, MBOX_OK, "Fehler", "Die Kennwörter stimmen nicht überein."); return 1; }
		FXString errorMsg;
		if (setUserPassword(username, pw, errorMsg)) {
			FXMessageBox::information(this, MBOX_OK, "Fertig", "Das Kennwort wurde geändert.");
		} else {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		}
		return 1;
	}

	UserPropertiesDialog(FXWindow* owner, const FXString& username_, const FXString& displayName, const FXString& description, bool disabled)
		: FXDialogBox(owner, "Eigenschaften von " + username_, DECOR_TITLE | DECOR_BORDER, 0,0,420,0),
		  username(username_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Anmeldename: " + username_);
		new FXLabel(main, "Anzeigename:");
		displayNameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		displayNameField->setText(displayName);
		new FXLabel(main, "Beschreibung:");
		descriptionField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		descriptionField->setText(description);
		disabledCheck = new FXCheckButton(main, "Konto ist deaktiviert");
		disabledCheck->setCheck(disabled);

		FXHorizontalFrame* pwf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXButton(pwf, "&Kennwort zurücksetzen...", NULL, this, ID_RESET_PW, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getDisplayName() const { return displayNameField->getText(); }
	FXString getDescription() const { return descriptionField->getText(); }
	bool getDisabled() const { return disabledCheck->getCheck(); }
	virtual ~UserPropertiesDialog() {}
};
FXDEFMAP(UserPropertiesDialog) UserPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, UserPropertiesDialog::ID_RESET_PW, UserPropertiesDialog::onResetPassword),
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
		for (auto& p : machinePkgs) machineList->appendItem((p.displayName + " (Zugewiesen)").c_str());

		userList->clearItems();
		userPkgs = listSoftwarePackages(credOwner, domain, gpoGuid, false);
		for (auto& p : userPkgs) userList->appendItem((p.displayName + (p.published ? " (Veröffentlicht)" : " (Zugewiesen)")).c_str());
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

	long onRemoveMachine(FXObject*, FXSelector, void*) {
		int idx = machineList->getCurrentItem();
		if (idx < 0 || idx >= (int)machinePkgs.size()) return 1;
		if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen", "\"%s\" wirklich entfernen?", machinePkgs[idx].displayName.c_str()) != MBOX_CLICKED_YES) return 1;
		FXString errorMsg;
		if (!deleteSoftwarePackage(credOwner, domain, gpoGuid, true, machinePkgs[idx], errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		}
		reload();
		return 1;
	}
	long onRemoveUser(FXObject*, FXSelector, void*) {
		int idx = userList->getCurrentItem();
		if (idx < 0 || idx >= (int)userPkgs.size()) return 1;
		if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen", "\"%s\" wirklich entfernen?", userPkgs[idx].displayName.c_str()) != MBOX_CLICKED_YES) return 1;
		FXString errorMsg;
		if (!deleteSoftwarePackage(credOwner, domain, gpoGuid, false, userPkgs[idx], errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
		}
		reload();
		return 1;
	}

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
		machinePath = sysvolBase + "/MACHINE/Scripts/scripts.ini";
		userPath = sysvolBase + "/USER/Scripts/scripts.ini";

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
	enum { ID_NEW_GPO = FXDialogBox::ID_LAST, ID_ADD_GPO, ID_REMOVE_GPO, ID_EDIT_GPO, ID_INSTALL_SOFTWARE, ID_SECURITY_SETTINGS, ID_SCRIPTS, ID_FOLDER_REDIR, ID_LINK_UP, ID_LINK_DOWN };
	long onNewGpo(FXObject*, FXSelector, void*);
	long onAddGpo(FXObject*, FXSelector, void*);
	long onRemoveGpo(FXObject*, FXSelector, void*);
	long onEditGpo(FXObject*, FXSelector, void*);
	long onInstallSoftware(FXObject*, FXSelector, void*);
	long onSecuritySettings(FXObject*, FXSelector, void*);
	long onScripts(FXObject*, FXSelector, void*);
	long onFolderRedirection(FXObject*, FXSelector, void*);
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
			FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
			return 1;
		}
		auto all = listAllGpos();
		FXString guid;
		for (auto& g : all) if (g.displayName == name) guid = g.guid;
		if (!guid.empty()) linkGpo(this, guid, containerFullDN, errorMsg);
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
	FXString errorMsg;
	unlinkGpo(this, linkedGuids[idx], containerFullDN, errorMsg);
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
	std::string machinePolPath = sysvolBase + "/MACHINE/Registry.pol";
	std::string userPolPath = sysvolBase + "/USER/Registry.pol";
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
	std::string userPolPath = "/var/lib/samba/sysvol/" + std::string(realmLower.text()) + "/Policies/" + std::string(guid.text()) + "/USER/Registry.pol";
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
	FXMenuPane *konsolemenu, *vorgangmenu, *hilfemenu;
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
		ID_USER_PROPS, ID_MOVE_OBJECT, ID_RENAME_OBJECT
	};
	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
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

	FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);

	menubar = new FXMenuBar(main, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
	konsolemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Konsole", NULL, konsolemenu);
	new FXMenuCommand(konsolemenu, "&Beenden", NULL, getApp(), FXApp::ID_QUIT);
	vorgangmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Aktualisieren", NULL, this, ID_REFRESH);
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
	list->appendHeader("Typ", NULL, 140);
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
	for (auto& cont : listTopContainers()) {
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
	list->clearItems();
	for (auto& obj : currentObjects) {
		const char* typeName = "Objekt";
		FXIcon* ic = icoFolder;
		switch (obj.type) {
			case OBJ_USER: typeName = "Benutzer"; ic = icoUser; break;
			case OBJ_GROUP: typeName = "Sicherheitsgruppe - Global"; ic = icoUsers; break;
			case OBJ_COMPUTER: typeName = "Computer"; ic = icoServer; break;
			case OBJ_OU: typeName = "Organisationseinheit"; ic = icoFolder; break;
			case OBJ_CONTAINER: typeName = "Container"; ic = icoFolder; break;
			default: typeName = "Objekt"; ic = icoFolder; break;
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

	// Aktuelle Werte lesen (displayName/description/Kontostatus) --
	// samba-tool user list liefert das nicht, daher per "user show".
	std::string raw;
	runAsRootCaptured({ FXString("samba-tool"), FXString("user"), FXString("show"), obj.accountName }, raw);
	FXString curDisplayName, curDescription;
	bool curDisabled = false;
	for (auto& l : splitLines(raw)) {
		FXString fl = l.c_str();
		if (fl.left(12) == "displayName:") curDisplayName = fl.mid(12, fl.length() - 12).trim();
		else if (fl.left(12) == "description:") curDescription = fl.mid(12, fl.length() - 12).trim();
		else if (fl.left(19) == "userAccountControl:") {
			long uac = 0;
			try { uac = std::stol(fl.mid(19, fl.length() - 19).trim().text()); } catch (...) {}
			curDisabled = (uac & 0x2) != 0; // UF_ACCOUNTDISABLE
		}
	}

	UserPropertiesDialog dlg(this, obj.accountName, curDisplayName, curDescription, curDisabled);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	FXString errorMsg;
	FXString userFullDN = relDNToFullDN(obj.dn, domain);
	bool ok = setUserAttributes(this, domain.realm, userFullDN, dlg.getDisplayName(), dlg.getDescription(), errorMsg);
	if (ok && dlg.getDisabled() != curDisabled) {
		ok = setUserEnabled(obj.accountName, !dlg.getDisabled(), errorMsg);
	}
	if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	onRefresh(NULL, 0, NULL);
	return 1;
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
