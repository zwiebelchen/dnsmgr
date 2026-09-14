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
// ADM-Dateien laden und zusammenfuehren -- mehrere .adm-Dateien
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
// GPT.INI-Versionszaehler erhoehen -- damit ein echter Client erkennt,
// dass sich die Gruppenrichtlinie geaendert hat und neu angewendet
// werden muss. Format: 32-Bit-Zahl, oberes Halbwort = Benutzer-Version,
// unteres Halbwort = Computer-Version (wir erhoehen hier nur die
// Computer-Version, da dieser Editor sich vorerst auf
// Computerkonfiguration beschraenkt).
// ---------------------------------------------------------------------
static void bumpGptIniVersion(const std::string& gptIniPath, bool bumpMachine, bool bumpUser) {
	std::string content = readFileUnprivileged(gptIniPath.c_str());
	uint32_t version = 0;
	size_t pos = content.find("Version=");
	if (pos != std::string::npos) {
		size_t start = pos + 8, end = start;
		while (end < content.size() && isdigit((unsigned char)content[end])) end++;
		try { version = (uint32_t)std::stoul(content.substr(start, end - start)); } catch (...) {}
	}
	uint32_t machineVer = version & 0xFFFF;
	uint32_t userVer = (version >> 16) & 0xFFFF;
	if (bumpMachine) machineVer++;
	if (bumpUser) userVer++;
	uint32_t newVersion = (userVer << 16) | machineVer;
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
	enum { ID_TREE = FXDialogBox::ID_LAST, ID_LIST, ID_SAVE };

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
		bumpGptIniVersion(gptIniPath, touchedMachine, touchedUser);

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
	                const std::string& machinePolPath, const std::string& userPolPath, const std::string& gptIniPath_)
		: FXDialogBox(owner, "Gruppenrichtlinienobjekt-Editor", DECOR_ALL, 0,0,760,480),
		  gptIniPath(gptIniPath_) {
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
		                       ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y | FRAME_NORMAL);
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
};
FXIMPLEMENT(AdmEditorDialog, FXDialogBox, AdmEditorDialogMap, ARRAYNUMBER(AdmEditorDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" von Domäne/OU -- mit dem "Gruppenrichtlinie"-
// Reiter (Original-Vorbild: Screenshot des Nutzers). Der eigentliche
// Editor der Administrativen Vorlagen ist ein eigener, spaeterer
// Baustein -- hier nur Verknuepfen/Loesen/Anlegen von GPOs.
// ---------------------------------------------------------------------
class PropertiesDialog : public FXDialogBox {
	FXDECLARE(PropertiesDialog)
private:
	FXString containerFullDN;
	FXString realm;
	FXList* gpoList;
	std::vector<FXString> linkedGuids;
	std::map<FXString, FXString> guidToName;
public:
	enum { ID_NEW_GPO = FXDialogBox::ID_LAST, ID_ADD_GPO, ID_REMOVE_GPO, ID_EDIT_GPO };
	long onNewGpo(FXObject*, FXSelector, void*);
	long onAddGpo(FXObject*, FXSelector, void*);
	long onRemoveGpo(FXObject*, FXSelector, void*);
	long onEditGpo(FXObject*, FXSelector, void*);

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
		: FXDialogBox(owner, FXString("Eigenschaften von ") + title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,420),
		  containerFullDN(fullDN), realm(realm_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		FXTabBook* tabs = new FXTabBook(main, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);

		new FXTabItem(tabs, "Gruppenrichtlinie");
		FXVerticalFrame* gpoPage = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(gpoPage, "Aktuelle Gruppenrichtlinienobjekt-Verknüpfungen für\n" + title + ":");
		gpoList = new FXList(gpoPage, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXHorizontalFrame* gpoBtns = new FXHorizontalFrame(gpoPage, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXButton(gpoBtns, "&Neu", NULL, this, ID_NEW_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Hinzufügen...", NULL, this, ID_ADD_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Entfernen", NULL, this, ID_REMOVE_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(gpoBtns, "&Bearbeiten...", NULL, this, ID_EDIT_GPO, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

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
	AdmEditorDialog dlg(this, std::move(machineCats), std::move(userCats), machinePolPath, userPolPath, gptIniPath);
	dlg.execute(PLACEMENT_OWNER);
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
		ID_NEW_USER, ID_NEW_GROUP, ID_NEW_OU, ID_DELETE_OBJECT, ID_PROPERTIES, ID_GROUP_PROPS
	};
	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	long onNewUser(FXObject*, FXSelector, void*);
	long onNewGroup(FXObject*, FXSelector, void*);
	long onNewOU(FXObject*, FXSelector, void*);
	long onDeleteObject(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onGroupProperties(FXObject*, FXSelector, void*);

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
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_DELETE_OBJECT, DsAdminWindow::onDeleteObject),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_PROPERTIES, DsAdminWindow::onProperties),
	FXMAPFUNC(SEL_COMMAND, DsAdminWindow::ID_GROUP_PROPS, DsAdminWindow::onGroupProperties),
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

	for (auto& cont : listTopContainers()) {
		FXString label = cont;
		if (label.left(3) == "CN=") label = label.mid(3, label.length() - 3);
		else if (label.left(3) == "OU=") label = label.mid(3, label.length() - 3);
		FXTreeItem* it = tree->appendItem(domainRootItem, label, icoFolder, icoFolder);
		itemToRelDN[it] = cont;
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

long DsAdminWindow::onTreeRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item || !itemToRelDN.count(item)) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);
	FXString relDN = itemToRelDN[item];

	FXMenuPane menu(this);
	FXMenuPane neuMenu(this);
	new FXMenuCommand(&neuMenu, "&Benutzer...", NULL, this, ID_NEW_USER);
	new FXMenuCommand(&neuMenu, "&Gruppe...", NULL, this, ID_NEW_GROUP);
	new FXMenuCommand(&neuMenu, "&Organisationseinheit...", NULL, this, ID_NEW_OU);
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
		default: errorMsg = "Dieser Objekttyp kann hier noch nicht gelöscht werden."; break;
	}
	if (!ok) FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
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
