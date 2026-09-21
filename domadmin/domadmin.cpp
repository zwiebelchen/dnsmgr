// domadmin.cpp
//
// "Active Directory-Domänen und -Vertrauensstellungen" fuer ice2k --
// Nachbau des Snap-Ins aus Windows 2000 Server.
//
// Texte und Dialoge wortgleich aus domadmin.dll (Wurzel, UPN-Suffixe,
// Betriebsmaster) und dsprop.dll (Eigenschaftenseiten "Allgemein" und
// "Vertrauensstellungen", Dialoge zum Hinzufuegen einer
// Vertrauensstellung) -- deutsches Windows 2000 SP4, die DLLs selbst
// liegen nicht im Repository.
//
// Unterbau: samba-tool domain trust / level / fsmo sowie ldbmodify fuer
// die UPN-Suffixe (Attribut uPNSuffixes an CN=Partitions).

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "../common/ui/msgbox.h"

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/wait.h>

static FXApp* app = NULL;
static bool g_haveRoot = false;

static const char* SAM_LDB = "/var/lib/samba/private/sam.ldb";
static const char* LDAPI_URL = "ldapi://%2Fvar%2Flib%2Fsamba%2Fprivate%2Fldap_priv%2Fldapi";

// ---------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------
static std::string trimStr(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

static std::vector<std::string> splitLines(const std::string& s) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : s) {
		if (c == '\n') { out.push_back(cur); cur.clear(); }
		else if (c != '\r') cur += c;
	}
	if (!cur.empty()) out.push_back(cur);
	return out;
}

static int runCaptured(const std::vector<std::string>& args, std::string& output) {
	std::vector<char*> argv;
	for (auto& a : args) argv.push_back((char*)a.c_str());
	argv.push_back(NULL);
	int pipefd[2];
	if (pipe(pipefd) != 0) return -1;
	pid_t pid = fork();
	if (pid == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execvp(argv[0], argv.data());
		_exit(127);
	} else if (pid > 0) {
		close(pipefd[1]);
		char buf[8192];
		ssize_t n;
		while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) output.append(buf, n);
		close(pipefd[0]);
		int status = 0;
		waitpid(pid, &status, 0);
		return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	}
	close(pipefd[0]);
	close(pipefd[1]);
	return -1;
}

static int runAsRootCaptured(const std::vector<std::string>& args, std::string& output) {
	std::vector<std::string> full = { "i2ksudo" };
	for (auto& a : args) full.push_back(a);
	return runCaptured(full, output);
}

static int runAsRoot(const std::vector<std::string>& args) {
	std::string out;
	return runAsRootCaptured(args, out);
}

static std::string condenseError(const std::string& out) {
	std::string last;
	for (auto& line : splitLines(out)) {
		std::string l = trimStr(line);
		if (l.empty() || l.rfind("File \"", 0) == 0 || l.rfind("Traceback", 0) == 0) continue;
		last = l;
	}
	return last.empty() ? trimStr(out) : last;
}

// Wert eines Attributs per ldapsearch (erster Treffer).
static std::vector<std::string> ldapValues(const std::string& base, const std::string& scope,
                                           const std::string& filter, const std::string& attr) {
	std::vector<std::string> out;
	std::string raw;
	if (runAsRootCaptured({ "ldapsearch", "-x", "-LLL", "-o", "ldif-wrap=no", "-H", LDAPI_URL,
	                        "-b", base, "-s", scope, filter, attr }, raw) != 0) return out;
	for (auto& line : splitLines(raw))
		if (line.rfind(attr + ": ", 0) == 0) out.push_back(trimStr(line.substr(attr.size() + 2)));
	return out;
}

// ---------------------------------------------------------------------
// Domäne und Vertrauensstellungen
// ---------------------------------------------------------------------
struct DomainFacts {
	std::string baseDN, dnsName, netbios, description, level;
};

static DomainFacts readDomain() {
	DomainFacts d;
	auto base = ldapValues("", "base", "(objectClass=*)", "defaultNamingContext");
	if (base.empty()) return d;
	d.baseDN = base[0];
	// DC=linux,DC=zwiebelchen,DC=org -> linux.zwiebelchen.org
	std::string dns, rest = d.baseDN;
	while (!rest.empty()) {
		size_t eq = rest.find('=');
		size_t comma = rest.find(',');
		std::string part = rest.substr(eq + 1, comma == std::string::npos ? std::string::npos : comma - eq - 1);
		dns += (dns.empty() ? "" : ".") + part;
		if (comma == std::string::npos) break;
		rest = rest.substr(comma + 1);
	}
	d.dnsName = dns;
	auto nb = ldapValues("CN=Partitions,CN=Configuration," + d.baseDN, "one", "(nCName=" + d.baseDN + ")", "nETBIOSName");
	if (!nb.empty()) d.netbios = nb[0];
	auto desc = ldapValues(d.baseDN, "base", "(objectClass=*)", "description");
	if (!desc.empty()) d.description = desc[0];
	std::string out;
	runAsRootCaptured({ "samba-tool", "domain", "level", "show" }, out);
	for (auto& line : splitLines(out))
		if (line.find("Domain function level:") != std::string::npos) d.level = trimStr(line.substr(line.find(':') + 1));
	return d;
}

struct TrustInfo {
	std::string name, type, direction, transitive;
};

// "Type[External] Transitive[No]  Direction[OUTGOING] Name[andere.domaene]"
static std::string bracketValue(const std::string& line, const std::string& key) {
	size_t p = line.find(key + "[");
	if (p == std::string::npos) return "";
	p += key.size() + 1;
	size_t e = line.find(']', p);
	return e == std::string::npos ? "" : line.substr(p, e - p);
}

static std::vector<TrustInfo> listTrusts(std::string& error) {
	std::vector<TrustInfo> out;
	std::string raw;
	if (runAsRootCaptured({ "timeout", "30", "samba-tool", "domain", "trust", "list" }, raw) != 0) {
		error = condenseError(raw);
		return out;
	}
	for (auto& line : splitLines(raw)) {
		if (line.find("Name[") == std::string::npos) continue;
		TrustInfo t;
		t.name = bracketValue(line, "Name");
		t.type = bracketValue(line, "Type");
		t.direction = bracketValue(line, "Direction");
		t.transitive = bracketValue(line, "Transitive");
		out.push_back(t);
	}
	return out;
}

static std::vector<std::string> listUpnSuffixes(const DomainFacts& d) {
	return ldapValues("CN=Partitions,CN=Configuration," + d.baseDN, "base", "(objectClass=*)", "uPNSuffixes");
}

static bool saveUpnSuffixes(const DomainFacts& d, const std::vector<std::string>& suffixes, FXString& errorMsg) {
	std::string ldif = "dn: CN=Partitions,CN=Configuration," + d.baseDN + "\nchangetype: modify\nreplace: uPNSuffixes\n";
	for (auto& s : suffixes) ldif += "uPNSuffixes: " + s + "\n";
	ldif += "\n";
	std::string tmp = "/tmp/ice2k-upn.ldif";
	{ std::ofstream out(tmp); out << ldif; }
	std::string out;
	int rc = runAsRootCaptured({ "sh", "-c", std::string("ldbmodify -H ") + SAM_LDB + " " + tmp + " 2>&1" }, out);
	runAsRoot({ "rm", "-f", tmp });
	if (rc != 0) {
		// Text 201 aus domadmin.dll
		errorMsg = FXString("Die UPN-Suffixe können nicht aktualisiert werden. ") + trimStr(out).c_str();
		return false;
	}
	return true;
}

static std::string namingMaster() {
	std::string out;
	runAsRootCaptured({ "samba-tool", "fsmo", "show" }, out);
	for (auto& line : splitLines(out)) {
		if (line.find("DomainNamingMasterRole") == std::string::npos) continue;
		// ...owner: CN=NTDS Settings,CN=VM,CN=Servers,...
		size_t p = line.find("CN=NTDS Settings,CN=");
		if (p == std::string::npos) return trimStr(line.substr(line.find(':') + 1));
		p += 20;
		return line.substr(p, line.find(',', p) - p);
	}
	return "";
}

// ---------------------------------------------------------------------
// Dialoge
// ---------------------------------------------------------------------

// "UPN-Suffixe" (domadmin.dll, Dialog 214)
class UpnDialog : public FXDialogBox {
	FXDECLARE(UpnDialog)
private:
	FXTextField* field = nullptr;
	FXList* list = nullptr;
	std::vector<std::string> suffixes;
protected:
	UpnDialog() {}
public:
	enum { ID_ADD = FXDialogBox::ID_LAST, ID_REMOVE };
	UpnDialog(FXWindow* owner, const std::vector<std::string>& initial)
		: FXDialogBox(owner, "Eigenschaften von Active Directory-Domänen und -Vertrauensstellungen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,600,440),
		  suffixes(initial) {
		FXVerticalFrame* outer = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(outer, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "UPN-Suffixe", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		new FXLabel(page, "Die Namen der aktuellen Domäne und der Stammdomäne sind die UPN-Standardsuffixe.\n"
		                  "Wenn alternative Domänennamen hinzugefügt werden, wird die Anmeldesicherheit\n"
		                  "erhöht und die Benutzeranmeldenamen vereinfacht.", NULL, JUSTIFY_LEFT);
		new FXLabel(page, "Fügen Sie die alternativen UPN-Suffixe, die während der Benutzererstellung\n"
		                  "angezeigt werden sollen, in folgende Liste ein.", NULL, JUSTIFY_LEFT);
		new FXLabel(page, "Alternative &UPN-Suffixe:", NULL, JUSTIFY_LEFT);
		FXHorizontalFrame* r = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		field = new FXTextField(r, 24, this, ID_ADD, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_ENTER_ONLY);
		new FXButton(r, "Hin&zufügen", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,90,0, 4,4,3,3);
		FXHorizontalFrame* r2 = new FXHorizontalFrame(page, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 6,0);
		FXPacker* lf = new FXPacker(r2, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		list = new FXList(lf, NULL, 0, LIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXButton(r2, "&Entfernen", NULL, this, ID_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH | LAYOUT_TOP, 0,0,90,0, 4,4,3,3);
		for (auto& s : suffixes) list->appendItem(s.c_str());
		FXHorizontalFrame* btnf = new FXHorizontalFrame(outer, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onAdd(FXObject*, FXSelector, void*) {
		std::string v = trimStr(field->getText().text());
		if (v.empty()) return 1;
		if (std::find(suffixes.begin(), suffixes.end(), v) != suffixes.end()) {
			// Text 202 aus domadmin.dll
			ice2kui::error(this, MBOX_OK, "Active Directory-Domänen und -Vertrauensstellungen",
				"Es ist bereits eine UPN-Suffix in der Liste vorhanden.");
			return 1;
		}
		suffixes.push_back(v);
		list->appendItem(v.c_str());
		field->setText("");
		return 1;
	}
	long onRemove(FXObject*, FXSelector, void*) {
		int i = list->getCurrentItem();
		if (i < 0 || i >= (int)suffixes.size()) return 1;
		// Text 200 aus domadmin.dll (gekürzt auf den ersten Satz)
		if (ice2kui::warning(this, MBOX_YES_NO, "Active Directory-Domänen und -Vertrauensstellungen",
		        "Benutzerkonten, die auf die gelöschten UPN-Suffixe verweisen, sind betroffen.\n"
		        "Diese Benutzer können sich nicht am Netzwerk anmelden, wenn sie das\n"
		        "gelöschte Suffix verwenden.\n\nMöchten Sie fortfahren?") != MBOX_CLICKED_YES) return 1;
		suffixes.erase(suffixes.begin() + i);
		list->removeItem(i);
		return 1;
	}
	const std::vector<std::string>& result() const { return suffixes; }
	virtual ~UpnDialog() {}
};
FXDEFMAP(UpnDialog) UpnDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, UpnDialog::ID_ADD, UpnDialog::onAdd),
	FXMAPFUNC(SEL_COMMAND, UpnDialog::ID_REMOVE, UpnDialog::onRemove),
};
FXIMPLEMENT(UpnDialog, FXDialogBox, UpnDialogMap, ARRAYNUMBER(UpnDialogMap))

// "Betriebsmaster ändern" (domadmin.dll, Dialog 217)
class OpsMasterDialog : public FXDialogBox {
	FXDECLARE(OpsMasterDialog)
protected:
	OpsMasterDialog() {}
public:
	enum { ID_CHANGE = FXDialogBox::ID_LAST };
	std::string master;
	OpsMasterDialog(FXWindow* owner, const std::string& master_, const std::string& current)
		: FXDialogBox(owner, "Betriebsmaster ändern", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,470,0), master(master_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Der Domänennamen-Betriebsmaster stellt sicher, dass Domänennamen eindeutig\n"
		                  "sind. Nur ein Domänencontroller der Organisation kann diese Funktion ausführen.", NULL, JUSTIFY_LEFT);
		new FXLabel(main, "Domänennamen-Betriebsmaster:", NULL, JUSTIFY_LEFT);
		FXTextField* m = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_READONLY);
		m->setText(master.c_str());
		FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,6,0, 8,0);
		new FXLabel(r, "Klicken Sie auf \"Ändern\", um die Domänennamen-Masterfunktion auf\n"
		               "folgenden Computer zu übertragen.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		new FXButton(r, "Ä&ndern...", NULL, this, ID_CHANGE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH | LAYOUT_TOP, 0,0,90,0, 4,4,3,3);
		FXTextField* c = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_READONLY);
		c->setText(current.c_str());
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "&Schließen", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		currentHost = current;
	}
	std::string currentHost;
	long onChange(FXObject*, FXSelector, void*) {
		if (lower(currentHost) == lower(master)) {
			// Text 205 aus domadmin.dll
			ice2kui::information(this, MBOX_OK, "Active Directory-Domänen und -Vertrauensstellungen",
				"Der aktuelle Domänencontroller ist der Betriebsmaster. Um die Betriebsmasterfunktion\n"
				"auf einen anderen Computer zu übertragen, müssen Sie zuerst eine Verbindung mit\n"
				"diesem Computer herstellen.");
			return 1;
		}
		// Text 206
		if (ice2kui::question(this, MBOX_YES_NO, "Active Directory-Domänen und -Vertrauensstellungen",
		        "Soll die Betriebsmasterfunktion wirklich auf einen anderen Computer übertragen werden?") != MBOX_CLICKED_YES)
			return 1;
		std::string out;
		if (runAsRootCaptured({ "timeout", "60", "samba-tool", "fsmo", "transfer", "--role=naming" }, out) != 0)
			// Text 203
			ice2kui::error(this, MBOX_OK, "Active Directory-Domänen und -Vertrauensstellungen",
				"Die aktuelle Betriebsmasterfunktion konnte nicht übertragen werden. Ursache:  %s.", condenseError(out).c_str());
		else
			// Text 208
			ice2kui::information(this, MBOX_OK, "Active Directory-Domänen und -Vertrauensstellungen",
				"Der Betriebsmaster wurde fehlerfrei übertragen.");
		return 1;
	}
	static std::string lower(std::string s) { std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; }
	virtual ~OpsMasterDialog() {}
};
FXDEFMAP(OpsMasterDialog) OpsMasterDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, OpsMasterDialog::ID_CHANGE, OpsMasterDialog::onChange),
};
FXIMPLEMENT(OpsMasterDialog, FXDialogBox, OpsMasterDialogMap, ARRAYNUMBER(OpsMasterDialogMap))

// "Vertraute/Vertrauende Domäne hinzufügen" (dsprop.dll, Dialoge 241/242)
// plus Anmeldung an der anderen Domäne (Dialog 334). Samba braucht statt
// des Vertrauenskennworts die Anmeldung eines Administrators der anderen
// Domäne -- deshalb beides in einem Dialog.
class AddTrustDialog : public FXDialogBox {
	FXDECLARE(AddTrustDialog)
private:
	FXTextField *domainField = nullptr, *userField = nullptr, *passField = nullptr;
protected:
	AddTrustDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	AddTrustDialog(FXWindow* owner, bool outgoing)
		: FXDialogBox(owner, outgoing ? "Vertraute Domäne hinzufügen" : "Vertrauende Domäne hinzufügen",
		              DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,470,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		FXMatrix* m = new FXMatrix(main, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
		new FXLabel(m, outgoing ? "&Vertraute Domäne:" : "&Vertrauende Domäne:", NULL, JUSTIFY_LEFT);
		domainField = new FXTextField(m, 26, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		new FXLabel(main, "Sie müssen sich an der anderen Domäne als Benutzer mit der Berechtigung,\n"
		                  "die Vertrauensstellung zu ändern, anmelden, um den Vorgang abschließen zu können.", NULL, JUSTIFY_LEFT);
		FXMatrix* m2 = new FXMatrix(main, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
		new FXLabel(m2, "Be&nutzername:", NULL, JUSTIFY_LEFT);
		userField = new FXTextField(m2, 26, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		userField->setText("Administrator");
		new FXLabel(m2, "&Kennwort:", NULL, JUSTIFY_LEFT);
		passField = new FXTextField(m2, 26, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (trimStr(domainField->getText().text()).empty() || trimStr(userField->getText().text()).empty()) {
			ice2kui::error(this, MBOX_OK, "Active Directory", "Geben Sie die Domäne und einen Benutzernamen an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string domain() const { return trimStr(domainField->getText().text()); }
	std::string user() const { return trimStr(userField->getText().text()); }
	std::string password() const { return passField->getText().text(); }
	virtual ~AddTrustDialog() {}
};
FXDEFMAP(AddTrustDialog) AddTrustDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, AddTrustDialog::ID_OK, AddTrustDialog::onOk),
};
FXIMPLEMENT(AddTrustDialog, FXDialogBox, AddTrustDialogMap, ARRAYNUMBER(AddTrustDialogMap))

// Eigenschaften einer Vertrauensstellung (dsprop.dll, Dialog 246)
class TrustPropertiesDialog : public FXDialogBox {
	FXDECLARE(TrustPropertiesDialog)
private:
	TrustInfo trust;
protected:
	TrustPropertiesDialog() {}
public:
	enum { ID_VALIDATE = FXDialogBox::ID_LAST, ID_DELETE };
	bool deleted = false;
	TrustPropertiesDialog(FXWindow* owner, const DomainFacts& d, const TrustInfo& t)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + t.name.c_str(), DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,480,0), trust(t) {
		FXVerticalFrame* outer = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(outer, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		FXMatrix* m = new FXMatrix(page, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
		auto row = [&](const char* label, const std::string& value) {
			new FXLabel(m, label, NULL, JUSTIFY_LEFT);
			FXTextField* f = new FXTextField(m, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_READONLY);
			f->setText(value.c_str());
		};
		row("Diese Domäne:", d.dnsName);
		row("Andere Domäne:", t.name);
		row("Vertrauenstyp:", t.type == "External" ? "Extern" : t.type == "Forest" ? "Gesamtstruktur" : t.type);
		new FXLabel(page, "Vertrauensrichtung:", NULL, JUSTIFY_LEFT);
		FXString dir = t.direction == "OUTGOING" ? FXString("Diese Domäne vertraut der anderen Domäne.")
		             : t.direction == "INCOMING" ? FXString("Die andere Domäne vertraut dieser Domäne.")
		             : FXString("Die Domänen vertrauen einander (bidirektional).");
		new FXLabel(page, dir, NULL, JUSTIFY_LEFT);
		new FXLabel(page, "Transitivität der Vertrauensstellung:", NULL, JUSTIFY_LEFT);
		new FXLabel(page, t.transitive == "Yes" ? "Diese Vertrauensstellung ist transitiv."
		                                        : "Diese Vertrauensstellung ist nicht transitiv.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* v = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 8,0);
		new FXLabel(v, "Klicken Sie auf \"Überprüfen\", um diese Vertrauensstellung zu überprüfen\n"
		               "und ggf. zurückzusetzen. Dies ist bei der Problembehandlung hilfreich.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		new FXButton(v, "Üb&erprüfen", NULL, this, ID_VALIDATE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_TOP, 0,0,0,0, 8,8,3,3);
		new FXButton(page, "Vertrauensstellung aufheben", NULL, this, ID_DELETE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_RIGHT, 0,0,0,0, 8,8,3,3);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(outer, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onValidate(FXObject*, FXSelector, void*) {
		getApp()->beginWaitCursor();
		std::string out;
		int rc = runAsRootCaptured({ "timeout", "60", "samba-tool", "domain", "trust", "validate", trust.name }, out);
		getApp()->endWaitCursor();
		if (rc != 0) ice2kui::error(this, MBOX_OK, "Active Directory", "Die Überprüfung ist fehlgeschlagen:\n\n%s", condenseError(out).c_str());
		else ice2kui::information(this, MBOX_OK, "Active Directory", "Die Vertrauensstellung wurde überprüft und ist in Ordnung.");
		return 1;
	}
	long onDelete(FXObject*, FXSelector, void*) {
		if (ice2kui::question(this, MBOX_YES_NO, "Active Directory",
		        "Soll die Vertrauensstellung zu %s wirklich aufgehoben werden?", trust.name.c_str()) != MBOX_CLICKED_YES) return 1;
		std::string out;
		if (runAsRootCaptured({ "timeout", "60", "samba-tool", "domain", "trust", "delete", trust.name }, out) != 0) {
			ice2kui::error(this, MBOX_OK, "Active Directory", "Die Vertrauensstellung konnte nicht aufgehoben werden:\n\n%s", condenseError(out).c_str());
			return 1;
		}
		deleted = true;
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	virtual ~TrustPropertiesDialog() {}
};
FXDEFMAP(TrustPropertiesDialog) TrustPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, TrustPropertiesDialog::ID_VALIDATE, TrustPropertiesDialog::onValidate),
	FXMAPFUNC(SEL_COMMAND, TrustPropertiesDialog::ID_DELETE, TrustPropertiesDialog::onDelete),
};
FXIMPLEMENT(TrustPropertiesDialog, FXDialogBox, TrustPropertiesDialogMap, ARRAYNUMBER(TrustPropertiesDialogMap))

// Eigenschaften der Domäne: "Allgemein" (dsprop.dll 230) und
// "Vertrauensstellungen" (dsprop.dll 237).
class DomainPropertiesDialog : public FXDialogBox {
	FXDECLARE(DomainPropertiesDialog)
private:
	DomainFacts dom;
	std::vector<TrustInfo> trusts;
	std::vector<TrustInfo> outgoing, incoming;   // vertraut / vertrauend
	FXIconList *outList = nullptr, *inList = nullptr;
	FXTextField* descField = nullptr;
	std::string origDesc;
protected:
	DomainPropertiesDialog() {}
public:
	enum { ID_ADD_OUT = FXDialogBox::ID_LAST, ID_EDIT_OUT, ID_DEL_OUT, ID_ADD_IN, ID_EDIT_IN, ID_DEL_IN, ID_MODE, ID_OK };
	DomainPropertiesDialog(FXWindow* owner, const DomainFacts& d)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + d.dnsName.c_str(), DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,520,480), dom(d) {
		FXVerticalFrame* outer = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(outer, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		// ---- Allgemein ----
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* gen = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		new FXLabel(gen, d.dnsName.c_str(), NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(gen, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* nb = new FXHorizontalFrame(gen, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 8,0);
		new FXLabel(nb, "Domänenname (Windows NT 3.5x/4.0):", NULL, LAYOUT_CENTER_Y);
		FXTextField* nbField = new FXTextField(nb, 16, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | TEXTFIELD_READONLY);
		nbField->setText(d.netbios.c_str());
		new FXLabel(gen, "B&eschreibung:", NULL, JUSTIFY_LEFT);
		descField = new FXTextField(gen, 40, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		descField->setText(d.description.c_str());
		origDesc = d.description;
		new FXLabel(gen, "Betriebsmodus der Domäne:", NULL, JUSTIFY_LEFT);
		// Samba setzt mindestens Funktionsebene 2003 voraus -- das entspricht
		// dem einheitlichen Modus von Windows 2000.
		new FXLabel(gen, FXString("Einheitlicher Modus (Funktionsebene ") + d.level.c_str() + ")", NULL, JUSTIFY_LEFT);
		FXGroupBox* mode = new FXGroupBox(gen, "Domänenmodus", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8, 0,4);
		new FXLabel(mode, "Die Domäne arbeitet bereits im einheitlichen Modus. Ein Wechsel ist\n"
		                  "weder nötig noch möglich; Samba kennt den gemischten Modus nicht.", NULL, JUSTIFY_LEFT);
		(new FXButton(mode, "&Modus wechseln", NULL, this, ID_MODE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_RIGHT, 0,0,0,0, 8,8,3,3))->disable();

		// ---- Vertrauensstellungen ----
		new FXTabItem(tabs, "Vertrauensstellungen", NULL);
		FXVerticalFrame* tr = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,4);
		auto block = [&](const char* label, FXIconList*& lst, FXSelector add, FXSelector edit, FXSelector del, const char* addText) {
			new FXLabel(tr, label, NULL, JUSTIFY_LEFT);
			FXHorizontalFrame* h = new FXHorizontalFrame(tr, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 6,0);
			FXPacker* lf = new FXPacker(h, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
			lst = new FXIconList(lf, NULL, 0, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
			lst->appendHeader("Domänenname", NULL, 200);
			lst->appendHeader("Transitiv", NULL, 80);
			FXVerticalFrame* b = new FXVerticalFrame(h, LAYOUT_FILL_Y | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,0,0, 0,4);
			new FXButton(b, addText, NULL, this, add, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);
			new FXButton(b, "B&earbeiten...", NULL, this, edit, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);
			new FXButton(b, "En&tfernen", NULL, this, del, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 8,8,3,3);
		};
		block("&Domänen, denen diese Domäne vertraut:", outList, ID_ADD_OUT, ID_EDIT_OUT, ID_DEL_OUT, "&Hinzufügen...");
		block("Do&mänen, die dieser Domäne vertrauen:", inList, ID_ADD_IN, ID_EDIT_IN, ID_DEL_IN, "Hinzufügen...");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(outer, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		reloadTrusts();
	}
	void reloadTrusts() {
		std::string error;
		trusts = listTrusts(error);
		outgoing.clear(); incoming.clear();
		outList->clearItems(); inList->clearItems();
		for (auto& t : trusts) {
			FXString line = FXString(t.name.c_str()) + "\t" + (t.transitive == "Yes" ? "Ja" : "Nein");
			// Bidirektional erscheint wie im Original in beiden Listen.
			if (t.direction == "OUTGOING" || t.direction == "BOTH") { outgoing.push_back(t); outList->appendItem(line); }
			if (t.direction == "INCOMING" || t.direction == "BOTH") { incoming.push_back(t); inList->appendItem(line); }
		}
	}
	void addTrust(bool out) {
		if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Active Directory", "Ohne Root-Rechte kann nichts geändert werden."); return; }
		AddTrustDialog dlg(this, out);
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		getApp()->beginWaitCursor();
		std::string o;
		int rc = runAsRootCaptured({ "timeout", "120", "samba-tool", "domain", "trust", "create", dlg.domain(),
		                             "--type=external", std::string("--direction=") + (out ? "outgoing" : "incoming"),
		                             "-U", dlg.user() + "%" + dlg.password() }, o);
		getApp()->endWaitCursor();
		if (rc != 0) ice2kui::error(this, MBOX_OK, "Active Directory", "Die Vertrauensstellung konnte nicht erstellt werden:\n\n%s", condenseError(o).c_str());
		reloadTrusts();
	}
	void editTrust(bool out) {
		FXIconList* lst = out ? outList : inList;
		std::vector<TrustInfo>& v = out ? outgoing : incoming;
		int i = lst->getCurrentItem();
		if (i < 0 || i >= (int)v.size()) return;
		TrustPropertiesDialog dlg(this, dom, v[i]);
		dlg.execute(PLACEMENT_OWNER);
		if (dlg.deleted) reloadTrusts();
	}
	void deleteTrust(bool out) {
		FXIconList* lst = out ? outList : inList;
		std::vector<TrustInfo>& v = out ? outgoing : incoming;
		int i = lst->getCurrentItem();
		if (i < 0 || i >= (int)v.size()) return;
		if (ice2kui::question(this, MBOX_YES_NO, "Active Directory",
		        "Soll die Vertrauensstellung zu %s wirklich entfernt werden?", v[i].name.c_str()) != MBOX_CLICKED_YES) return;
		std::string o;
		if (runAsRootCaptured({ "timeout", "60", "samba-tool", "domain", "trust", "delete", v[i].name }, o) != 0)
			ice2kui::error(this, MBOX_OK, "Active Directory", "Die Vertrauensstellung konnte nicht entfernt werden:\n\n%s", condenseError(o).c_str());
		reloadTrusts();
	}
	long onAddOut(FXObject*, FXSelector, void*) { addTrust(true); return 1; }
	long onAddIn(FXObject*, FXSelector, void*) { addTrust(false); return 1; }
	long onEditOut(FXObject*, FXSelector, void*) { editTrust(true); return 1; }
	long onEditIn(FXObject*, FXSelector, void*) { editTrust(false); return 1; }
	long onDelOut(FXObject*, FXSelector, void*) { deleteTrust(true); return 1; }
	long onDelIn(FXObject*, FXSelector, void*) { deleteTrust(false); return 1; }
	long onOk(FXObject*, FXSelector, void*) {
		std::string desc = trimStr(descField->getText().text());
		if (desc != origDesc) {
			std::string ldif = "dn: " + dom.baseDN + "\nchangetype: modify\nreplace: description\n" +
			                   (desc.empty() ? std::string() : "description: " + desc + "\n") + "\n";
			std::string tmp = "/tmp/ice2k-domdesc.ldif";
			{ std::ofstream o(tmp); o << ldif; }
			std::string out;
			int rc = runAsRootCaptured({ "sh", "-c", std::string("ldbmodify -H ") + SAM_LDB + " " + tmp + " 2>&1" }, out);
			runAsRoot({ "rm", "-f", tmp });
			if (rc != 0) { ice2kui::error(this, MBOX_OK, "Active Directory", "%s", trimStr(out).c_str()); return 1; }
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	virtual ~DomainPropertiesDialog() {}
};
FXDEFMAP(DomainPropertiesDialog) DomainPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_ADD_OUT, DomainPropertiesDialog::onAddOut),
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_ADD_IN, DomainPropertiesDialog::onAddIn),
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_EDIT_OUT, DomainPropertiesDialog::onEditOut),
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_EDIT_IN, DomainPropertiesDialog::onEditIn),
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_DEL_OUT, DomainPropertiesDialog::onDelOut),
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_DEL_IN, DomainPropertiesDialog::onDelIn),
	FXMAPFUNC(SEL_COMMAND, DomainPropertiesDialog::ID_OK, DomainPropertiesDialog::onOk),
};
FXIMPLEMENT(DomainPropertiesDialog, FXDialogBox, DomainPropertiesDialogMap, ARRAYNUMBER(DomainPropertiesDialogMap))

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
class DomAdminWindow : public FXMainWindow {
	FXDECLARE(DomAdminWindow)
private:
	FXTreeList* tree = nullptr;
	FXIconList* list = nullptr;
	FXLabel* statusbar = nullptr;
	FXTreeItem *rootItem = nullptr, *domainItem = nullptr;
	FXIcon *icoRoot = nullptr, *icoDomain = nullptr;
	DomainFacts dom;
protected:
	DomAdminWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_MANAGE, ID_OPSMASTER, ID_UPN, ID_DOMAIN_PROPS, ID_REFRESH, ID_ABOUT };
	DomAdminWindow(FXApp* a);
	virtual void create();
	long onTree(FXObject*, FXSelector, void*);
	long onTreeRight(FXObject*, FXSelector, void*);
	long onListDouble(FXObject*, FXSelector, void*);
	long onManage(FXObject*, FXSelector, void*);
	long onOpsMaster(FXObject*, FXSelector, void*);
	long onUpn(FXObject*, FXSelector, void*);
	long onDomainProps(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	void reload();
	void showFor(FXTreeItem* item);
	virtual ~DomAdminWindow() {}
};

FXDEFMAP(DomAdminWindow) DomAdminWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, DomAdminWindow::ID_TREE, DomAdminWindow::onTree),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, DomAdminWindow::ID_TREE, DomAdminWindow::onTreeRight),
	FXMAPFUNC(SEL_DOUBLECLICKED, DomAdminWindow::ID_LIST, DomAdminWindow::onListDouble),
	FXMAPFUNC(SEL_COMMAND, DomAdminWindow::ID_MANAGE, DomAdminWindow::onManage),
	FXMAPFUNC(SEL_COMMAND, DomAdminWindow::ID_OPSMASTER, DomAdminWindow::onOpsMaster),
	FXMAPFUNC(SEL_COMMAND, DomAdminWindow::ID_UPN, DomAdminWindow::onUpn),
	FXMAPFUNC(SEL_COMMAND, DomAdminWindow::ID_DOMAIN_PROPS, DomAdminWindow::onDomainProps),
	FXMAPFUNC(SEL_COMMAND, DomAdminWindow::ID_REFRESH, DomAdminWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DomAdminWindow::ID_ABOUT, DomAdminWindow::onAbout),
};
FXIMPLEMENT(DomAdminWindow, FXMainWindow, DomAdminWindowMap, ARRAYNUMBER(DomAdminWindowMap))

DomAdminWindow::DomAdminWindow(FXApp* a)
	: FXMainWindow(a, "Active Directory-Domänen und -Vertrauensstellungen", NULL, NULL, DECOR_ALL, 0,0, 820,520) {
	// Symbole aus domadmin.dll (deutsches Windows 2000 SP4).
	icoRoot = new FXPNGIcon(a, resico_dom_root, IMAGE_NEAREST);
	icoDomain = new FXPNGIcon(a, resico_dom_domain, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoDomain }) i->create();

	FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	FXMenuPane* vorgang = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
	// Befehle wortgleich aus domadmin.dll (Texte 100, 103).
	new FXMenuCommand(vorgang, "&Verwalten", NULL, this, ID_MANAGE);
	new FXMenuCommand(vorgang, "&Betriebsmaster...", NULL, this, ID_OPSMASTER);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Eigenschaften", NULL, this, ID_DOMAIN_PROPS);
	FXMenuPane* hilfe = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&?", NULL, hilfe);
	new FXMenuCommand(hilfe, "&Info", NULL, this, ID_ABOUT);

	FXToolBar* toolbar = new FXToolBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
	auto gif = [&](const unsigned char* d) { return new FXGIFIcon(getApp(), d); };
	auto tb = [&](const char* tip, FXIcon* ic, FXSelector sel) {
		new FXButton(toolbar, tip, ic, this, sel, BUTTON_TOOLBAR | FRAME_RAISED | LAYOUT_CENTER_Y, 0,0,0,0, 2,2,2,2);
	};
	tb("\tZurück", gif(resico_mmc_back), 0);
	tb("\tVor", gif(resico_mmc_forward), 0);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
	tb("\tEigenschaften", gif(resico_mmc_properties), ID_DOMAIN_PROPS);
	tb("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
	tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	new FXToolTip(getApp());

	statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);
	FXSplitter* splitter = new FXSplitter(this, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,330,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
	FXPacker* listframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(listframe, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	// Spalten wie domadmin.dll (Texte 2 und 4).
	list->appendHeader("Name", NULL, 300);
	list->appendHeader("Typ", NULL, 200);
}

void DomAdminWindow::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

void DomAdminWindow::reload() {
	getApp()->beginWaitCursor();
	dom = readDomain();
	getApp()->endWaitCursor();
	tree->clearItems();
	rootItem = tree->appendItem(0, "Active Directory-Domänen und -Vertrauensstellungen", icoRoot, icoRoot);
	domainItem = dom.dnsName.empty() ? nullptr : tree->appendItem(rootItem, dom.dnsName.c_str(), icoDomain, icoDomain);
	tree->expandTree(rootItem);
	tree->setCurrentItem(rootItem);
	tree->selectItem(rootItem);
	showFor(rootItem);
	if (dom.dnsName.empty())
		// Text 6 aus domadmin.dll
		statusbar->setText(" Die Konfigurationsinformationen, die diese Organisation beschreiben, sind nicht verfügbar.");
}

void DomAdminWindow::showFor(FXTreeItem* item) {
	list->clearItems();
	if (item == rootItem && domainItem) {
		list->appendItem(FXString(dom.dnsName.c_str()) + "\tdomainDNS", icoDomain, icoDomain);
		statusbar->setText(FXString(" Domänennamen-Betriebsmaster: ") + namingMaster().c_str());
	} else if (item == domainItem) {
		statusbar->setText(FXString(" ") + dom.dnsName.c_str() + " (" + dom.netbios.c_str() + ") -- Funktionsebene " + dom.level.c_str());
	}
}

long DomAdminWindow::onTree(FXObject*, FXSelector, void*) { showFor(tree->getCurrentItem()); return 1; }

long DomAdminWindow::onTreeRight(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);
	showFor(item);
	FXMenuPane menu(this);
	if (item == rootItem) {
		new FXMenuCommand(&menu, "&Betriebsmaster...", NULL, this, ID_OPSMASTER);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_UPN);
	} else {
		new FXMenuCommand(&menu, "&Verwalten", NULL, this, ID_MANAGE);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_DOMAIN_PROPS);
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DomAdminWindow::onListDouble(FXObject*, FXSelector, void*) { return onDomainProps(NULL, 0, NULL); }

// "Verwalten" startet Active Directory-Benutzer und -Computer (Text 100).
long DomAdminWindow::onManage(FXObject*, FXSelector, void*) {
	pid_t pid = fork();
	if (pid == 0) {
		setsid();
		execlp("dsadmin", "dsadmin", (char*)NULL);
		_exit(127);
	}
	int status = 0;
	usleep(300000);
	if (waitpid(pid, &status, WNOHANG) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 127)
		// Text 204 aus domadmin.dll
		ice2kui::error(this, MBOX_OK, "Active Directory-Domänen und -Vertrauensstellungen",
			"Der Start de Komponente Active Directory-Benutzer und Computer-Snap-In ist fehlgeschlagen.");
	return 1;
}

long DomAdminWindow::onOpsMaster(FXObject*, FXSelector, void*) {
	char host[256] = { 0 };
	gethostname(host, sizeof(host) - 1);
	std::string h = host;
	size_t dot = h.find('.');
	if (dot != std::string::npos) h = h.substr(0, dot);
	std::transform(h.begin(), h.end(), h.begin(), ::toupper);
	OpsMasterDialog dlg(this, namingMaster(), h);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DomAdminWindow::onUpn(FXObject*, FXSelector, void*) {
	if (dom.baseDN.empty()) return 1;
	UpnDialog dlg(this, listUpnSuffixes(dom));
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Active Directory", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	FXString errorMsg;
	if (!saveUpnSuffixes(dom, dlg.result(), errorMsg))
		ice2kui::error(this, MBOX_OK, "Active Directory-Domänen und -Vertrauensstellungen", "%s", errorMsg.text());
	return 1;
}

long DomAdminWindow::onDomainProps(FXObject*, FXSelector, void*) {
	if (dom.baseDN.empty()) return 1;
	if (tree->getCurrentItem() == rootItem && list->getCurrentItem() < 0) return onUpn(NULL, 0, NULL);
	DomainPropertiesDialog dlg(this, dom);
	if (dlg.execute(PLACEMENT_OWNER)) reload();
	return 1;
}

long DomAdminWindow::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }

long DomAdminWindow::onAbout(FXObject*, FXSelector, void*) {
	ice2kui::information(this, MBOX_OK, "Info",
		"Active Directory-Domänen und -Vertrauensstellungen (ice2k)\n\n"
		"Domänen, Vertrauensstellungen (samba-tool domain trust), UPN-Suffixe\n"
		"und der Domänennamen-Betriebsmaster (samba-tool fsmo).");
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("DomAdmin", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	g_haveRoot = (runAsRoot({ "true" }) == 0);
	DomAdminWindow* win = new DomAdminWindow(&application);
	application.create();
	if (!g_haveRoot)
		ice2kui::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\nDie Anzeige funktioniert, Änderungen sind nicht möglich.");
	return application.run();
}
