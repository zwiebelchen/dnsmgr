// dssite.cpp
//
// "Active Directory-Standorte und -Dienste" fuer ice2k -- Nachbau des
// Snap-Ins aus Windows 2000 Server.
//
// Gelesen wird der Konfigurationsteil des Verzeichnisses unter
// CN=Sites,CN=Configuration,<Basis>. Standorte und Subnetze legt
// "samba-tool sites" an bzw. entfernt sie; Standortverknuepfungen
// (Kosten, Replikationsintervall, beteiligte Standorte) werden mit
// ldbmodify geaendert, weil samba-tool dafuer keinen Befehl hat.

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

// Fehlerausgabe von samba-tool auf das Wesentliche eindampfen.
static std::string condenseError(const std::string& out) {
	std::string last;
	for (auto& line : splitLines(out)) {
		std::string l = trimStr(line);
		if (l.empty() || l.rfind("  File \"", 0) == 0 || l.rfind("    ", 0) == 0) continue;
		last = l;
	}
	return last.empty() ? trimStr(out) : last;
}

// ---------------------------------------------------------------------
// Verzeichnis lesen
// ---------------------------------------------------------------------
struct LdapEntry {
	std::string dn;
	std::multimap<std::string, std::string> attrs;
	std::string first(const std::string& key) const {
		auto it = attrs.find(key);
		return it == attrs.end() ? std::string() : it->second;
	}
	std::vector<std::string> all(const std::string& key) const {
		std::vector<std::string> out;
		auto range = attrs.equal_range(key);
		for (auto it = range.first; it != range.second; ++it) out.push_back(it->second);
		return out;
	}
};

static std::string g_baseDN;

static std::string detectBaseDN() {
	std::string out;
	if (runAsRootCaptured({ "ldapsearch", "-x", "-LLL", "-o", "ldif-wrap=no", "-H", LDAPI_URL,
	                        "-b", "", "-s", "base", "(objectClass=*)", "defaultNamingContext" }, out) != 0) return "";
	for (auto& line : splitLines(out))
		if (line.rfind("defaultNamingContext: ", 0) == 0) return trimStr(line.substr(22));
	return "";
}

static std::vector<LdapEntry> ldapSearch(const std::string& base, const std::string& scope, const std::string& filter,
                                         const std::vector<std::string>& attrs) {
	std::vector<LdapEntry> out;
	std::vector<std::string> args = { "ldapsearch", "-x", "-LLL", "-o", "ldif-wrap=no", "-H", LDAPI_URL,
	                                  "-b", base, "-s", scope, filter };
	for (auto& a : attrs) args.push_back(a);
	std::string raw;
	if (runAsRootCaptured(args, raw) != 0) return out;
	LdapEntry cur;
	for (auto& line : splitLines(raw)) {
		if (line.empty()) {
			if (!cur.dn.empty()) out.push_back(cur);
			cur = LdapEntry();
			continue;
		}
		size_t colon = line.find(':');
		if (colon == std::string::npos) continue;
		std::string key = line.substr(0, colon);
		std::string val = trimStr(line.substr(colon + 1));
		if (!val.empty() && line[colon + 1] == ':') val = trimStr(line.substr(colon + 2)); // base64 -- hier nicht nötig
		if (key == "dn") cur.dn = val; else cur.attrs.insert({ key, val });
	}
	if (!cur.dn.empty()) out.push_back(cur);
	return out;
}

static std::string sitesDN() { return "CN=Sites,CN=Configuration," + g_baseDN; }

// "CN=Berlin,CN=Sites,..." -> "Berlin"
static std::string dnLeaf(const std::string& dn) {
	size_t eq = dn.find('=');
	if (eq == std::string::npos) return dn;
	size_t comma = dn.find(',', eq);
	return dn.substr(eq + 1, comma == std::string::npos ? std::string::npos : comma - eq - 1);
}

struct SiteInfo {
	std::string dn, name, description;
	std::vector<std::string> servers;   // Namen der Server im Standort
};

struct SubnetInfo {
	std::string dn, name, site, description;
};

struct SiteLinkInfo {
	std::string dn, name, transport;    // IP oder SMTP
	std::vector<std::string> sites;     // Namen der beteiligten Standorte
	int cost = 100;
	int interval = 180;                 // Minuten
};

static std::vector<SiteInfo> listSites() {
	std::vector<SiteInfo> out;
	for (auto& e : ldapSearch(sitesDN(), "one", "(objectClass=site)", { "cn", "description" })) {
		SiteInfo s;
		s.dn = e.dn;
		s.name = e.first("cn");
		s.description = e.first("description");
		for (auto& srv : ldapSearch("CN=Servers," + e.dn, "one", "(objectClass=server)", { "cn" }))
			s.servers.push_back(srv.first("cn"));
		std::sort(s.servers.begin(), s.servers.end());
		out.push_back(s);
	}
	std::sort(out.begin(), out.end(), [](const SiteInfo& a, const SiteInfo& b) { return a.name < b.name; });
	return out;
}

static std::vector<SubnetInfo> listSubnets() {
	std::vector<SubnetInfo> out;
	for (auto& e : ldapSearch("CN=Subnets," + sitesDN(), "one", "(objectClass=subnet)", { "cn", "siteObject", "description" })) {
		SubnetInfo s;
		s.dn = e.dn;
		s.name = e.first("cn");
		std::string site = e.first("siteObject");
		s.site = site.empty() ? "" : dnLeaf(site);
		s.description = e.first("description");
		out.push_back(s);
	}
	std::sort(out.begin(), out.end(), [](const SubnetInfo& a, const SubnetInfo& b) { return a.name < b.name; });
	return out;
}

static std::vector<SiteLinkInfo> listSiteLinks(const std::string& transport) {
	std::vector<SiteLinkInfo> out;
	std::string base = "CN=" + transport + ",CN=Inter-Site Transports," + sitesDN();
	for (auto& e : ldapSearch(base, "one", "(objectClass=siteLink)", { "cn", "siteList", "cost", "replInterval" })) {
		SiteLinkInfo l;
		l.dn = e.dn;
		l.name = e.first("cn");
		l.transport = transport;
		for (auto& s : e.all("siteList")) l.sites.push_back(dnLeaf(s));
		std::sort(l.sites.begin(), l.sites.end());
		std::string cost = e.first("cost"), interval = e.first("replInterval");
		if (!cost.empty()) l.cost = atoi(cost.c_str());
		if (!interval.empty()) l.interval = atoi(interval.c_str());
		out.push_back(l);
	}
	std::sort(out.begin(), out.end(), [](const SiteLinkInfo& a, const SiteLinkInfo& b) { return a.name < b.name; });
	return out;
}

// ---------------------------------------------------------------------
// Ändern
// ---------------------------------------------------------------------
static bool createSite(const std::string& name, FXString& errorMsg) {
	std::string out;
	if (runAsRootCaptured({ "samba-tool", "sites", "create", name }, out) != 0) {
		errorMsg = condenseError(out).c_str();
		return false;
	}
	return true;
}

static bool removeSite(const std::string& name, FXString& errorMsg) {
	std::string out;
	if (runAsRootCaptured({ "samba-tool", "sites", "remove", name }, out) != 0) {
		errorMsg = condenseError(out).c_str();
		return false;
	}
	return true;
}

static bool createSubnet(const std::string& subnet, const std::string& site, FXString& errorMsg) {
	std::string out;
	if (runAsRootCaptured({ "samba-tool", "sites", "subnet", "create", subnet, site }, out) != 0) {
		errorMsg = condenseError(out).c_str();
		return false;
	}
	return true;
}

static bool removeSubnet(const std::string& subnet, FXString& errorMsg) {
	std::string out;
	if (runAsRootCaptured({ "samba-tool", "sites", "subnet", "remove", subnet }, out) != 0) {
		errorMsg = condenseError(out).c_str();
		return false;
	}
	return true;
}

static bool setSubnetSite(const std::string& subnet, const std::string& site, FXString& errorMsg) {
	std::string out;
	if (runAsRootCaptured({ "samba-tool", "sites", "subnet", "set-site", subnet, site }, out) != 0) {
		errorMsg = condenseError(out).c_str();
		return false;
	}
	return true;
}

// samba-tool kennt keine Standortverknüpfungen -- daher direkt über ldb.
static bool applyLdif(const std::string& ldif, FXString& errorMsg) {
	std::string tmp = "/tmp/ice2k-dssite.ldif";
	{
		std::ofstream out(tmp);
		if (!out) { errorMsg = "Temporäre Datei konnte nicht geschrieben werden."; return false; }
		out << ldif;
	}
	std::string out;
	int rc = runAsRootCaptured({ "sh", "-c", std::string("ldbmodify -H ") + SAM_LDB + " " + tmp + " 2>&1" }, out);
	runAsRoot({ "rm", "-f", tmp });
	if (rc != 0) {
		errorMsg = FXString("Die Änderung wurde abgelehnt:\n") + trimStr(out).c_str();
		return false;
	}
	return true;
}

static bool updateSiteLink(const SiteLinkInfo& link, int cost, int interval,
                           const std::vector<std::string>& siteNames, FXString& errorMsg) {
	std::string ldif = "dn: " + link.dn + "\nchangetype: modify\n"
	                   "replace: cost\ncost: " + std::to_string(cost) + "\n-\n"
	                   "replace: replInterval\nreplInterval: " + std::to_string(interval) + "\n-\n"
	                   "replace: siteList\n";
	for (auto& s : siteNames) ldif += "siteList: CN=" + s + "," + sitesDN() + "\n";
	ldif += "\n";
	return applyLdif(ldif, errorMsg);
}

// ---------------------------------------------------------------------
// Dialoge
// ---------------------------------------------------------------------
class NameDialog : public FXDialogBox {
	FXDECLARE(NameDialog)
private:
	FXTextField* field = nullptr;
	FXListBox* box = nullptr;
protected:
	NameDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	// choices leer = nur Eingabefeld; sonst zusätzlich eine Auswahl.
	NameDialog(FXWindow* owner, const FXString& title, const FXString& intro, const FXString& label,
	           const FXString& value, const FXString& choiceLabel = "", const std::vector<std::string>& choices = {})
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,430,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, intro, NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,140,0);
		field = new FXTextField(r, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		field->setText(value);
		if (!choices.empty()) {
			FXHorizontalFrame* r2 = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r2, choiceLabel, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,140,0);
			box = new FXListBox(r2, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
			for (auto& c : choices) box->appendItem(c.c_str());
			box->setNumVisible(std::min<int>(8, (int)choices.size()));
		}
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (trimStr(field->getText().text()).empty()) {
			ice2kui::error(this, MBOX_OK, "Active Directory", "Geben Sie einen Namen an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string value() const { return trimStr(field->getText().text()); }
	std::string choice() const { return box && box->getCurrentItem() >= 0 ? box->getItemText(box->getCurrentItem()).text() : ""; }
	virtual ~NameDialog() {}
};
FXDEFMAP(NameDialog) NameDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NameDialog::ID_OK, NameDialog::onOk),
};
FXIMPLEMENT(NameDialog, FXDialogBox, NameDialogMap, ARRAYNUMBER(NameDialogMap))

// Eigenschaften einer Standortverknüpfung (im Original Reiter "Allgemein").
class SiteLinkDialog : public FXDialogBox {
	FXDECLARE(SiteLinkDialog)
private:
	FXList *available = nullptr, *chosen = nullptr;
	FXSpinner *cost = nullptr, *interval = nullptr;
protected:
	SiteLinkDialog() {}
public:
	enum { ID_ADD = FXDialogBox::ID_LAST, ID_REMOVE, ID_OK };
	SiteLinkDialog(FXWindow* owner, const SiteLinkInfo& link, const std::vector<SiteInfo>& sites)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + link.name.c_str(), DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,480,420) {
		FXVerticalFrame* outer = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(outer, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10, 0,6);
		new FXLabel(page, FXString("Standortverknüpfung ") + link.name.c_str() + " (" + link.transport.c_str() + ")", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* lists = new FXHorizontalFrame(page, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 8,0);
		FXVerticalFrame* left = new FXVerticalFrame(lists, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,2);
		new FXLabel(left, "Standorte &außerhalb dieser Verknüpfung:", NULL, JUSTIFY_LEFT);
		FXPacker* lf = new FXPacker(left, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		available = new FXList(lf, NULL, 0, LIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXVerticalFrame* mid = new FXVerticalFrame(lists, LAYOUT_CENTER_Y | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,0,0, 0,4);
		new FXButton(mid, "&Hinzufügen >>", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);
		new FXButton(mid, "<< &Entfernen", NULL, this, ID_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);
		FXVerticalFrame* right = new FXVerticalFrame(lists, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,2);
		new FXLabel(right, "Standorte in &dieser Verknüpfung:", NULL, JUSTIFY_LEFT);
		FXPacker* rf = new FXPacker(right, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		chosen = new FXList(rf, NULL, 0, LIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		for (auto& s : sites) {
			if (std::find(link.sites.begin(), link.sites.end(), s.name) != link.sites.end()) chosen->appendItem(s.name.c_str());
			else available->appendItem(s.name.c_str());
		}
		FXMatrix* m = new FXMatrix(page, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,6,0, 10,4);
		new FXLabel(m, "&Kosten:", NULL, JUSTIFY_LEFT);
		cost = new FXSpinner(m, 6, NULL, 0, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		cost->setRange(1, 32767);
		cost->setValue(link.cost);
		new FXLabel(m, "&Replizieren alle (Minuten):", NULL, JUSTIFY_LEFT);
		interval = new FXSpinner(m, 6, NULL, 0, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		interval->setRange(15, 10080);
		interval->setValue(link.interval);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(outer, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onAdd(FXObject*, FXSelector, void*) {
		int i = available->getCurrentItem();
		if (i < 0) return 1;
		chosen->appendItem(available->getItemText(i));
		available->removeItem(i);
		return 1;
	}
	long onRemove(FXObject*, FXSelector, void*) {
		int i = chosen->getCurrentItem();
		if (i < 0) return 1;
		available->appendItem(chosen->getItemText(i));
		chosen->removeItem(i);
		return 1;
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (chosen->getNumItems() < 2) {
			ice2kui::error(this, MBOX_OK, "Standortverknüpfung",
				"Eine Standortverknüpfung muss mindestens zwei Standorte verbinden.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	int costValue() const { return cost->getValue(); }
	int intervalValue() const { return interval->getValue(); }
	std::vector<std::string> siteNames() const {
		std::vector<std::string> out;
		for (int i = 0; i < chosen->getNumItems(); i++) out.push_back(chosen->getItemText(i).text());
		return out;
	}
	virtual ~SiteLinkDialog() {}
};
FXDEFMAP(SiteLinkDialog) SiteLinkDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, SiteLinkDialog::ID_ADD, SiteLinkDialog::onAdd),
	FXMAPFUNC(SEL_COMMAND, SiteLinkDialog::ID_REMOVE, SiteLinkDialog::onRemove),
	FXMAPFUNC(SEL_COMMAND, SiteLinkDialog::ID_OK, SiteLinkDialog::onOk),
};
FXIMPLEMENT(SiteLinkDialog, FXDialogBox, SiteLinkDialogMap, ARRAYNUMBER(SiteLinkDialogMap))

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
enum NodeKind { NK_ROOT, NK_SITE, NK_SERVERS, NK_SERVER, NK_SUBNETS, NK_TRANSPORTS, NK_TRANSPORT };

struct NodeInfo {
	NodeKind kind = NK_ROOT;
	std::string name;       // Standort-, Server- oder Transportname
	std::string site;       // zugehöriger Standort
};

class DsSiteWindow : public FXMainWindow {
	FXDECLARE(DsSiteWindow)
private:
	FXTreeList* tree = nullptr;
	FXIconList* list = nullptr;
	FXLabel* statusbar = nullptr;
	FXIcon *icoRoot = nullptr, *icoSite = nullptr, *icoFolder = nullptr, *icoServer = nullptr, *icoLink = nullptr;
	std::vector<SiteInfo> sites;
	std::vector<SubnetInfo> subnets;
	std::vector<SiteLinkInfo> ipLinks, smtpLinks;
	std::map<FXTreeItem*, NodeInfo> nodes;
	FXTreeItem* rootItem = nullptr;
protected:
	DsSiteWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_NEW_SITE, ID_DELETE_SITE, ID_NEW_SUBNET,
	       ID_DELETE_SUBNET, ID_SUBNET_SITE, ID_PROPERTIES, ID_REFRESH, ID_ABOUT };

	DsSiteWindow(FXApp* a);
	virtual void create();
	long onTree(FXObject*, FXSelector, void*);
	long onTreeRight(FXObject*, FXSelector, void*);
	long onListRight(FXObject*, FXSelector, void*);
	long onListDouble(FXObject*, FXSelector, void*);
	long onNewSite(FXObject*, FXSelector, void*);
	long onDeleteSite(FXObject*, FXSelector, void*);
	long onNewSubnet(FXObject*, FXSelector, void*);
	long onDeleteSubnet(FXObject*, FXSelector, void*);
	long onSubnetSite(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	void reload();
	void showFor(FXTreeItem* item);
	NodeInfo currentNode();
	std::vector<std::string> siteNames() const;
	virtual ~DsSiteWindow() {}
};

FXDEFMAP(DsSiteWindow) DsSiteWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, DsSiteWindow::ID_TREE, DsSiteWindow::onTree),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, DsSiteWindow::ID_TREE, DsSiteWindow::onTreeRight),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, DsSiteWindow::ID_LIST, DsSiteWindow::onListRight),
	FXMAPFUNC(SEL_DOUBLECLICKED, DsSiteWindow::ID_LIST, DsSiteWindow::onListDouble),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_NEW_SITE, DsSiteWindow::onNewSite),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_DELETE_SITE, DsSiteWindow::onDeleteSite),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_NEW_SUBNET, DsSiteWindow::onNewSubnet),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_DELETE_SUBNET, DsSiteWindow::onDeleteSubnet),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_SUBNET_SITE, DsSiteWindow::onSubnetSite),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_PROPERTIES, DsSiteWindow::onProperties),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_REFRESH, DsSiteWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DsSiteWindow::ID_ABOUT, DsSiteWindow::onAbout),
};
FXIMPLEMENT(DsSiteWindow, FXMainWindow, DsSiteWindowMap, ARRAYNUMBER(DsSiteWindowMap))

DsSiteWindow::DsSiteWindow(FXApp* a)
	: FXMainWindow(a, "Active Directory-Standorte und -Dienste", NULL, NULL, DECOR_ALL, 0,0, 900,560) {
	icoRoot = new FXPNGIcon(a, resico_network, IMAGE_NEAREST);
	icoSite = new FXPNGIcon(a, resico_server, IMAGE_NEAREST);
	icoFolder = new FXPNGIcon(a, resico_folder, IMAGE_NEAREST);
	icoServer = new FXPNGIcon(a, resico_server, IMAGE_NEAREST);
	icoLink = new FXPNGIcon(a, resico_network, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoSite, icoFolder, icoServer, icoLink }) i->create();

	FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	FXMenuPane* vorgang = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
	new FXMenuCommand(vorgang, "Neuer &Standort...", NULL, this, ID_NEW_SITE);
	new FXMenuCommand(vorgang, "Neues S&ubnetz...", NULL, this, ID_NEW_SUBNET);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Eigenschaften", NULL, this, ID_PROPERTIES);
	FXMenuPane* ansicht = new FXMenuPane(this);
	new FXMenuTitle(menubar, "A&nsicht", NULL, ansicht);
	new FXMenuCommand(ansicht, "&Aktualisieren", NULL, this, ID_REFRESH);
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
	tb("\tEigenschaften", gif(resico_mmc_properties), ID_PROPERTIES);
	tb("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
	tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	new FXToolTip(getApp());

	statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);

	FXSplitter* splitter = new FXSplitter(this, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,320,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
	FXPacker* listframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(listframe, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
}

void DsSiteWindow::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

std::vector<std::string> DsSiteWindow::siteNames() const {
	std::vector<std::string> out;
	for (auto& s : sites) out.push_back(s.name);
	return out;
}

void DsSiteWindow::reload() {
	getApp()->beginWaitCursor();
	sites = listSites();
	subnets = listSubnets();
	ipLinks = listSiteLinks("IP");
	smtpLinks = listSiteLinks("SMTP");
	getApp()->endWaitCursor();

	// Auswahl merken
	NodeInfo sel = nodes.count(tree->getCurrentItem()) ? nodes[tree->getCurrentItem()] : NodeInfo();
	tree->clearItems();
	nodes.clear();
	rootItem = tree->appendItem(0, "Active Directory-Standorte und -Dienste", icoRoot, icoRoot);
	nodes[rootItem] = { NK_ROOT, "", "" };
	FXTreeItem* selectItem = rootItem;
	for (auto& s : sites) {
		FXTreeItem* si = tree->appendItem(rootItem, s.name.c_str(), icoSite, icoSite);
		nodes[si] = { NK_SITE, s.name, s.name };
		FXTreeItem* servers = tree->appendItem(si, "Servers", icoFolder, icoFolder);
		nodes[servers] = { NK_SERVERS, "Servers", s.name };
		for (auto& srv : s.servers) {
			FXTreeItem* item = tree->appendItem(servers, srv.c_str(), icoServer, icoServer);
			nodes[item] = { NK_SERVER, srv, s.name };
			if (sel.kind == NK_SERVER && sel.name == srv) selectItem = item;
		}
		tree->expandTree(si);
		if (sel.kind == NK_SITE && sel.name == s.name) selectItem = si;
		if (sel.kind == NK_SERVERS && sel.site == s.name) selectItem = servers;
	}
	FXTreeItem* subnetsItem = tree->appendItem(rootItem, "Subnets", icoFolder, icoFolder);
	nodes[subnetsItem] = { NK_SUBNETS, "Subnets", "" };
	if (sel.kind == NK_SUBNETS) selectItem = subnetsItem;
	FXTreeItem* transports = tree->appendItem(rootItem, "Inter-Site Transports", icoFolder, icoFolder);
	nodes[transports] = { NK_TRANSPORTS, "Inter-Site Transports", "" };
	for (const char* t : { "IP", "SMTP" }) {
		FXTreeItem* item = tree->appendItem(transports, t, icoLink, icoLink);
		nodes[item] = { NK_TRANSPORT, t, "" };
		if (sel.kind == NK_TRANSPORT && sel.name == t) selectItem = item;
	}
	tree->expandTree(rootItem);
	tree->expandTree(transports);
	tree->setCurrentItem(selectItem);
	tree->selectItem(selectItem);
	showFor(selectItem);
}

NodeInfo DsSiteWindow::currentNode() {
	auto it = nodes.find(tree->getCurrentItem());
	return it == nodes.end() ? NodeInfo() : it->second;
}

void DsSiteWindow::showFor(FXTreeItem* item) {
	while (list->getNumHeaders() > 0) list->removeHeader(0);
	list->clearItems();
	NodeInfo n = nodes.count(item) ? nodes[item] : NodeInfo();
	switch (n.kind) {
		case NK_ROOT:
			list->appendHeader("Name", NULL, 240);
			list->appendHeader("Typ", NULL, 160);
			list->appendHeader("Beschreibung", NULL, 260);
			for (auto& s : sites) list->appendItem(FXString(s.name.c_str()) + "\tStandort\t" + s.description.c_str(), icoSite, icoSite);
			list->appendItem("Subnets\tSubnetz-Container\t", icoFolder, icoFolder);
			list->appendItem("Inter-Site Transports\tTransport-Container\t", icoFolder, icoFolder);
			statusbar->setText(FXString(" ") + FXString(std::to_string(sites.size()).c_str()) + " Standort(e)");
			break;
		case NK_SITE: {
			list->appendHeader("Name", NULL, 240);
			list->appendHeader("Typ", NULL, 200);
			list->appendItem("Servers\tServer-Container\t", icoFolder, icoFolder);
			list->appendItem("NTDS Site Settings\tStandorteinstellungen\t", icoFolder, icoFolder);
			int count = 0;
			for (auto& s : sites) if (s.name == n.site) count = (int)s.servers.size();
			statusbar->setText(FXString(" Standort ") + n.name.c_str() + " -- " + FXString(std::to_string(count).c_str()) + " Server");
			break;
		}
		case NK_SERVERS:
		case NK_SERVER: {
			list->appendHeader("Name", NULL, 240);
			list->appendHeader("Typ", NULL, 200);
			for (auto& s : sites)
				if (s.name == n.site)
					for (auto& srv : s.servers) list->appendItem(FXString(srv.c_str()) + "\tServer", icoServer, icoServer);
			statusbar->setText(FXString(" Server im Standort ") + n.site.c_str());
			break;
		}
		case NK_SUBNETS:
			list->appendHeader("Name", NULL, 200);
			list->appendHeader("Standort", NULL, 200);
			list->appendHeader("Beschreibung", NULL, 260);
			for (auto& s : subnets)
				list->appendItem(FXString(s.name.c_str()) + "\t" + (s.site.empty() ? "-" : s.site.c_str()) + "\t" + s.description.c_str(), icoFolder, icoFolder);
			statusbar->setText(subnets.empty()
				? " Kein Subnetz eingetragen. Rechtsklick: Neues Subnetz."
				: FXString(" ") + FXString(std::to_string(subnets.size()).c_str()) + " Subnetz(e)");
			break;
		case NK_TRANSPORTS:
			list->appendHeader("Name", NULL, 200);
			list->appendHeader("Typ", NULL, 240);
			list->appendItem("IP\tTransport", icoLink, icoLink);
			list->appendItem("SMTP\tTransport", icoLink, icoLink);
			statusbar->setText(" Transporte für die Replikation zwischen Standorten");
			break;
		case NK_TRANSPORT: {
			list->appendHeader("Name", NULL, 200);
			list->appendHeader("Standorte", NULL, 260);
			list->appendHeader("Kosten", NULL, 80);
			list->appendHeader("Replikation alle (Min.)", NULL, 160);
			const std::vector<SiteLinkInfo>& links = n.name == "IP" ? ipLinks : smtpLinks;
			for (auto& l : links) {
				FXString siteList;
				for (auto& s : l.sites) { if (!siteList.empty()) siteList += ", "; siteList += s.c_str(); }
				list->appendItem(FXString(l.name.c_str()) + "\t" + siteList + "\t" +
				                 FXString(std::to_string(l.cost).c_str()) + "\t" +
				                 FXString(std::to_string(l.interval).c_str()), icoLink, icoLink);
			}
			statusbar->setText(links.empty()
				? FXString(" Keine Standortverknüpfung über ") + n.name.c_str()
				: FXString(" Doppelklick öffnet die Eigenschaften einer Standortverknüpfung."));
			break;
		}
	}
}

long DsSiteWindow::onTree(FXObject*, FXSelector, void*) { showFor(tree->getCurrentItem()); return 1; }

long DsSiteWindow::onTreeRight(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);
	showFor(item);
	NodeInfo n = currentNode();
	FXMenuPane menu(this);
	if (n.kind == NK_ROOT) new FXMenuCommand(&menu, "Neuer &Standort...", NULL, this, ID_NEW_SITE);
	else if (n.kind == NK_SITE) {
		new FXMenuCommand(&menu, "Neuer &Standort...", NULL, this, ID_NEW_SITE);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_SITE);
	} else if (n.kind == NK_SUBNETS) new FXMenuCommand(&menu, "Neues S&ubnetz...", NULL, this, ID_NEW_SUBNET);
	new FXMenuSeparator(&menu);
	new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DsSiteWindow::onListRight(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx >= 0) { list->setCurrentItem(idx); list->selectItem(idx); }
	NodeInfo n = currentNode();
	FXMenuPane menu(this);
	if (n.kind == NK_SUBNETS) {
		new FXMenuCommand(&menu, "Neues S&ubnetz...", NULL, this, ID_NEW_SUBNET);
		if (idx >= 0) {
			new FXMenuCommand(&menu, "&Standort zuweisen...", NULL, this, ID_SUBNET_SITE);
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_SUBNET);
		}
	} else if (n.kind == NK_ROOT) {
		new FXMenuCommand(&menu, "Neuer &Standort...", NULL, this, ID_NEW_SITE);
		if (idx >= 0 && idx < (int)sites.size()) {
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_SITE);
		}
	} else if (n.kind == NK_TRANSPORT && idx >= 0) {
		new FXMenuCommand(&menu, "Ei&genschaften", NULL, this, ID_PROPERTIES);
	} else {
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DsSiteWindow::onListDouble(FXObject*, FXSelector, void*) { return onProperties(NULL, 0, NULL); }

long DsSiteWindow::onNewSite(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Active Directory", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	NameDialog dlg(this, "Neues Objekt - Standort",
		"Ein Standort fasst die Computer eines gut angebundenen Netzwerks zusammen.\n"
		"Subnetze ordnen die Clients dem Standort zu.", "&Name:", "");
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!createSite(dlg.value(), errorMsg)) ice2kui::error(this, MBOX_OK, "Neuer Standort", "%s", errorMsg.text());
	reload();
	return 1;
}

long DsSiteWindow::onDeleteSite(FXObject*, FXSelector, void*) {
	NodeInfo n = currentNode();
	std::string name = n.kind == NK_SITE ? n.name : "";
	if (name.empty()) {
		int idx = list->getCurrentItem();
		if (idx >= 0 && idx < (int)sites.size()) name = sites[idx].name;
	}
	if (name.empty()) return 1;
	if (ice2kui::question(this, MBOX_YES_NO, "Active Directory",
	        "Möchten Sie den Standort \"%s\" wirklich löschen?", name.c_str()) != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	if (!removeSite(name, errorMsg)) ice2kui::error(this, MBOX_OK, "Standort löschen", "%s", errorMsg.text());
	reload();
	return 1;
}

long DsSiteWindow::onNewSubnet(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Active Directory", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	if (sites.empty()) { ice2kui::error(this, MBOX_OK, "Neues Subnetz", "Es gibt noch keinen Standort."); return 1; }
	NameDialog dlg(this, "Neues Objekt - Subnetz",
		"Das Subnetz ordnet einen Adressbereich einem Standort zu.\n"
		"Schreibweise wie 192.168.5.0/24.", "&Adresse:", "", "&Standort:", siteNames());
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!createSubnet(dlg.value(), dlg.choice(), errorMsg)) ice2kui::error(this, MBOX_OK, "Neues Subnetz", "%s", errorMsg.text());
	reload();
	return 1;
}

long DsSiteWindow::onDeleteSubnet(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (currentNode().kind != NK_SUBNETS || idx < 0 || idx >= (int)subnets.size()) return 1;
	if (ice2kui::question(this, MBOX_YES_NO, "Active Directory",
	        "Möchten Sie das Subnetz \"%s\" wirklich löschen?", subnets[idx].name.c_str()) != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	if (!removeSubnet(subnets[idx].name, errorMsg)) ice2kui::error(this, MBOX_OK, "Subnetz löschen", "%s", errorMsg.text());
	reload();
	return 1;
}

long DsSiteWindow::onSubnetSite(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (currentNode().kind != NK_SUBNETS || idx < 0 || idx >= (int)subnets.size()) return 1;
	NameDialog dlg(this, "Standort zuweisen",
		FXString("Zu welchem Standort gehört das Subnetz ") + subnets[idx].name.c_str() + "?",
		"&Subnetz:", subnets[idx].name.c_str(), "&Standort:", siteNames());
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!setSubnetSite(subnets[idx].name, dlg.choice(), errorMsg)) ice2kui::error(this, MBOX_OK, "Standort zuweisen", "%s", errorMsg.text());
	reload();
	return 1;
}

long DsSiteWindow::onProperties(FXObject*, FXSelector, void*) {
	NodeInfo n = currentNode();
	if (n.kind != NK_TRANSPORT) return 1;
	std::vector<SiteLinkInfo>& links = n.name == "IP" ? ipLinks : smtpLinks;
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)links.size()) return 1;
	SiteLinkDialog dlg(this, links[idx], sites);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Active Directory", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	FXString errorMsg;
	if (!updateSiteLink(links[idx], dlg.costValue(), dlg.intervalValue(), dlg.siteNames(), errorMsg))
		ice2kui::error(this, MBOX_OK, "Standortverknüpfung", "%s", errorMsg.text());
	reload();
	return 1;
}

long DsSiteWindow::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }

long DsSiteWindow::onAbout(FXObject*, FXSelector, void*) {
	ice2kui::information(this, MBOX_OK, "Info",
		"Active Directory-Standorte und -Dienste (ice2k)\n\n"
		"Standorte, Server, Subnetze und Standortverknüpfungen aus\n"
		"CN=Sites,CN=Configuration. Geändert wird über samba-tool sites;\n"
		"Standortverknüpfungen über ldbmodify.");
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("DsSite", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	g_haveRoot = (runAsRoot({ "true" }) == 0);
	g_baseDN = detectBaseDN();
	DsSiteWindow* win = new DsSiteWindow(&application);
	application.create();
	if (g_baseDN.empty())
		ice2kui::error(win, MBOX_OK, "Active Directory",
			"Der Verzeichnisdienst ist nicht erreichbar.\n\n"
			"Prüfen Sie, ob der Domänencontroller läuft:\n    systemctl status samba-ad-dc");
	else if (!g_haveRoot)
		ice2kui::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\nDie Anzeige funktioniert, Änderungen sind nicht möglich.");
	return application.run();
}
