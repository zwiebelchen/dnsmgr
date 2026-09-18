// rras.cpp
//
// "Routing und RAS" fuer ice2k -- Nachbau des gleichnamigen Snap-Ins von
// Windows 2000 Server. Aufbau wie im Original: links der Baum mit
// "Serverstatus" und dem lokalen Server, rechts der Startbildschirm bzw.
// die Serverstatusliste.
//
// Unterbau ist der Linux-Kernel: "Routing und RAS konfigurieren und
// aktivieren" schaltet die IP-Weiterleitung ein (sofort per sysctl und
// dauerhaft ueber /etc/sysctl.d), "deaktivieren" wieder aus. Der
// gewaehlte Serverrolle merkt sich /etc/ice2k/rras.conf, damit die
// Konsole beim naechsten Start weiss, was eingerichtet wurde.
//
// Noch nicht umgesetzt: Einwaehl- und VPN-Server (Ports, Schnittstellen,
// Richtlinien) sowie NAT -- die Konsole sagt das an den betreffenden
// Stellen ausdruecklich, statt etwas vorzutaeuschen.

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "../common/svcprobe/svcprobe.h"

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/wait.h>

static FXApp* app = NULL;
static bool g_haveRoot = false;

static const char* RRAS_CONF = "/etc/ice2k/rras.conf";
static const char* RRAS_SYSCTL = "/etc/sysctl.d/99-ice2k-rras.conf";

// ---------------------------------------------------------------------
// Root-Aufrufe wie in den anderen ice2k-Programmen ueber i2ksudo.
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
	close(pipefd[0]);
	close(pipefd[1]);
	return -1;
}

static svcprobe::Runner rootRunner() {
	return [](const std::vector<std::string>& args, std::string& out) {
		std::vector<FXString> a;
		for (auto& s : args) a.push_back(FXString(s.c_str()));
		return runAsRootCaptured(a, out);
	};
}

// Schreibt "content" als root nach "path" (erst in eine Temp-Datei, dann
// kopieren -- so laeuft die GUI selbst nicht als root).
static bool writeFileAsRoot(const std::string& path, const std::string& content, FXString& errorMsg) {
	FXString tmp = "/tmp/ice2k-rras.tmp";
	{
		std::ofstream out(tmp.text(), std::ios::binary);
		if (!out) { errorMsg = "Temporäre Datei konnte nicht geschrieben werden."; return false; }
		out << content;
	}
	std::string slash = path.substr(0, path.find_last_of('/'));
	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString(slash.c_str()) });
	std::string out;
	int rc = runAsRootCaptured({ FXString("cp"), tmp, FXString(path.c_str()) }, out);
	runAsRoot({ FXString("rm"), FXString("-f"), tmp });
	if (rc != 0) {
		errorMsg = FXString("Datei konnte nicht geschrieben werden:\n") + path.c_str() + "\n\n" + svcprobe::trimmed(out).c_str();
		return false;
	}
	return true;
}

static std::string readFileUnprivileged(const char* path) {
	std::ifstream in(path);
	if (!in) return "";
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
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

// ---------------------------------------------------------------------
// Zustand: Serverrolle und IP-Weiterleitung.
// ---------------------------------------------------------------------
enum ServerRole { ROLE_NONE = 0, ROLE_ROUTER_LAN, ROLE_ROUTER_DIALUP, ROLE_MANUAL };

struct RrasState {
	ServerRole role = ROLE_NONE;
	bool forwarding = false;    // net.ipv4.ip_forward des laufenden Systems
	bool configured() const { return role != ROLE_NONE; }
};

static RrasState readState() {
	RrasState st;
	for (auto& line : splitLines(readFileUnprivileged(RRAS_CONF))) {
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		std::string key = svcprobe::trimmed(line.substr(0, eq));
		std::string val = svcprobe::trimmed(line.substr(eq + 1));
		if (key != "role") continue;
		if (val == "router-lan") st.role = ROLE_ROUTER_LAN;
		else if (val == "router-dialup") st.role = ROLE_ROUTER_DIALUP;
		else if (val == "manual") st.role = ROLE_MANUAL;
	}
	st.forwarding = svcprobe::trimmed(readFileUnprivileged("/proc/sys/net/ipv4/ip_forward")) == "1";
	return st;
}

static const char* roleKeyword(ServerRole r) {
	return r == ROLE_ROUTER_LAN ? "router-lan" : r == ROLE_ROUTER_DIALUP ? "router-dialup" : r == ROLE_MANUAL ? "manual" : "none";
}

static FXString roleLabel(ServerRole r) {
	return r == ROLE_ROUTER_LAN ? "Netzwerkrouter (nur lokales Netzwerk)"
	     : r == ROLE_ROUTER_DIALUP ? "Netzwerkrouter (LAN- und Einwählrouting)"
	     : r == ROLE_MANUAL ? "Manuell konfigurierter Server"
	                        : "Nicht konfiguriert";
}

// Schaltet die IP-Weiterleitung sofort und dauerhaft.
static bool applyForwarding(bool on, FXString& errorMsg) {
	std::string sysctl = "# Von ice2k \"Routing und RAS\" verwaltet.\n"
	                     "net.ipv4.ip_forward = " + std::string(on ? "1" : "0") + "\n";
	if (!writeFileAsRoot(RRAS_SYSCTL, sysctl, errorMsg)) return false;
	std::string out;
	if (runAsRootCaptured({ FXString("sysctl"), FXString("-w"),
	                        FXString((std::string("net.ipv4.ip_forward=") + (on ? "1" : "0")).c_str()) }, out) != 0) {
		errorMsg = FXString("Die IP-Weiterleitung konnte nicht umgeschaltet werden:\n") + svcprobe::trimmed(out).c_str();
		return false;
	}
	return true;
}

static bool writeState(const RrasState& st, FXString& errorMsg) {
	std::string conf = "# Von ice2k \"Routing und RAS\" verwaltet.\n"
	                   "role = " + std::string(roleKeyword(st.role)) + "\n";
	return writeFileAsRoot(RRAS_CONF, conf, errorMsg);
}

// Anzeigename des Systems, wie ihn das Original als "Servertyp" zeigt.
static FXString serverType() {
	for (auto& line : splitLines(readFileUnprivileged("/etc/os-release"))) {
		if (line.rfind("PRETTY_NAME=", 0) != 0) continue;
		std::string v = line.substr(12);
		if (v.size() >= 2 && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
		return v.c_str();
	}
	return "Linux";
}

static FXString hostName() {
	char buf[256] = { 0 };
	if (gethostname(buf, sizeof(buf) - 1) != 0) return "localhost";
	FXString h = buf;
	int dot = h.find('.');
	if (dot > 0) h = h.left(dot);
	h.upper();
	return h;
}

// ---------------------------------------------------------------------
// Dialog "Routing und RAS konfigurieren und aktivieren" -- im Original
// ein Assistent; hier eine Seite mit denselben Serverrollen.
// ---------------------------------------------------------------------
class ConfigureDialog : public FXDialogBox {
	FXDECLARE(ConfigureDialog)
private:
	FXint choice = 3;   // Vorauswahl: Netzwerkrouter
	FXDataTarget choiceTarget;
	FXLabel* description = nullptr;
protected:
	ConfigureDialog() {}
public:
	enum { ID_CHOICE = FXDialogBox::ID_LAST, ID_OK };
	// Reihenfolge wie im Assistenten von Windows 2000.
	enum { C_INTERNET = 0, C_RAS = 1, C_VPN = 2, C_ROUTER = 3, C_MANUAL = 4 };

	ConfigureDialog(FXWindow* owner)
		: FXDialogBox(owner, "Setup-Assistent für den Routing- und RAS-Server", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,520,0),
		  choiceTarget(choice, this, ID_CHOICE) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Allgemeine Konfigurationen", NULL, JUSTIFY_LEFT);
		new FXLabel(main, "Sie können den Server mit einer der folgenden Konfigurationen einrichten.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* radios = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 12,0,4,4, 0,4);
		new FXRadioButton(radios, "&Internetverbindungsserver", &choiceTarget, FXDataTarget::ID_OPTION + C_INTERNET);
		new FXRadioButton(radios, "&RAS-Server", &choiceTarget, FXDataTarget::ID_OPTION + C_RAS);
		new FXRadioButton(radios, "&VPN-Server (Virtuelles privates Netzwerk)", &choiceTarget, FXDataTarget::ID_OPTION + C_VPN);
		new FXRadioButton(radios, "&Netzwerkrouter", &choiceTarget, FXDataTarget::ID_OPTION + C_ROUTER);
		new FXRadioButton(radios, "&Manuell konfigurierter Server", &choiceTarget, FXDataTarget::ID_OPTION + C_MANUAL);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		description = new FXLabel(main, "", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "&Fertig stellen", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		onChoice(NULL, 0, NULL);
	}

	long onChoice(FXObject*, FXSelector, void*) {
		switch (choice) {
			case C_INTERNET: description->setText("Verbindet dieses Netzwerk über eine gemeinsame Verbindung mit dem Internet.\n"
			                                      "Noch nicht umgesetzt (dafür wären Adressumsetzung und Firewallregeln nötig)."); break;
			case C_RAS: description->setText("Nimmt Einwählverbindungen entgegen.\n"
			                                 "Noch nicht umgesetzt."); break;
			case C_VPN: description->setText("Nimmt VPN-Verbindungen aus dem Internet entgegen.\n"
			                                 "Noch nicht umgesetzt."); break;
			case C_ROUTER: description->setText("Leitet Pakete zwischen den Netzwerken dieses Servers weiter.\n"
			                                    "Schaltet die IP-Weiterleitung des Kernels ein."); break;
			default: description->setText("Aktiviert Routing und RAS, ohne weitere Einstellungen vorzunehmen.\n"
			                              "Schaltet die IP-Weiterleitung des Kernels ein."); break;
		}
		return 1;
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (choice == C_INTERNET || choice == C_RAS || choice == C_VPN) {
			FXMessageBox::information(this, MBOX_OK, "Routing und RAS",
				"Diese Serverrolle ist noch nicht umgesetzt.\n\n"
				"Umgesetzt sind bisher \"Netzwerkrouter\" und \"Manuell konfigurierter Server\";\n"
				"beide schalten die IP-Weiterleitung ein.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	ServerRole role() const { return choice == C_ROUTER ? ROLE_ROUTER_LAN : ROLE_MANUAL; }
	virtual ~ConfigureDialog() {}
};
FXDEFMAP(ConfigureDialog) ConfigureDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, ConfigureDialog::ID_CHOICE, ConfigureDialog::onChoice),
	FXMAPFUNC(SEL_COMMAND, ConfigureDialog::ID_OK, ConfigureDialog::onOk),
};
FXIMPLEMENT(ConfigureDialog, FXDialogBox, ConfigureDialogMap, ARRAYNUMBER(ConfigureDialogMap))

// ---------------------------------------------------------------------
// Eigenschaften des Servers -- Reiter "Allgemein" wie im Original.
// ---------------------------------------------------------------------
class ServerPropertiesDialog : public FXDialogBox {
	FXDECLARE(ServerPropertiesDialog)
private:
	FXCheckButton* routerCheck = nullptr;
	FXint routing = 0;   // 0 = nur lokales Netzwerk, 1 = LAN- und Einwählrouting
	FXDataTarget routingTarget;
	std::vector<FXWindow*> routerControls;
protected:
	ServerPropertiesDialog() {}
public:
	enum { ID_ROUTER = FXDialogBox::ID_LAST };
	ServerPropertiesDialog(FXWindow* owner, const FXString& serverName, const RrasState& st)
		: FXDialogBox(owner, "Eigenschaften von " + serverName, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0),
		  routing(st.role == ROLE_ROUTER_DIALUP ? 1 : 0), routingTarget(routing) {
		FXVerticalFrame* outer = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 6,6,6,6, 0,6);
		FXTabBook* tabs = new FXTabBook(outer, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(page, "Diesen Computer aktivieren als:", NULL, JUSTIFY_LEFT);
		routerCheck = new FXCheckButton(page, "&Router", this, ID_ROUTER);
		routerCheck->setCheck(st.role != ROLE_NONE);
		FXVerticalFrame* sub = new FXVerticalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 20,0,0,0, 0,4);
		routerControls.push_back(new FXRadioButton(sub, "&Nur lokales Netzwerk (LAN-Routing)", &routingTarget, FXDataTarget::ID_OPTION + 0));
		routerControls.push_back(new FXRadioButton(sub, "LAN- und &Einwählrouting", &routingTarget, FXDataTarget::ID_OPTION + 1));
		(new FXCheckButton(page, "R&AS-Server"))->disable();
		new FXLabel(page, "Einwähl- und VPN-Verbindungen sind noch nicht umgesetzt.", NULL, JUSTIFY_LEFT);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(outer, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		updateEnabled();
	}
	void updateEnabled() {
		for (auto* w : routerControls) { if (routerCheck->getCheck()) w->enable(); else w->disable(); }
	}
	long onRouter(FXObject*, FXSelector, void*) { updateEnabled(); return 1; }
	ServerRole role() const {
		if (!routerCheck->getCheck()) return ROLE_NONE;
		return routing ? ROLE_ROUTER_DIALUP : ROLE_ROUTER_LAN;
	}
	virtual ~ServerPropertiesDialog() {}
};
FXDEFMAP(ServerPropertiesDialog) ServerPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, ServerPropertiesDialog::ID_ROUTER, ServerPropertiesDialog::onRouter),
};
FXIMPLEMENT(ServerPropertiesDialog, FXDialogBox, ServerPropertiesDialogMap, ARRAYNUMBER(ServerPropertiesDialogMap))

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
class RrasWindow : public FXMainWindow {
	FXDECLARE(RrasWindow)
private:
	FXMenuBar* menubar = nullptr;
	FXToolBar* toolbar = nullptr;
	FXMenuPane *vorgangmenu = nullptr, *ansichtmenu = nullptr, *hilfemenu = nullptr;
	FXTreeList* tree = nullptr;
	FXSwitcher* rightPane = nullptr;
	FXIconList* statusList = nullptr;
	FXLabel* welcomeTitle = nullptr, *welcomeText = nullptr;
	FXLabel* statusbar = nullptr;
	FXTreeItem *rootItem = nullptr, *statusItem = nullptr, *serverItem = nullptr;
	FXIcon *icoRoot = nullptr, *icoStatus = nullptr, *icoServer = nullptr, *icoInfo = nullptr;
	RrasState state;
protected:
	RrasWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_CONFIGURE, ID_DEACTIVATE, ID_PROPERTIES, ID_REFRESH, ID_ABOUT };

	RrasWindow(FXApp* a);
	virtual void create();

	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onConfigure(FXObject*, FXSelector, void*);
	long onDeactivate(FXObject*, FXSelector, void*);
	long onUpdDeactivate(FXObject*, FXSelector, void*);
	long onUpdConfigure(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);

	void reload();
	void showFor(FXTreeItem* item);
	virtual ~RrasWindow() {}
};

FXDEFMAP(RrasWindow) RrasWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, RrasWindow::ID_TREE, RrasWindow::onTreeChanged),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, RrasWindow::ID_TREE, RrasWindow::onTreeRightClick),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_CONFIGURE, RrasWindow::onConfigure),
	FXMAPFUNC(SEL_UPDATE, RrasWindow::ID_CONFIGURE, RrasWindow::onUpdConfigure),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_DEACTIVATE, RrasWindow::onDeactivate),
	FXMAPFUNC(SEL_UPDATE, RrasWindow::ID_DEACTIVATE, RrasWindow::onUpdDeactivate),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_PROPERTIES, RrasWindow::onProperties),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_REFRESH, RrasWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_ABOUT, RrasWindow::onAbout),
};
FXIMPLEMENT(RrasWindow, FXMainWindow, RrasWindowMap, ARRAYNUMBER(RrasWindowMap))

RrasWindow::RrasWindow(FXApp* a)
	: FXMainWindow(a, "Routing und RAS", NULL, NULL, DECOR_ALL, 0,0, 900,560) {
	icoRoot = new FXGIFIcon(a, resico_rras);
	icoStatus = new FXPNGIcon(a, resico_server, IMAGE_NEAREST);
	icoServer = new FXPNGIcon(a, resico_network, IMAGE_NEAREST);
	icoInfo = new FXPNGIcon(a, resico_key, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoStatus, icoServer, icoInfo }) i->create();

	menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	vorgangmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgangmenu);
	new FXMenuCommand(vorgangmenu, "Routing und RAS &konfigurieren und aktivieren", NULL, this, ID_CONFIGURE);
	new FXMenuCommand(vorgangmenu, "Routing und RAS &deaktivieren", NULL, this, ID_DEACTIVATE);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Eigenschaften", NULL, this, ID_PROPERTIES);
	ansichtmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "A&nsicht", NULL, ansichtmenu);
	new FXMenuCommand(ansichtmenu, "&Aktualisieren", NULL, this, ID_REFRESH);
	hilfemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&?", NULL, hilfemenu);
	new FXMenuCommand(hilfemenu, "&Info", NULL, this, ID_ABOUT);

	toolbar = new FXToolBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
	auto gif = [&](const unsigned char* d) { return new FXGIFIcon(getApp(), d); };
	auto tb = [&](const char* tip, FXIcon* ic, FXSelector sel) {
		new FXButton(toolbar, tip, ic, this, sel, BUTTON_TOOLBAR | FRAME_RAISED | LAYOUT_CENTER_Y, 0,0,0,0, 2,2,2,2);
	};
	tb("\tZurück", gif(resico_mmc_back), 0);
	tb("\tVor", gif(resico_mmc_forward), 0);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
	tb("\tEbene nach oben", gif(resico_mmc_up), 0);
	tb("\tStruktur anzeigen/ausblenden", gif(resico_mmc_contree), 0);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
	tb("\tEigenschaften", gif(resico_mmc_properties), ID_PROPERTIES);
	tb("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
	tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	new FXToolTip(getApp());

	statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);

	FXSplitter* splitter = new FXSplitter(this, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,300,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
	rightPane = new FXSwitcher(splitter, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);

	// Seite 0: Startbildschirm wie im Original
	FXVerticalFrame* welcome = new FXVerticalFrame(rightPane, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 20,20,20,20, 0,12);
	welcome->setBackColor(FXRGB(255,255,255));
	FXHorizontalFrame* head = new FXHorizontalFrame(welcome, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,0);
	head->setBackColor(FXRGB(255,255,255));
	FXLabel* infoIcon = new FXLabel(head, "", icoInfo, LAYOUT_TOP);
	infoIcon->setBackColor(FXRGB(255,255,255));
	welcomeTitle = new FXLabel(head, "Willkommen", NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
	welcomeTitle->setBackColor(FXRGB(255,255,255));
	welcomeText = new FXLabel(welcome, "", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
	welcomeText->setBackColor(FXRGB(255,255,255));

	// Seite 1: Serverstatus
	FXPacker* listframe = new FXPacker(rightPane, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	statusList = new FXIconList(listframe, NULL, 0, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	statusList->appendHeader("Servername", NULL, 130);
	statusList->appendHeader("Servertyp", NULL, 220);
	statusList->appendHeader("Status", NULL, 180);
	statusList->appendHeader("Verwendete Ports", NULL, 110);
	statusList->appendHeader("Ports gesamt", NULL, 90);
	statusList->appendHeader("Betriebszeit (Tage:Std.:Min.)", NULL, 160);

	rootItem = tree->appendItem(0, "Routing und RAS", icoRoot, icoRoot);
	statusItem = tree->appendItem(rootItem, "Serverstatus", icoStatus, icoStatus);
	serverItem = tree->appendItem(rootItem, hostName() + " (lokal)", icoServer, icoServer);
	tree->expandTree(rootItem);
	tree->setCurrentItem(rootItem);
	tree->selectItem(rootItem);
}

void RrasWindow::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

void RrasWindow::reload() {
	state = readState();
	// Serverstatusliste
	statusList->clearItems();
	FXString status = state.configured()
		? (state.forwarding ? FXString("Gestartet") : FXString("Beendet (konfiguriert)"))
		: FXString("Beendet (nicht konfiguriert)");
	statusList->appendItem(hostName() + "\t" + serverType() + "\t" + status + "\t-\t-\t-", icoServer, icoServer);
	statusbar->setText(state.configured()
		? FXString(" ") + roleLabel(state.role) + (state.forwarding ? ", IP-Weiterleitung aktiv" : ", IP-Weiterleitung aus")
		: FXString(" Routing und RAS ist auf diesem Server nicht konfiguriert."));
	showFor(tree->getCurrentItem());
}

void RrasWindow::showFor(FXTreeItem* item) {
	if (item == statusItem) { rightPane->setCurrent(1); return; }
	rightPane->setCurrent(0);
	if (item == serverItem) {
		welcomeTitle->setText(state.configured() ? "Routing und RAS ist aktiviert" : "Den Routing- und RAS-Server konfigurieren");
		welcomeText->setText(state.configured()
			? FXString("Dieser Server ist eingerichtet als: ") + roleLabel(state.role) + ".\n\n"
			  "Klicken Sie im Menü \"Vorgang\" auf \"Routing und RAS deaktivieren\", um die\n"
			  "Weiterleitung wieder abzuschalten."
			: FXString("Klicken Sie im Menü \"Vorgang\" auf \"Routing und RAS konfigurieren und aktivieren\",\n"
			  "um Routing und RAS einzurichten.\n\n"
			  "Umgesetzt sind bisher die Rollen \"Netzwerkrouter\" und \"Manuell konfigurierter Server\";\n"
			  "beide schalten die IP-Weiterleitung des Kernels ein."));
		return;
	}
	welcomeTitle->setText("Willkommen");
	welcomeText->setText("Routing und RAS bietet integriertes Multiprotokollrouting, Remotezugriff- und\n"
	                     "VPN-Funktionalität.\n\n"
	                     "Wählen Sie links den Server aus, um ihn zu konfigurieren, oder \"Serverstatus\",\n"
	                     "um seinen Zustand zu sehen.");
}

long RrasWindow::onTreeChanged(FXObject*, FXSelector, void*) {
	showFor(tree->getCurrentItem());
	return 1;
}

long RrasWindow::onTreeRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);
	showFor(item);

	FXMenuPane menu(this);
	if (item == serverItem) {
		new FXMenuCommand(&menu, "Routing und RAS &konfigurieren und aktivieren", NULL, this, ID_CONFIGURE);
		new FXMenuCommand(&menu, "Routing und RAS &deaktivieren", NULL, this, ID_DEACTIVATE);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_PROPERTIES);
	} else {
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long RrasWindow::onUpdConfigure(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, state.configured() ? ID_DISABLE : ID_ENABLE), NULL);
	return 1;
}

long RrasWindow::onUpdDeactivate(FXObject* sender, FXSelector, void*) {
	sender->handle(this, FXSEL(SEL_COMMAND, state.configured() ? ID_ENABLE : ID_DISABLE), NULL);
	return 1;
}

long RrasWindow::onConfigure(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "Ohne Root-Rechte kann nichts geändert werden.");
		return 1;
	}
	ConfigureDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	RrasState st = state;
	st.role = dlg.role();
	if (!applyForwarding(true, errorMsg) || !writeState(st, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "%s", errorMsg.text());
		reload();
		return 1;
	}
	reload();
	FXMessageBox::information(this, MBOX_OK, "Routing und RAS",
		"Routing und RAS wurde aktiviert.\n\nDie IP-Weiterleitung ist eingeschaltet und bleibt es auch nach einem Neustart.");
	return 1;
}

long RrasWindow::onDeactivate(FXObject*, FXSelector, void*) {
	if (FXMessageBox::question(this, MBOX_YES_NO, "Routing und RAS",
	        "Möchten Sie Routing und RAS wirklich deaktivieren?\n\n"
	        "Die IP-Weiterleitung wird abgeschaltet.") != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	RrasState st = state;
	st.role = ROLE_NONE;
	if (!applyForwarding(false, errorMsg) || !writeState(st, errorMsg))
		FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "%s", errorMsg.text());
	reload();
	return 1;
}

long RrasWindow::onProperties(FXObject*, FXSelector, void*) {
	ServerPropertiesDialog dlg(this, hostName(), state);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (dlg.role() == state.role) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "Ohne Root-Rechte kann nichts geändert werden.");
		return 1;
	}
	FXString errorMsg;
	RrasState st = state;
	st.role = dlg.role();
	if (!applyForwarding(st.role != ROLE_NONE, errorMsg) || !writeState(st, errorMsg))
		FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "%s", errorMsg.text());
	reload();
	return 1;
}

long RrasWindow::onRefresh(FXObject*, FXSelector, void*) {
	reload();
	return 1;
}

long RrasWindow::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Info",
		"Routing und RAS (ice2k)\n\n"
		"Nachbau des Snap-Ins von Windows 2000 Server.\n"
		"Umgesetzt: Serverstatus sowie Aktivieren/Deaktivieren der IP-Weiterleitung\n"
		"(sofort per sysctl, dauerhaft über /etc/sysctl.d/99-ice2k-rras.conf).\n\n"
		"Noch nicht umgesetzt: Einwähl- und VPN-Server, Adressumsetzung,\n"
		"Routingprotokolle und Schnittstellenverwaltung.");
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("Rras", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	RrasWindow* win = new RrasWindow(&application);
	application.create();
	if (!g_haveRoot)
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\nDer Zustand wird angezeigt, kann aber nicht geändert werden.");
	return application.run();
}
