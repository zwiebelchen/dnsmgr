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

// Gemeinsames Wurzelsymbol fuer die Dialoge.
static FXIcon* sharedRootIcon() {
	static FXIcon* ico = NULL;
	if (!ico) { ico = new FXPNGIcon(app, resico_rras_root, IMAGE_NEAREST); ico->create(); }
	return ico;
}

static FXString roleLabel(ServerRole r) {
	return r == ROLE_ROUTER_LAN ? "Netzwerkrouter (nur LAN-Routing)"
	     : r == ROLE_ROUTER_DIALUP ? "Netzwerkrouter (LAN und bei Bedarf wählendes Routing)"
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
// Netzwerkschnittstellen und Routen des Systems ("ip" aus iproute2).
// ---------------------------------------------------------------------
struct IfaceInfo {
	std::string name;
	std::string type;      // "Loopback", "Lokale Verbindung" ...
	bool up = false;       // Verwaltungsstatus (IFF_UP)
	bool running = false;  // Verbindung besteht (LOWER_UP)
	std::string address;   // erste IPv4-Adresse mit Praefix
};

static std::vector<IfaceInfo> listInterfaces() {
	std::vector<IfaceInfo> out;
	std::string raw;
	if (runAsRootCaptured({ FXString("ip"), FXString("-o"), FXString("link"), FXString("show") }, raw) != 0) return out;
	for (auto& line : splitLines(raw)) {
		size_t colon = line.find(": ");
		if (colon == std::string::npos) continue;
		size_t second = line.find(':', colon + 2);
		if (second == std::string::npos) continue;
		IfaceInfo i;
		i.name = line.substr(colon + 2, second - colon - 2);
		size_t at = i.name.find('@');
		if (at != std::string::npos) i.name = i.name.substr(0, at);
		i.up = line.find("UP") != std::string::npos;
		i.running = line.find("LOWER_UP") != std::string::npos;
		i.type = i.name == "lo" ? "Loopback" : "Lokale Verbindung";
		out.push_back(i);
	}
	raw.clear();
	runAsRootCaptured({ FXString("ip"), FXString("-o"), FXString("-4"), FXString("addr"), FXString("show") }, raw);
	for (auto& line : splitLines(raw)) {
		std::istringstream iss(line);
		std::string idx, name, fam, addr;
		iss >> idx >> name >> fam >> addr;
		for (auto& i : out) if (i.name == name && i.address.empty()) i.address = addr;
	}
	return out;
}

struct RouteInfo {
	std::string dest;      // "192.168.5.0"
	std::string mask;      // "255.255.255.0"
	std::string gateway;   // leer = direkt verbunden
	std::string iface;
	int metric = 0;
};

// "24" -> "255.255.255.0"
static std::string prefixToMask(int bits) {
	unsigned long m = bits >= 32 ? 0xFFFFFFFFul : (bits <= 0 ? 0ul : (0xFFFFFFFFul << (32 - bits)));
	char buf[20];
	snprintf(buf, sizeof(buf), "%lu.%lu.%lu.%lu", (m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF);
	return buf;
}

static int maskToPrefix(const std::string& mask) {
	unsigned a = 0, b = 0, c = 0, d = 0;
	if (sscanf(mask.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
	unsigned long m = (a << 24) | (b << 16) | (c << 8) | d;
	int bits = 0;
	while (bits < 32 && (m & (0x80000000ul >> bits))) bits++;
	// Nach den gesetzten Bits darf nichts mehr kommen.
	unsigned long expect = bits == 0 ? 0ul : (0xFFFFFFFFul << (32 - bits)) & 0xFFFFFFFFul;
	return m == expect ? bits : -1;
}

static std::vector<RouteInfo> listRoutes() {
	std::vector<RouteInfo> out;
	std::string raw;
	if (runAsRootCaptured({ FXString("ip"), FXString("-4"), FXString("route"), FXString("show") }, raw) != 0) return out;
	for (auto& line : splitLines(raw)) {
		std::istringstream iss(line);
		std::string tok;
		RouteInfo r;
		if (!(iss >> tok)) continue;
		if (tok == "default") { r.dest = "0.0.0.0"; r.mask = "0.0.0.0"; }
		else {
			size_t slash = tok.find('/');
			r.dest = slash == std::string::npos ? tok : tok.substr(0, slash);
			r.mask = slash == std::string::npos ? "255.255.255.255" : prefixToMask(atoi(tok.c_str() + slash + 1));
		}
		while (iss >> tok) {
			if (tok == "via") iss >> r.gateway;
			else if (tok == "dev") iss >> r.iface;
			else if (tok == "metric") { std::string m; iss >> m; r.metric = atoi(m.c_str()); }
		}
		out.push_back(r);
	}
	return out;
}

// Statische Routen dieser Konsole: zusaetzlich zu "ip route add" in einer
// Datei gemerkt, damit sie beim Aktivieren wieder gesetzt werden koennen
// -- der Kernel vergisst sie beim Neustart.
static const char* RRAS_ROUTES = "/etc/ice2k/rras-routes";

static std::vector<std::string> storedRouteLines() {
	std::vector<std::string> out;
	for (auto& l : splitLines(readFileUnprivileged(RRAS_ROUTES)))
		if (!svcprobe::trimmed(l).empty() && l[0] != '#') out.push_back(svcprobe::trimmed(l));
	return out;
}

static bool storeRouteLines(const std::vector<std::string>& lines, FXString& errorMsg) {
	std::string content = "# Statische Routen, von ice2k \"Routing und RAS\" verwaltet.\n";
	for (auto& l : lines) content += l + "\n";
	return writeFileAsRoot(RRAS_ROUTES, content, errorMsg);
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
		: FXDialogBox(owner, "Setup-Assistent für den Routing- und RAS-Server", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,600,0),
		  choiceTarget(choice, this, ID_CHOICE) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Allgemeine Konfigurationen", NULL, JUSTIFY_LEFT);
		new FXLabel(main, "Sie können den Server mit einer der folgenden Konfigurationen einrichten.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		// Optionen und Beschreibungen wortgleich aus mprsnap.dll (Dialog 12611).
		FXVerticalFrame* radios = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 12,0,4,4, 0,2);
		auto option = [&](const char* label, int value, const char* text) {
			new FXRadioButton(radios, label, &choiceTarget, FXDataTarget::ID_OPTION + value);
			FXLabel* l = new FXLabel(radios, text, NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
			l->setLayoutHints(l->getLayoutHints());
			new FXFrame(radios, LAYOUT_FIX_HEIGHT, 0,0,0,4, 0,0,0,0);
			(void)l;
		};
		option("&Internetverbindungsserver", C_INTERNET, "        Ermöglicht, dass alle Computer dieses Netzwerks eine Internetverbindung haben.");
		option("&RAS-Server", C_RAS, "        Ermöglicht Remotecomputern das Einwählen in dieses Netzwerk.");
		option("&VPN-Server", C_VPN, "        Ermöglicht Remotecomputern eine Verbindung mit diesem Netzwerk durch das Internet.");
		option("&Netzwerkrouter", C_ROUTER, "        Ermöglicht diesem Netzwerk die Kommunikation mit anderen Netzwerken.");
		option("&Manuell konfigurierter Server", C_MANUAL, "        Startet den Server mit Standardeinstellungen.");
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		// Zusatzzeile: was diese Konsole daraus tatsächlich macht.
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
		// Aufbau wie mprsnap.dll, Dialog 12517.
		FXHorizontalFrame* head = new FXHorizontalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,4, 12,0);
		new FXLabel(head, "", sharedRootIcon(), LAYOUT_CENTER_Y);
		new FXLabel(head, "Routing und RAS", NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		new FXLabel(page, "Diesen Computer aktivieren als:", NULL, JUSTIFY_LEFT);
		routerCheck = new FXCheckButton(page, "&Router", this, ID_ROUTER);
		routerCheck->setCheck(st.role != ROLE_NONE);
		FXVerticalFrame* sub = new FXVerticalFrame(page, LAYOUT_FILL_X, 0,0,0,0, 20,0,0,0, 0,4);
		routerControls.push_back(new FXRadioButton(sub, "&Nur LAN-Routing", &routingTarget, FXDataTarget::ID_OPTION + 0));
		routerControls.push_back(new FXRadioButton(sub, "&LAN und bei Bedarf wählendes Routing", &routingTarget, FXDataTarget::ID_OPTION + 1));
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
// "Neue statische Route" -- die Dialoge des IP-Routers stecken in
// iprtrui.dll, die hier nicht vorliegt; Beschriftungen daher eigene,
// aber mit den Feldern des Originals.
// ---------------------------------------------------------------------
class StaticRouteDialog : public FXDialogBox {
	FXDECLARE(StaticRouteDialog)
private:
	FXListBox* ifaceBox = nullptr;
	FXTextField *destField = nullptr, *maskField = nullptr, *gwField = nullptr, *metricField = nullptr;
	std::vector<std::string> ifaces;
protected:
	StaticRouteDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	StaticRouteDialog(FXWindow* owner, const std::vector<IfaceInfo>& interfaces)
		: FXDialogBox(owner, "Statische Route", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,4);
		auto row = [&](const char* label) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,120,0);
			return r;
		};
		FXHorizontalFrame* ir = row("&Schnittstelle:");
		ifaceBox = new FXListBox(ir, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		for (auto& i : interfaces) { if (i.name == "lo") continue; ifaceBox->appendItem(i.name.c_str()); ifaces.push_back(i.name); }
		ifaceBox->setNumVisible(std::min<int>(8, (int)ifaces.size()));
		destField = new FXTextField(row("&Ziel:"), 18, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		maskField = new FXTextField(row("&Netzwerkmaske:"), 18, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		maskField->setText("255.255.255.0");
		gwField = new FXTextField(row("&Gateway:"), 18, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		metricField = new FXTextField(row("&Metrik:"), 6, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		metricField->setText("1");
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (ifaces.empty()) { FXMessageBox::error(this, MBOX_OK, "Statische Route", "Es wurde keine Netzwerkschnittstelle gefunden."); return 1; }
		unsigned a,b,c,d;
		if (sscanf(svcprobe::trimmed(destField->getText().text()).c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) {
			FXMessageBox::error(this, MBOX_OK, "Statische Route", "Geben Sie eine gültige IP-Adresse für das Ziel an."); return 1;
		}
		if (maskToPrefix(svcprobe::trimmed(maskField->getText().text())) < 0) {
			FXMessageBox::error(this, MBOX_OK, "Statische Route", "Geben Sie eine gültige Netzwerkmaske an (z.B. 255.255.255.0)."); return 1;
		}
		std::string gw = svcprobe::trimmed(gwField->getText().text());
		if (!gw.empty() && sscanf(gw.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) {
			FXMessageBox::error(this, MBOX_OK, "Statische Route", "Geben Sie eine gültige IP-Adresse für das Gateway an."); return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	// Route als "ip route"-Argumente, so wie sie auch gespeichert wird.
	std::string routeSpec() const {
		std::string dest = svcprobe::trimmed(destField->getText().text());
		int bits = maskToPrefix(svcprobe::trimmed(maskField->getText().text()));
		std::string gw = svcprobe::trimmed(gwField->getText().text());
		std::string metric = svcprobe::trimmed(metricField->getText().text());
		std::string spec = dest + "/" + std::to_string(bits);
		if (!gw.empty()) spec += " via " + gw;
		spec += " dev " + ifaces[std::max(0, ifaceBox->getCurrentItem())];
		if (!metric.empty() && metric != "0") spec += " metric " + metric;
		return spec;
	}
	virtual ~StaticRouteDialog() {}
};
FXDEFMAP(StaticRouteDialog) StaticRouteDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, StaticRouteDialog::ID_OK, StaticRouteDialog::onOk),
};
FXIMPLEMENT(StaticRouteDialog, FXDialogBox, StaticRouteDialogMap, ARRAYNUMBER(StaticRouteDialogMap))

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
	// Knoten unterhalb des Servers -- nur, solange Routing und RAS aktiv ist
	// (wie im Original).
	FXTreeItem *ifacesItem = nullptr, *portsItem = nullptr, *ipRoutingItem = nullptr,
	           *ipGeneralItem = nullptr, *staticRoutesItem = nullptr;
	FXIconList* itemList = nullptr;
	std::vector<RouteInfo> shownRoutes;
	FXIcon *icoRoot = nullptr, *icoStatus = nullptr, *icoServerStopped = nullptr, *icoServerStarted = nullptr,
	       *icoInfo = nullptr, *icoNetwork = nullptr;
	RrasState state;
protected:
	RrasWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_CONFIGURE, ID_DEACTIVATE, ID_PROPERTIES, ID_REFRESH, ID_ABOUT,
	       ID_LIST, ID_NEW_ROUTE, ID_DELETE_ROUTE };

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
	long onListRightClick(FXObject*, FXSelector, void*);
	long onNewRoute(FXObject*, FXSelector, void*);
	long onDeleteRoute(FXObject*, FXSelector, void*);
	void buildServerNodes();
	void setColumns(const std::vector<std::pair<const char*, int>>& cols);

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
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, RrasWindow::ID_LIST, RrasWindow::onListRightClick),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_NEW_ROUTE, RrasWindow::onNewRoute),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_DELETE_ROUTE, RrasWindow::onDeleteRoute),
};
FXIMPLEMENT(RrasWindow, FXMainWindow, RrasWindowMap, ARRAYNUMBER(RrasWindowMap))

RrasWindow::RrasWindow(FXApp* a)
	: FXMainWindow(a, "Routing und RAS", NULL, NULL, DECOR_ALL, 0,0, 900,560) {
	// Symbole aus mprsnap.dll (deutsches Windows 2000 SP4).
	icoRoot = new FXPNGIcon(a, resico_rras_root, IMAGE_NEAREST);
	icoStatus = new FXPNGIcon(a, resico_rras_status, IMAGE_NEAREST);
	icoServerStopped = new FXPNGIcon(a, resico_rras_server_stopped, IMAGE_NEAREST);
	icoServerStarted = new FXPNGIcon(a, resico_rras_server_started, IMAGE_NEAREST);
	icoInfo = new FXPNGIcon(a, resico_key, IMAGE_NEAREST);
	icoNetwork = new FXPNGIcon(a, resico_rras_network, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoStatus, icoServerStopped, icoServerStarted, icoInfo, icoNetwork }) i->create();

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

	// Seite 2: Listen der Knoten unterhalb des Servers
	FXPacker* itemframe = new FXPacker(rightPane, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	itemList = new FXIconList(itemframe, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);

	rootItem = tree->appendItem(0, "Routing und RAS", icoRoot, icoRoot);
	statusItem = tree->appendItem(rootItem, "Serverstatus", icoStatus, icoStatus);
	serverItem = tree->appendItem(rootItem, hostName() + " (lokal)", icoServerStopped, icoServerStopped);
	tree->expandTree(rootItem);
	tree->setCurrentItem(rootItem);
	tree->selectItem(rootItem);
}

void RrasWindow::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

// Unterhalb des Servers erscheinen die Knoten des Originals, sobald
// Routing und RAS aktiviert ist (Namen aus mprsnap.dll: 13, 21).
void RrasWindow::buildServerNodes() {
	for (FXTreeItem* it : { staticRoutesItem, ipGeneralItem, ipRoutingItem, portsItem, ifacesItem })
		if (it) tree->removeItem(it);
	ifacesItem = portsItem = ipRoutingItem = ipGeneralItem = staticRoutesItem = nullptr;
	if (!state.configured()) return;
	ifacesItem = tree->appendItem(serverItem, "Routingschnittstellen", icoNetwork, icoNetwork);
	portsItem = tree->appendItem(serverItem, "Ports", icoStatus, icoStatus);
	ipRoutingItem = tree->appendItem(serverItem, "IP-Routing", icoNetwork, icoNetwork);
	ipGeneralItem = tree->appendItem(ipRoutingItem, "Allgemein", icoNetwork, icoNetwork);
	staticRoutesItem = tree->appendItem(ipRoutingItem, "Statische Routen", icoNetwork, icoNetwork);
	tree->expandTree(serverItem);
	tree->expandTree(ipRoutingItem);
}

void RrasWindow::setColumns(const std::vector<std::pair<const char*, int>>& cols) {
	while (itemList->getNumHeaders() > 0) itemList->removeHeader(0);
	for (auto& c : cols) itemList->appendHeader(c.first, NULL, c.second);
	itemList->clearItems();
}

void RrasWindow::reload() {
	state = readState();
	// Serverstatusliste
	statusList->clearItems();
	// Zustandstexte wie mprsnap.dll (102 "Beendet", 105 "Gestartet",
	// 97 "%s (nicht konfiguriert)").
	FXString status = state.configured()
		? (state.forwarding ? FXString("Gestartet") : FXString("Beendet"))
		: FXString("Beendet (nicht konfiguriert)");
	// Symbol des Serverknotens wie im Original je nach Zustand.
	FXIcon* srvIcon = (state.configured() && state.forwarding) ? icoServerStarted : icoServerStopped;
	serverItem->setOpenIcon(srvIcon);
	serverItem->setClosedIcon(srvIcon);
	tree->updateItem(serverItem);
	statusList->appendItem(hostName() + "\t" + serverType() + "\t" + status + "\t-\t-\t-", srvIcon, srvIcon);
	statusbar->setText(state.configured()
		? FXString(" ") + roleLabel(state.role) + (state.forwarding ? ", IP-Weiterleitung aktiv" : ", IP-Weiterleitung aus")
		: FXString(" Routing und RAS ist auf diesem Server nicht konfiguriert."));
	buildServerNodes();
	showFor(tree->getCurrentItem());
}

void RrasWindow::showFor(FXTreeItem* item) {
	if (item == statusItem) { rightPane->setCurrent(1); return; }
	if (item && (item == ifacesItem || item == portsItem || item == ipGeneralItem || item == staticRoutesItem)) {
		rightPane->setCurrent(2);
		shownRoutes.clear();
		if (item == ifacesItem) {
			// Spalten wie mprsnap.dll (14-17).
			setColumns({ { "Schnittstelle", 200 }, { "Typ", 160 }, { "Status", 120 }, { "Status der Verbindung", 160 } });
			for (auto& i : listInterfaces())
				itemList->appendItem(FXString(i.name.c_str()) + "\t" + i.type.c_str() + "\t" +
				                     (i.up ? "Aktiviert" : "Deaktiviert") + "\t" + (i.running ? "Verbunden" : "Getrennt"),
				                     icoNetwork, icoNetwork);
			statusbar->setText(" LAN-Schnittstellen und Schnittstellen für Wählen bei Bedarf");
		} else if (item == portsItem) {
			setColumns({ { "Name", 220 }, { "Gerät", 200 }, { "Status", 160 } });
			statusbar->setText(" Einwähl- und VPN-Anschlüsse sind noch nicht umgesetzt.");
		} else if (item == ipGeneralItem) {
			setColumns({ { "Schnittstelle", 200 }, { "Typ", 160 }, { "IP-Adresse", 180 }, { "Verwaltungsstatus", 130 }, { "Betriebsstatus", 130 } });
			for (auto& i : listInterfaces())
				itemList->appendItem(FXString(i.name.c_str()) + "\t" + i.type.c_str() + "\t" +
				                     (i.address.empty() ? FXString("-") : FXString(i.address.c_str())) + "\t" +
				                     (i.up ? "Aktiviert" : "Deaktiviert") + "\t" + (i.running ? "Betriebsbereit" : "Nicht betriebsbereit"),
				                     icoNetwork, icoNetwork);
			statusbar->setText(" IP-Schnittstellen dieses Servers");
		} else {
			setColumns({ { "Ziel", 150 }, { "Netzwerkmaske", 140 }, { "Gateway", 150 }, { "Schnittstelle", 140 }, { "Metrik", 70 } });
			shownRoutes = listRoutes();
			for (auto& r : shownRoutes)
				itemList->appendItem(FXString(r.dest.c_str()) + "\t" + r.mask.c_str() + "\t" +
				                     (r.gateway.empty() ? FXString("Direkt verbunden") : FXString(r.gateway.c_str())) + "\t" +
				                     r.iface.c_str() + "\t" + FXString(std::to_string(r.metric).c_str()),
				                     icoNetwork, icoNetwork);
			statusbar->setText(" Rechtsklick in die Liste: Neue statische Route anlegen oder eine Route löschen.");
		}
		return;
	}
	rightPane->setCurrent(0);
	if (item == serverItem) {
		welcomeTitle->setText(state.configured() ? "Routing und RAS ist aktiviert" : "Den Routing- und RAS-Server konfigurieren");
		welcomeText->setText(state.configured()
			? FXString("Dieser Server ist eingerichtet als: ") + roleLabel(state.role) + ".\n\n"
			  "Klicken Sie im Menü \"Vorgang\" auf \"Routing und RAS deaktivieren\", um die\n"
			  "Weiterleitung wieder abzuschalten."
			// Texte 301 und 302 aus mprsnap.dll.
			: FXString("Klicken Sie im Menü \"Vorgang\" auf \"Routing und RAS konfigurieren und aktivieren\",\n"
			  "um Routing und RAS einzurichten.\n\n"
			  "Weitere Informationen bezüglich der Einrichtung eines Routing- und RAS-Servers finden\n"
			  "Sie in der Onlinehilfe.\n\n"
			  "Umgesetzt sind bisher die Rollen \"Netzwerkrouter\" und \"Manuell konfigurierter Server\";\n"
			  "beide schalten die IP-Weiterleitung des Kernels ein."));
		return;
	}
	welcomeTitle->setText("Willkommen");
	// Text 291 aus mprsnap.dll; der zweite Absatz weicht ab, weil es hier
	// (noch) kein "Server hinzufügen" gibt.
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
	// Gemerkte statische Routen wieder setzen (der Kernel hat sie nach
	// einem Neustart nicht mehr).
	for (auto& spec : storedRouteLines()) {
		std::vector<FXString> args = { FXString("ip"), FXString("route"), FXString("replace") };
		std::istringstream iss(spec);
		std::string tok;
		while (iss >> tok) args.push_back(FXString(tok.c_str()));
		std::string out;
		runAsRootCaptured(args, out);
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

long RrasWindow::onListRightClick(FXObject*, FXSelector, void* ptr) {
	if (tree->getCurrentItem() != staticRoutesItem) return 1;
	FXEvent* ev = (FXEvent*)ptr;
	FXint idx = itemList->getItemAt(ev->win_x, ev->win_y);
	if (idx >= 0) { itemList->setCurrentItem(idx); itemList->selectItem(idx); }
	FXMenuPane menu(this);
	new FXMenuCommand(&menu, "&Neue statische Route...", NULL, this, ID_NEW_ROUTE);
	if (idx >= 0 && idx < (int)shownRoutes.size()) {
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_ROUTE);
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

// Setzt die Route sofort und merkt sie sich, damit sie beim naechsten
// Aktivieren wieder gesetzt werden kann -- der Kernel vergisst Routen
// beim Neustart.
long RrasWindow::onNewRoute(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	StaticRouteDialog dlg(this, listInterfaces());
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	std::string spec = dlg.routeSpec();
	std::string out;
	std::vector<FXString> args = { FXString("ip"), FXString("route"), FXString("add") };
	std::istringstream iss(spec);
	std::string tok;
	while (iss >> tok) args.push_back(FXString(tok.c_str()));
	if (runAsRootCaptured(args, out) != 0) {
		FXMessageBox::error(this, MBOX_OK, "Statische Route", "Die Route konnte nicht gesetzt werden:\n\n%s", svcprobe::trimmed(out).c_str());
		return 1;
	}
	std::vector<std::string> lines = storedRouteLines();
	lines.push_back(spec);
	FXString errorMsg;
	if (!storeRouteLines(lines, errorMsg))
		FXMessageBox::warning(this, MBOX_OK, "Statische Route",
			"Die Route ist gesetzt, konnte aber nicht dauerhaft gespeichert werden:\n\n%s", errorMsg.text());
	showFor(tree->getCurrentItem());
	return 1;
}

long RrasWindow::onDeleteRoute(FXObject*, FXSelector, void*) {
	int idx = itemList->getCurrentItem();
	if (idx < 0 || idx >= (int)shownRoutes.size()) return 1;
	const RouteInfo& r = shownRoutes[idx];
	if (FXMessageBox::question(this, MBOX_YES_NO, "Statische Route",
	        "Möchten Sie die Route zu %s wirklich löschen?", r.dest.c_str()) != MBOX_CLICKED_YES) return 1;
	int bits = maskToPrefix(r.mask);
	std::string dest = r.dest + "/" + std::to_string(bits < 0 ? 32 : bits);
	std::vector<FXString> args = { FXString("ip"), FXString("route"), FXString("del"), FXString(dest.c_str()) };
	if (!r.gateway.empty()) { args.push_back("via"); args.push_back(FXString(r.gateway.c_str())); }
	if (!r.iface.empty()) { args.push_back("dev"); args.push_back(FXString(r.iface.c_str())); }
	std::string out;
	if (runAsRootCaptured(args, out) != 0) {
		FXMessageBox::error(this, MBOX_OK, "Statische Route", "Die Route konnte nicht gelöscht werden:\n\n%s", svcprobe::trimmed(out).c_str());
		return 1;
	}
	// Auch aus der gespeicherten Liste nehmen.
	std::vector<std::string> keep;
	for (auto& l : storedRouteLines()) if (l.compare(0, dest.size(), dest) != 0) keep.push_back(l);
	FXString errorMsg;
	storeRouteLines(keep, errorMsg);
	showFor(tree->getCurrentItem());
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
