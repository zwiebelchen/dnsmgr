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
enum ServerRole { ROLE_NONE = 0, ROLE_ROUTER_LAN, ROLE_ROUTER_DIALUP, ROLE_MANUAL, ROLE_VPN };

struct RrasState {
	ServerRole role = ROLE_NONE;
	bool forwarding = false;    // net.ipv4.ip_forward des laufenden Systems
	// Nur bei role = vpn gefuellt.
	std::string vpnBackend, vpnName, vpnPort, vpnSubnet, vpnServerIp;
	bool configured() const { return role != ROLE_NONE; }
};

static RrasState readState() {
	RrasState st;
	for (auto& line : splitLines(readFileUnprivileged(RRAS_CONF))) {
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		std::string key = svcprobe::trimmed(line.substr(0, eq));
		std::string val = svcprobe::trimmed(line.substr(eq + 1));
		if (key != "role") {
			if (key == "vpn") st.vpnBackend = val;
			else if (key == "vpn-name") st.vpnName = val;
			else if (key == "vpn-port") st.vpnPort = val;
			else if (key == "vpn-subnet") st.vpnSubnet = val;
			else if (key == "vpn-server-ip") st.vpnServerIp = val;
			continue;
		}
		if (val == "router-lan") st.role = ROLE_ROUTER_LAN;
		else if (val == "router-dialup") st.role = ROLE_ROUTER_DIALUP;
		else if (val == "manual") st.role = ROLE_MANUAL;
		else if (val == "vpn") st.role = ROLE_VPN;
	}
	st.forwarding = svcprobe::trimmed(readFileUnprivileged("/proc/sys/net/ipv4/ip_forward")) == "1";
	return st;
}

static const char* roleKeyword(ServerRole r) {
	return r == ROLE_ROUTER_LAN ? "router-lan" : r == ROLE_ROUTER_DIALUP ? "router-dialup"
	     : r == ROLE_MANUAL ? "manual" : r == ROLE_VPN ? "vpn" : "none";
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
	     : r == ROLE_VPN ? "VPN-Server"
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
	if (st.role == ROLE_VPN)
		conf += "vpn = " + st.vpnBackend + "\nvpn-name = " + st.vpnName + "\nvpn-port = " + st.vpnPort +
		        "\nvpn-subnet = " + st.vpnSubnet + "\nvpn-server-ip = " + st.vpnServerIp + "\n";
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
			                                 "Zur Auswahl stehen WireGuard, OpenVPN und strongSwan."); break;
			case C_ROUTER: description->setText("Leitet Pakete zwischen den Netzwerken dieses Servers weiter.\n"
			                                    "Schaltet die IP-Weiterleitung des Kernels ein."); break;
			default: description->setText("Aktiviert Routing und RAS, ohne weitere Einstellungen vorzunehmen.\n"
			                              "Schaltet die IP-Weiterleitung des Kernels ein."); break;
		}
		return 1;
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (choice == C_INTERNET || choice == C_RAS) {
			FXMessageBox::information(this, MBOX_OK, "Routing und RAS",
				"Diese Serverrolle ist noch nicht umgesetzt.\n\n"
				"Umgesetzt sind \"VPN-Server\" (WireGuard, OpenVPN, strongSwan), \"Netzwerkrouter\"\n"
				"und \"Manuell konfigurierter Server\".");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	ServerRole role() const { return choice == C_ROUTER ? ROLE_ROUTER_LAN : choice == C_VPN ? ROLE_VPN : ROLE_MANUAL; }
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
// systemd-Unit: Routen und Paketfilter ueberleben einen Neustart nur,
// wenn sie beim Hochfahren wieder gesetzt werden. Die Konsole legt dazu
// ein kleines Skript und eine oneshot-Unit an und schaltet sie mit
// "Konfigurieren und aktivieren" ein bzw. mit "Deaktivieren" aus.
// ---------------------------------------------------------------------
static const char* RRAS_APPLY_SCRIPT = "/usr/local/sbin/ice2k-rras-apply";
static const char* RRAS_UNIT = "/etc/systemd/system/ice2k-rras.service";

static bool installRrasUnit(FXString& errorMsg) {
	std::string script =
		"#!/bin/sh\n"
		"# Von ice2k \"Routing und RAS\" erzeugt -- setzt beim Systemstart die\n"
		"# IP-Weiterleitung, die statischen Routen und die Paketfilter.\n"
		"set -e\n"
		"conf=/etc/ice2k/rras.conf\n"
		"[ -f \"$conf\" ] || exit 0\n"
		"role=$(sed -n 's/^role *= *//p' \"$conf\")\n"
		"[ \"$role\" = \"none\" ] && exit 0\n"
		"sysctl -q -w net.ipv4.ip_forward=1\n"
		"if [ -f /etc/ice2k/rras-routes ]; then\n"
		"  while read -r line; do\n"
		"    case \"$line\" in ''|\\#*) continue;; esac\n"
		"    ip route replace $line || true\n"
		"  done < /etc/ice2k/rras-routes\n"
		"fi\n"
		"[ -f /etc/ice2k/rras-filter.nft ] && nft -f /etc/ice2k/rras-filter.nft\n"
		"exit 0\n";
	if (!writeFileAsRoot(RRAS_APPLY_SCRIPT, script, errorMsg)) return false;
	runAsRoot({ FXString("chmod"), FXString("755"), FXString(RRAS_APPLY_SCRIPT) });

	std::string unit =
		"# Von ice2k \"Routing und RAS\" erzeugt.\n"
		"[Unit]\n"
		"Description=ice2k Routing und RAS (Weiterleitung, statische Routen, Paketfilter)\n"
		"After=network-online.target\n"
		"Wants=network-online.target\n\n"
		"[Service]\n"
		"Type=oneshot\n"
		"RemainAfterExit=yes\n"
		"ExecStart=" + std::string(RRAS_APPLY_SCRIPT) + "\n\n"
		"[Install]\n"
		"WantedBy=multi-user.target\n";
	if (!writeFileAsRoot(RRAS_UNIT, unit, errorMsg)) return false;
	std::string out;
	runAsRootCaptured({ FXString("systemctl"), FXString("daemon-reload") }, out);
	return true;
}

// note bleibt leer, wenn alles geklappt hat.
static void enableRrasUnit(bool on, std::string& note) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("systemctl"), FXString(on ? "enable" : "disable"), FXString("ice2k-rras.service") }, out);
	if (rc != 0)
		note = std::string(on ? "Die Unit ice2k-rras.service konnte nicht aktiviert werden:\n"
		                      : "Die Unit ice2k-rras.service konnte nicht deaktiviert werden:\n") + svcprobe::trimmed(out);
}

// ---------------------------------------------------------------------
// VPN-Server. Windows 2000 kennt hier PPTP und L2TP/IPSec; unter Linux
// treten WireGuard, OpenVPN und strongSwan an deren Stelle. Der Dialog
// hält sich an den Aufbau des Assistenten, die Felder sind die des
// jeweiligen Dienstes.
// ---------------------------------------------------------------------
enum VpnBackend { VPN_NONE = 0, VPN_WIREGUARD, VPN_OPENVPN, VPN_STRONGSWAN };

static const char* vpnKeyword(VpnBackend b) {
	return b == VPN_WIREGUARD ? "wireguard" : b == VPN_OPENVPN ? "openvpn" : b == VPN_STRONGSWAN ? "strongswan" : "none";
}
static FXString vpnLabel(VpnBackend b) {
	return b == VPN_WIREGUARD ? "WireGuard" : b == VPN_OPENVPN ? "OpenVPN" : b == VPN_STRONGSWAN ? "strongSwan (IPSec)" : "";
}
static const char* vpnUnit(VpnBackend b, const std::string& name) {
	static std::string unit;
	unit = b == VPN_WIREGUARD ? "wg-quick@" + name : b == VPN_OPENVPN ? "openvpn-server@" + name : "strongswan";
	return unit.c_str();
}

struct VpnConfig {
	VpnBackend backend = VPN_NONE;
	std::string name = "vpn0";      // wg-Schnittstelle bzw. Instanzname
	std::string port = "51820";
	std::string subnet = "10.8.0.0/24";
	std::string serverIp = "10.8.0.1";
};

// Dialog "VPN-Server einrichten".
class VpnSetupDialog : public FXDialogBox {
	FXDECLARE(VpnSetupDialog)
private:
	FXint backend = 0;   // 0 WireGuard, 1 OpenVPN, 2 strongSwan
	FXDataTarget backendTarget;
	FXTextField *nameField = nullptr, *portField = nullptr, *subnetField = nullptr, *serverIpField = nullptr;
	FXLabel* hint = nullptr;
	FXCheckButton* pkiCheck = nullptr;
protected:
	VpnSetupDialog() {}
public:
	enum { ID_BACKEND = FXDialogBox::ID_LAST, ID_OK };
	VpnSetupDialog(FXWindow* owner)
		: FXDialogBox(owner, "VPN-Server einrichten", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,560,0),
		  backendTarget(backend, this, ID_BACKEND) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "VPN-Dienst", NULL, JUSTIFY_LEFT);
		new FXLabel(main, "Windows 2000 verwendet hier PPTP und L2TP/IPSec. Wählen Sie den Dienst,\n"
		                  "der diese Aufgabe auf diesem Server übernimmt.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* radios = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 12,0,4,4, 0,2);
		auto opt = [&](const char* label, int v, const char* text) {
			new FXRadioButton(radios, label, &backendTarget, FXDataTarget::ID_OPTION + v);
			new FXLabel(radios, text, NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
			new FXFrame(radios, LAYOUT_FIX_HEIGHT, 0,0,0,4, 0,0,0,0);
		};
		opt("&WireGuard", 0, "        Schlanker VPN-Dienst mit Schlüsselpaaren; wird hier vollständig eingerichtet.");
		opt("&OpenVPN", 1, "        Benötigt Zertifikate (CA, Server) -- die Konfiguration wird geschrieben,\n        die Zertifikate müssen vorhanden sein.");
		opt("&strongSwan (IPSec)", 2, "        IKEv2; die Verbindung wird angelegt, Zertifikate bzw. Schlüssel müssen\n        vorhanden sein.");
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		auto row = [&](const char* label, const char* value) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,150,0);
			FXTextField* tf = new FXTextField(r, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			tf->setText(value);
			return tf;
		};
		nameField = row("&Name:", "vpn0");
		portField = row("&Port:", "51820");
		subnetField = row("&VPN-Netzwerk:", "10.8.0.0/24");
		serverIpField = row("&Adresse des Servers:", "10.8.0.1");
		pkiCheck = new FXCheckButton(main, "Bei OpenVPN eine eigene &Zertifizierungsstelle anlegen (CA und Serverzertifikat)");
		pkiCheck->setCheck(TRUE);
		hint = new FXLabel(main, "", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "&Fertig stellen", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		onBackend(NULL, 0, NULL);
	}
	long onBackend(FXObject*, FXSelector, void*) {
		if (pkiCheck) { if (backend == 1) pkiCheck->enable(); else pkiCheck->disable(); }
		if (backend == 0) { portField->setText("51820"); hint->setText("Schreibt /etc/wireguard/<Name>.conf mit einem neuen Schlüsselpaar und startet wg-quick@<Name>."); }
		else if (backend == 1) { portField->setText("1194"); hint->setText("Schreibt /etc/openvpn/server/<Name>.conf; erwartet ca.crt, server.crt, server.key und dh.pem in /etc/openvpn/server."); }
		else { portField->setText("500"); hint->setText("Schreibt /etc/swanctl/conf.d/<Name>.conf (IKEv2); Zertifikate bzw. Schlüssel müssen in /etc/swanctl liegen."); }
		return 1;
	}
	long onOk(FXObject*, FXSelector, void*) {
		std::string n = svcprobe::trimmed(nameField->getText().text());
		if (n.empty() || n.find('/') != std::string::npos || n.find(' ') != std::string::npos) {
			FXMessageBox::error(this, MBOX_OK, "VPN-Server", "Geben Sie einen gültigen Namen ohne Leer- und Sonderzeichen an.");
			return 1;
		}
		unsigned a,b,c,d,bits;
		if (sscanf(svcprobe::trimmed(subnetField->getText().text()).c_str(), "%u.%u.%u.%u/%u", &a,&b,&c,&d,&bits) != 5) {
			FXMessageBox::error(this, MBOX_OK, "VPN-Server", "Geben Sie das VPN-Netzwerk in der Form 10.8.0.0/24 an.");
			return 1;
		}
		if (sscanf(svcprobe::trimmed(serverIpField->getText().text()).c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) {
			FXMessageBox::error(this, MBOX_OK, "VPN-Server", "Geben Sie eine gültige Adresse für den Server an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	bool createPki() const { return backend == 1 && pkiCheck->getCheck(); }
	VpnConfig config() const {
		VpnConfig c;
		c.backend = backend == 0 ? VPN_WIREGUARD : backend == 1 ? VPN_OPENVPN : VPN_STRONGSWAN;
		c.name = svcprobe::trimmed(nameField->getText().text());
		c.port = svcprobe::trimmed(portField->getText().text());
		c.subnet = svcprobe::trimmed(subnetField->getText().text());
		c.serverIp = svcprobe::trimmed(serverIpField->getText().text());
		return c;
	}
	virtual ~VpnSetupDialog() {}
};
FXDEFMAP(VpnSetupDialog) VpnSetupDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, VpnSetupDialog::ID_BACKEND, VpnSetupDialog::onBackend),
	FXMAPFUNC(SEL_COMMAND, VpnSetupDialog::ID_OK, VpnSetupDialog::onOk),
};
FXIMPLEMENT(VpnSetupDialog, FXDialogBox, VpnSetupDialogMap, ARRAYNUMBER(VpnSetupDialogMap))

// Richtet den gewaehlten Dienst ein. Bei WireGuard komplett (Schluessel,
// Konfiguration, Dienst), bei OpenVPN und strongSwan wird die
// Serverkonfiguration geschrieben -- Zertifikate und Schluessel legt
// diese Konsole bewusst nicht an.
static bool createOpenvpnPki(FXString& errorMsg);

static bool setupVpn(const VpnConfig& c, bool withPki, std::string& note, FXString& errorMsg) {
	note.clear();
	if (c.backend == VPN_WIREGUARD) {
		std::string key, pub;
		if (runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString("wg genkey") }, key) != 0 || svcprobe::trimmed(key).empty()) {
			errorMsg = "wg wurde nicht gefunden. Installieren Sie das Paket wireguard-tools.";
			return false;
		}
		key = svcprobe::trimmed(key);
		runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString(("echo '" + key + "' | wg pubkey").c_str()) }, pub);
		std::string conf = "# Von ice2k \"Routing und RAS\" erzeugt.\n[Interface]\n"
		                   "Address = " + c.serverIp + "/" + c.subnet.substr(c.subnet.find('/') + 1) + "\n"
		                   "ListenPort = " + c.port + "\n"
		                   "PrivateKey = " + key + "\n\n"
		                   "# Für jeden Client hier einen Abschnitt anfügen:\n"
		                   "# [Peer]\n# PublicKey = <öffentlicher Schlüssel des Clients>\n# AllowedIPs = 10.8.0.2/32\n";
		if (!writeFileAsRoot("/etc/wireguard/" + c.name + ".conf", conf, errorMsg)) return false;
		runAsRoot({ FXString("chmod"), FXString("600"), FXString(("/etc/wireguard/" + c.name + ".conf").c_str()) });
		std::string out;
		if (runAsRootCaptured({ FXString("systemctl"), FXString("enable"), FXString("--now"), FXString(vpnUnit(c.backend, c.name)) }, out) != 0)
			note = "Die Konfiguration wurde geschrieben, der Dienst konnte aber nicht gestartet werden:\n\n" + svcprobe::trimmed(out);
		note += (note.empty() ? "" : "\n\n") + std::string("Öffentlicher Schlüssel des Servers:\n") + svcprobe::trimmed(pub);
		return true;
	}
	if (c.backend == VPN_OPENVPN) {
		if (withPki && !createOpenvpnPki(errorMsg)) return false;
		std::string conf = "# Von ice2k \"Routing und RAS\" erzeugt.\n"
		                   "port " + c.port + "\nproto udp\ndev tun\n"
		                   // Ohne Diffie-Hellman-Datei: OpenVPN 2.4+ handelt ECDHE aus.
		                   "ca ca.crt\ncert server.crt\nkey server.key\ndh none\n"
		                   "server " + c.subnet.substr(0, c.subnet.find('/')) + " " + prefixToMask(atoi(c.subnet.c_str() + c.subnet.find('/') + 1)) + "\n"
		                   "topology subnet\nkeepalive 10 120\npersist-key\npersist-tun\nuser nobody\ngroup nogroup\nverb 3\n";
		if (!writeFileAsRoot("/etc/openvpn/server/" + c.name + ".conf", conf, errorMsg)) return false;
		bool haveCerts = runAsRoot({ FXString("test"), FXString("-f"), FXString("/etc/openvpn/server/server.crt") }) == 0;
		if (!haveCerts) {
			note = "Die Konfiguration wurde nach /etc/openvpn/server/" + c.name + ".conf geschrieben.\n\n"
			       "Es fehlen noch die Zertifikate (ca.crt, server.crt, server.key) in /etc/openvpn/server.\n"
			       "Legen Sie sie an oder wiederholen Sie die Einrichtung mit der Option\n"
			       "\"Eine eigene Zertifizierungsstelle anlegen\".";
			return true;
		}
		note = "Zertifizierungsstelle und Serverzertifikat liegen unter /etc/openvpn/server/pki.";
		std::string out;
		if (runAsRootCaptured({ FXString("systemctl"), FXString("enable"), FXString("--now"), FXString(vpnUnit(c.backend, c.name)) }, out) != 0)
			note = "Die Konfiguration wurde geschrieben, der Dienst konnte aber nicht gestartet werden:\n\n" + svcprobe::trimmed(out);
		return true;
	}
	// strongSwan
	std::string conf = "# Von ice2k \"Routing und RAS\" erzeugt.\nconnections {\n"
	                   "    " + c.name + " {\n"
	                   "        version = 2\n        pools = " + c.name + "_pool\n"
	                   "        local {\n            auth = pubkey\n            certs = server.crt\n        }\n"
	                   "        remote {\n            auth = eap-mschapv2\n            eap_id = %any\n        }\n"
	                   "        children {\n            " + c.name + " {\n"
	                   "                local_ts = 0.0.0.0/0\n                esp_proposals = aes256gcm16-x25519\n            }\n        }\n    }\n}\n\n"
	                   "pools {\n    " + c.name + "_pool {\n        addrs = " + c.subnet + "\n    }\n}\n";
	if (!writeFileAsRoot("/etc/swanctl/conf.d/" + c.name + ".conf", conf, errorMsg)) return false;
	note = "Die Verbindung wurde nach /etc/swanctl/conf.d/" + c.name + ".conf geschrieben.\n\n"
	       "Serverzertifikat und Schlüssel müssen in /etc/swanctl/x509 bzw. /etc/swanctl/private\n"
	       "liegen, die Benutzer in /etc/swanctl/swanctl.conf (secrets). Danach:\n"
	       "systemctl restart strongswan und swanctl --load-all.";
	return true;
}

// Zustand der VPN-Anschluesse fuer den Knoten "Ports".
struct VpnPort {
	std::string name;     // "vpn0"
	std::string device;   // "WireGuard" ...
	std::string status;   // "Aktiv", "Beendet", "Nicht eingerichtet"
};

static std::vector<VpnPort> listVpnPorts(const VpnConfig& c) {
	std::vector<VpnPort> out;
	if (c.backend == VPN_NONE) return out;
	VpnPort p;
	p.name = c.name;
	p.device = vpnLabel(c.backend).text();
	std::string state;
	runAsRootCaptured({ FXString("systemctl"), FXString("is-active"), FXString(vpnUnit(c.backend, c.name)) }, state);
	state = svcprobe::trimmed(state);
	p.status = state == "active" ? "Aktiv" : state.empty() ? "Unbekannt" : ("Beendet (" + state + ")");
	out.push_back(p);
	if (c.backend == VPN_WIREGUARD) {
		// Jeder Peer ist ein "Anschluss".
		std::string raw;
		if (runAsRootCaptured({ FXString("wg"), FXString("show"), FXString(c.name.c_str()), FXString("peers") }, raw) == 0) {
			int n = 1;
			for (auto& line : splitLines(raw)) {
				if (svcprobe::trimmed(line).empty()) continue;
				VpnPort peer;
				peer.name = c.name + "-" + std::to_string(n++);
				peer.device = "WireGuard-Peer";
				peer.status = svcprobe::trimmed(line).substr(0, 20) + "...";
				out.push_back(peer);
			}
		}
	}
	return out;
}

// ---------------------------------------------------------------------
// OpenVPN: eigene kleine Zertifizierungsstelle. Windows 2000 hat dafuer
// die Zertifikatdienste; hier genuegt openssl. Alles liegt unter
// /etc/openvpn/server/pki, die Serverdateien zusaetzlich dort, wo die
// Konfiguration sie erwartet.
// ---------------------------------------------------------------------
static const char* OVPN_DIR = "/etc/openvpn/server";
static const char* OVPN_PKI = "/etc/openvpn/server/pki";

static bool opensslAvailable() {
	std::string out;
	return runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString("command -v openssl") }, out) == 0;
}

// Fuehrt ein Shell-Kommando als root aus und liefert Ausgabe/Erfolg.
static bool rootShell(const std::string& cmd, std::string& out) {
	return runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString(cmd.c_str()) }, out) == 0;
}

static bool createOpenvpnPki(FXString& errorMsg) {
	if (!opensslAvailable()) { errorMsg = "openssl wurde nicht gefunden."; return false; }
	std::string out;
	std::string cmd =
		"set -e\n"
		"umask 077\n"
		"mkdir -p " + std::string(OVPN_PKI) + "/private " + OVPN_PKI + "/issued\n"
		"cd " + OVPN_PKI + "\n"
		"if [ ! -f ca.crt ]; then\n"
		"  openssl req -x509 -newkey rsa:2048 -nodes -keyout private/ca.key -out ca.crt -days 3650 \\\n"
		"    -subj '/CN=ice2k Routing und RAS CA'\n"
		"fi\n"
		"if [ ! -f issued/server.crt ]; then\n"
		"  openssl req -newkey rsa:2048 -nodes -keyout private/server.key -out server.csr -subj '/CN=server'\n"
		"  openssl x509 -req -in server.csr -CA ca.crt -CAkey private/ca.key -CAcreateserial \\\n"
		"    -out issued/server.crt -days 3650 -extfile /dev/stdin <<'EXT'\n"
		"keyUsage = digitalSignature, keyEncipherment\n"
		"extendedKeyUsage = serverAuth\n"
		"EXT\n"
		"  rm -f server.csr\n"
		"fi\n"
		"cp ca.crt " + std::string(OVPN_DIR) + "/ca.crt\n"
		"cp issued/server.crt " + OVPN_DIR + "/server.crt\n"
		"cp private/server.key " + OVPN_DIR + "/server.key\n"
		"chmod 600 " + OVPN_DIR + "/server.key\n";
	if (!rootShell(cmd, out)) {
		errorMsg = FXString("Die Zertifikate konnten nicht erzeugt werden:\n") + svcprobe::trimmed(out).c_str();
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------
// Clients bzw. Benutzer eines VPN-Servers.
// ---------------------------------------------------------------------
struct VpnClient {
	std::string name;
	std::string detail;   // WireGuard: Adresse, OpenVPN: gueltig bis, strongSwan: Anmeldung
};

static std::vector<VpnClient> listVpnClients(const RrasState& st) {
	std::vector<VpnClient> out;
	if (st.vpnBackend == "wireguard") {
		// Die Konsole schreibt vor jedem Peer eine Kennzeile "# Client: <Name>".
		std::string raw;
		runAsRootCaptured({ FXString("cat"), FXString(("/etc/wireguard/" + st.vpnName + ".conf").c_str()) }, raw);
		VpnClient cur;
		bool inPeer = false;
		for (auto& line : splitLines(raw)) {
			std::string l = svcprobe::trimmed(line);
			if (l.rfind("# Client:", 0) == 0) { cur = VpnClient(); cur.name = svcprobe::trimmed(l.substr(9)); continue; }
			if (l == "[Peer]") { inPeer = true; continue; }
			if (l.rfind("AllowedIPs", 0) == 0 && inPeer) {
				size_t eq = l.find('=');
				cur.detail = eq == std::string::npos ? "" : svcprobe::trimmed(l.substr(eq + 1));
				if (cur.name.empty()) cur.name = cur.detail;
				out.push_back(cur);
				cur = VpnClient();
				inPeer = false;
			}
		}
	} else if (st.vpnBackend == "openvpn") {
		std::string raw;
		rootShell("ls -1 " + std::string(OVPN_PKI) + "/issued 2>/dev/null", raw);
		for (auto& line : splitLines(raw)) {
			std::string n = svcprobe::trimmed(line);
			if (n.size() < 5 || n.substr(n.size() - 4) != ".crt" || n == "server.crt") continue;
			VpnClient c;
			c.name = n.substr(0, n.size() - 4);
			std::string end;
			rootShell("openssl x509 -enddate -noout -in " + std::string(OVPN_PKI) + "/issued/" + n + " | cut -d= -f2", end);
			c.detail = "gültig bis " + svcprobe::trimmed(end);
			out.push_back(c);
		}
	} else if (st.vpnBackend == "strongswan") {
		std::string raw;
		runAsRootCaptured({ FXString("cat"), FXString("/etc/swanctl/conf.d/ice2k-users.conf") }, raw);
		for (auto& line : splitLines(raw)) {
			std::string l = svcprobe::trimmed(line);
			if (l.rfind("id = ", 0) != 0) continue;
			VpnClient c;
			c.name = svcprobe::trimmed(l.substr(5));
			c.detail = "EAP-Benutzer";
			out.push_back(c);
		}
	}
	return out;
}

// Naechste freie Adresse im VPN-Netz (x.x.x.2 aufwaerts).
static std::string nextClientAddress(const RrasState& st, const std::vector<VpnClient>& clients) {
	unsigned a = 0, b = 0, c = 0, d = 0;
	if (sscanf(st.vpnSubnet.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return "";
	for (unsigned host = 2; host < 255; host++) {
		char buf[24];
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a, b, c, host);
		bool used = false;
		for (auto& cl : clients) if (cl.detail.rfind(buf, 0) == 0) used = true;
		if (st.vpnServerIp == buf) used = true;
		if (!used) return buf;
	}
	return "";
}

// Legt einen Client an. clientConfig bekommt bei WireGuard/OpenVPN die
// fertige Clientkonfiguration zum Weitergeben.
static bool addVpnClient(const RrasState& st, const std::string& name, const std::string& password,
                         std::string& clientConfig, FXString& errorMsg) {
	clientConfig.clear();
	if (st.vpnBackend == "wireguard") {
		std::string key, pub, serverPub, out;
		if (!rootShell("wg genkey", key)) { errorMsg = "wg genkey ist fehlgeschlagen."; return false; }
		key = svcprobe::trimmed(key);
		rootShell("echo '" + key + "' | wg pubkey", pub);
		pub = svcprobe::trimmed(pub);
		rootShell("sed -n 's/^PrivateKey *= *//p' /etc/wireguard/" + st.vpnName + ".conf | head -1 | wg pubkey", serverPub);
		serverPub = svcprobe::trimmed(serverPub);
		std::vector<VpnClient> existing = listVpnClients(st);
		std::string addr = nextClientAddress(st, existing);
		if (addr.empty()) { errorMsg = "Im VPN-Netzwerk ist keine Adresse mehr frei."; return false; }
		std::string peer = "\n# Client: " + name + "\n[Peer]\nPublicKey = " + pub + "\nAllowedIPs = " + addr + "/32\n";
		if (!rootShell("cat >> /etc/wireguard/" + st.vpnName + ".conf <<'PEEREOF'" + peer + "PEEREOF", out)) {
			errorMsg = FXString("Der Peer konnte nicht eingetragen werden:\n") + svcprobe::trimmed(out).c_str();
			return false;
		}
		// Sofort wirksam, falls die Schnittstelle laeuft.
		rootShell("wg set " + st.vpnName + " peer " + pub + " allowed-ips " + addr + "/32 2>/dev/null", out);
		clientConfig =
			"[Interface]\nPrivateKey = " + key + "\nAddress = " + addr + "/32\n\n"
			"[Peer]\nPublicKey = " + serverPub + "\nEndpoint = <Serveradresse>:" + st.vpnPort + "\n"
			"AllowedIPs = " + st.vpnSubnet + "\nPersistentKeepalive = 25\n";
		return true;
	}
	if (st.vpnBackend == "openvpn") {
		std::string out;
		std::string cmd =
			"set -e\numask 077\ncd " + std::string(OVPN_PKI) + "\n"
			"openssl req -newkey rsa:2048 -nodes -keyout private/" + name + ".key -out " + name + ".csr -subj '/CN=" + name + "'\n"
			"openssl x509 -req -in " + name + ".csr -CA ca.crt -CAkey private/ca.key -CAcreateserial "
			"-out issued/" + name + ".crt -days 3650\n"
			"rm -f " + name + ".csr\n";
		if (!rootShell(cmd, out)) {
			errorMsg = FXString("Das Clientzertifikat konnte nicht erzeugt werden:\n") + svcprobe::trimmed(out).c_str();
			return false;
		}
		std::string ca, crt, keyText;
		rootShell("cat " + std::string(OVPN_PKI) + "/ca.crt", ca);
		rootShell("cat " + std::string(OVPN_PKI) + "/issued/" + name + ".crt", crt);
		rootShell("cat " + std::string(OVPN_PKI) + "/private/" + name + ".key", keyText);
		clientConfig =
			"client\ndev tun\nproto udp\nremote <Serveradresse> " + st.vpnPort + "\n"
			"resolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nverb 3\n\n"
			"<ca>\n" + ca + "</ca>\n<cert>\n" + crt + "</cert>\n<key>\n" + keyText + "</key>\n";
		return true;
	}
	// strongSwan: EAP-Benutzer in einer eigenen Datei
	if (password.empty()) { errorMsg = "Für strongSwan wird ein Kennwort benötigt."; return false; }
	std::string existing;
	runAsRootCaptured({ FXString("cat"), FXString("/etc/swanctl/conf.d/ice2k-users.conf") }, existing);
	std::string body = existing.find("secrets") == std::string::npos ? "# Von ice2k \"Routing und RAS\" verwaltet.\nsecrets {\n}\n" : existing;
	size_t close = body.rfind("}");
	std::string entry = "    eap-" + name + " {\n        id = " + name + "\n        secret = \"" + password + "\"\n    }\n";
	body.insert(close, entry);
	if (!writeFileAsRoot("/etc/swanctl/conf.d/ice2k-users.conf", body, errorMsg)) return false;
	std::string out;
	rootShell("chmod 600 /etc/swanctl/conf.d/ice2k-users.conf; swanctl --load-creds 2>/dev/null", out);
	return true;
}

static bool removeVpnClient(const RrasState& st, const VpnClient& client, FXString& errorMsg) {
	std::string out;
	if (st.vpnBackend == "wireguard") {
		// Den Block "# Client: <Name>" bis zur naechsten Leerzeile entfernen.
		std::string raw;
		runAsRootCaptured({ FXString("cat"), FXString(("/etc/wireguard/" + st.vpnName + ".conf").c_str()) }, raw);
		std::string result;
		bool skip = false;
		std::string pub;
		for (auto& line : splitLines(raw)) {
			std::string l = svcprobe::trimmed(line);
			if (l == "# Client: " + client.name) { skip = true; continue; }
			if (skip) {
				if (l.rfind("PublicKey", 0) == 0) { size_t eq = l.find('='); pub = svcprobe::trimmed(l.substr(eq + 1)); }
				if (l.rfind("AllowedIPs", 0) == 0) { skip = false; continue; }
				continue;
			}
			result += line + "\n";
		}
		if (!writeFileAsRoot("/etc/wireguard/" + st.vpnName + ".conf", result, errorMsg)) return false;
		runAsRoot({ FXString("chmod"), FXString("600"), FXString(("/etc/wireguard/" + st.vpnName + ".conf").c_str()) });
		if (!pub.empty()) rootShell("wg set " + st.vpnName + " peer " + pub + " remove 2>/dev/null", out);
		return true;
	}
	if (st.vpnBackend == "openvpn") {
		rootShell("rm -f " + std::string(OVPN_PKI) + "/issued/" + client.name + ".crt " +
		          OVPN_PKI + "/private/" + client.name + ".key", out);
		return true;
	}
	std::string raw;
	runAsRootCaptured({ FXString("cat"), FXString("/etc/swanctl/conf.d/ice2k-users.conf") }, raw);
	std::string result;
	bool skip = false;
	for (auto& line : splitLines(raw)) {
		std::string l = svcprobe::trimmed(line);
		if (l == "eap-" + client.name + " {") { skip = true; continue; }
		if (skip) { if (l == "}") skip = false; continue; }
		result += line + "\n";
	}
	if (!writeFileAsRoot("/etc/swanctl/conf.d/ice2k-users.conf", result, errorMsg)) return false;
	rootShell("swanctl --load-creds 2>/dev/null", out);
	return true;
}

// Dialog "Neuer Client" -- Name und (nur bei strongSwan) Kennwort.
class NewVpnClientDialog : public FXDialogBox {
	FXDECLARE(NewVpnClientDialog)
private:
	FXTextField *nameField = nullptr, *passField = nullptr;
protected:
	NewVpnClientDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	NewVpnClientDialog(FXWindow* owner, const FXString& backendLabel, bool needPassword)
		: FXDialogBox(owner, "Neuer Client", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,4);
		new FXLabel(main, "Neuer Client für " + backendLabel, NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		auto row = [&](const char* label) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,110,0);
			return new FXTextField(r, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		};
		nameField = row("&Name:");
		if (needPassword) {
			passField = row("&Kennwort:");
			passField->setTextStyle(TEXTFIELD_PASSWD);
		}
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		std::string n = svcprobe::trimmed(nameField->getText().text());
		if (n.empty() || n.find_first_of(" /\\\"'") != std::string::npos) {
			FXMessageBox::error(this, MBOX_OK, "Neuer Client", "Geben Sie einen Namen ohne Leer- und Sonderzeichen an.");
			return 1;
		}
		if (passField && svcprobe::trimmed(passField->getText().text()).empty()) {
			FXMessageBox::error(this, MBOX_OK, "Neuer Client", "Geben Sie ein Kennwort an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string name() const { return svcprobe::trimmed(nameField->getText().text()); }
	std::string password() const { return passField ? svcprobe::trimmed(passField->getText().text()) : std::string(); }
	virtual ~NewVpnClientDialog() {}
};
FXDEFMAP(NewVpnClientDialog) NewVpnClientDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewVpnClientDialog::ID_OK, NewVpnClientDialog::onOk),
};
FXIMPLEMENT(NewVpnClientDialog, FXDialogBox, NewVpnClientDialogMap, ARRAYNUMBER(NewVpnClientDialogMap))

// Zeigt die Clientkonfiguration und speichert sie auf Wunsch.
class ClientConfigDialog : public FXDialogBox {
	FXDECLARE(ClientConfigDialog)
private:
	FXText* text = nullptr;
	std::string suggested;
protected:
	ClientConfigDialog() {}
public:
	enum { ID_SAVE = FXDialogBox::ID_LAST };
	ClientConfigDialog(FXWindow* owner, const FXString& title, const std::string& content, const std::string& suggestedFile)
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,620,460), suggested(suggestedFile) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Diese Konfiguration gehört auf den Client:", NULL, JUSTIFY_LEFT);
		FXPacker* tf = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		text = new FXText(tf, NULL, 0, TEXT_READONLY | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		text->setText(content.c_str());
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXButton(btnf, "&Speichern unter...", NULL, this, ID_SAVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "Schließen", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onSave(FXObject*, FXSelector, void*) {
		FXString file = FXFileDialog::getSaveFilename(this, "Speichern unter", suggested.c_str());
		if (file.empty()) return 1;
		std::ofstream out(file.text(), std::ios::binary);
		if (!out) { FXMessageBox::error(this, MBOX_OK, "Speichern", "Die Datei konnte nicht geschrieben werden."); return 1; }
		out << text->getText().text();
		return 1;
	}
	virtual ~ClientConfigDialog() {}
};
FXDEFMAP(ClientConfigDialog) ClientConfigDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, ClientConfigDialog::ID_SAVE, ClientConfigDialog::onSave),
};
FXIMPLEMENT(ClientConfigDialog, FXDialogBox, ClientConfigDialogMap, ARRAYNUMBER(ClientConfigDialogMap))

// ---------------------------------------------------------------------
// Paketfilter je Schnittstelle -- Dialoge nach rtrfiltr.dll (14002
// "Eingabefilter"/"Ausgabefilter" und 14003 "IP-Filter"). Unterbau ist
// nftables: die Filter stehen in /etc/ice2k/rras-filters, daraus wird
// /etc/ice2k/rras-filter.nft erzeugt und mit "nft -f" geladen.
// ---------------------------------------------------------------------
struct PacketFilter {
	std::string iface;
	bool input = true;          // true = Eingabefilter, false = Ausgabefilter
	bool dropExcept = false;    // false = alle annehmen ausser..., true = alle verwerfen ausser...
	std::string src, srcMask, dst, dstMask;
	std::string proto;          // "", "tcp", "udp", "icmp"
	std::string sport, dport;
};

static const char* RRAS_FILTERS = "/etc/ice2k/rras-filters";
static const char* RRAS_FILTER_NFT = "/etc/ice2k/rras-filter.nft";

static std::vector<std::string> splitFields(const std::string& line, char sep) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : line) { if (c == sep) { out.push_back(cur); cur.clear(); } else cur += c; }
	out.push_back(cur);
	return out;
}

static std::vector<PacketFilter> loadFilters() {
	std::vector<PacketFilter> out;
	for (auto& line : splitLines(readFileUnprivileged(RRAS_FILTERS))) {
		if (line.empty() || line[0] == '#') continue;
		std::vector<std::string> f = splitFields(line, '|');
		if (f.size() < 10) continue;
		PacketFilter p;
		p.iface = f[0]; p.input = f[1] == "in"; p.dropExcept = f[2] == "drop";
		p.src = f[3]; p.srcMask = f[4]; p.dst = f[5]; p.dstMask = f[6];
		p.proto = f[7]; p.sport = f[8]; p.dport = f[9];
		out.push_back(p);
	}
	return out;
}

// Erzeugt das nftables-Regelwerk und laedt es.
static bool applyFilters(const std::vector<PacketFilter>& filters, FXString& errorMsg) {
	std::string content = "# Von ice2k \"Routing und RAS\" erzeugt -- nicht von Hand ändern.\n"
	                      "table inet ice2k_rras\ndelete table inet ice2k_rras\n"
	                      "table inet ice2k_rras {\n";
	auto rulesFor = [&](bool input) {
		std::string hook = input ? "input" : "output";
		std::string chain = "\tchain " + hook + " {\n\t\ttype filter hook " + hook + " priority 0; policy accept;\n";
		// Je Schnittstelle: die Kriterien zuerst, danach die Grundregel.
		std::vector<std::string> ifaces;
		for (auto& f : filters) {
			if (f.input != input) continue;
			if (std::find(ifaces.begin(), ifaces.end(), f.iface) == ifaces.end()) ifaces.push_back(f.iface);
		}
		for (auto& iface : ifaces) {
			bool dropExcept = false;
			for (auto& f : filters) if (f.input == input && f.iface == iface) dropExcept = f.dropExcept;
			for (auto& f : filters) {
				if (f.input != input || f.iface != iface) continue;
				std::string r = "\t\t" + std::string(input ? "iifname \"" : "oifname \"") + iface + "\"";
				if (!f.src.empty()) r += " ip saddr " + f.src + (f.srcMask.empty() ? "" : "/" + std::to_string(maskToPrefix(f.srcMask)));
				if (!f.dst.empty()) r += " ip daddr " + f.dst + (f.dstMask.empty() ? "" : "/" + std::to_string(maskToPrefix(f.dstMask)));
				if (!f.proto.empty()) r += " ip protocol " + f.proto;
				if (!f.sport.empty() && (f.proto == "tcp" || f.proto == "udp")) r += " " + f.proto + " sport " + f.sport;
				if (!f.dport.empty() && (f.proto == "tcp" || f.proto == "udp")) r += " " + f.proto + " dport " + f.dport;
				r += dropExcept ? " accept\n" : " drop\n";
				chain += r;
			}
			// Grundregel der Schnittstelle
			chain += "\t\t" + std::string(input ? "iifname \"" : "oifname \"") + iface + "\" " + (dropExcept ? "drop\n" : "accept\n");
		}
		chain += "\t}\n";
		return chain;
	};
	content += rulesFor(true);
	content += rulesFor(false);
	content += "}\n";
	if (!writeFileAsRoot(RRAS_FILTER_NFT, content, errorMsg)) return false;
	std::string out;
	if (runAsRootCaptured({ FXString("nft"), FXString("-f"), FXString(RRAS_FILTER_NFT) }, out) != 0) {
		errorMsg = FXString("Die Filter konnten nicht geladen werden:\n") + svcprobe::trimmed(out).c_str();
		return false;
	}
	return true;
}

static bool saveFilters(const std::vector<PacketFilter>& filters, FXString& errorMsg) {
	std::string content = "# Paketfilter, von ice2k \"Routing und RAS\" verwaltet.\n"
	                      "# Schnittstelle|in/out|accept/drop|Quelle|Quellmaske|Ziel|Zielmaske|Protokoll|Quellport|Zielport\n";
	for (auto& f : filters)
		content += f.iface + "|" + (f.input ? "in" : "out") + "|" + (f.dropExcept ? "drop" : "accept") + "|" +
		           f.src + "|" + f.srcMask + "|" + f.dst + "|" + f.dstMask + "|" + f.proto + "|" + f.sport + "|" + f.dport + "\n";
	if (!writeFileAsRoot(RRAS_FILTERS, content, errorMsg)) return false;
	return applyFilters(filters, errorMsg);
}

// Dialog "IP-Filter" (rtrfiltr.dll, 14003).
class IpFilterDialog : public FXDialogBox {
	FXDECLARE(IpFilterDialog)
private:
	FXCheckButton *srcCheck = nullptr, *dstCheck = nullptr;
	FXTextField *srcAddr = nullptr, *srcMask = nullptr, *dstAddr = nullptr, *dstMask = nullptr, *sport = nullptr, *dport = nullptr;
	FXListBox* protoBox = nullptr;
	std::vector<FXWindow*> srcCtrl, dstCtrl;
protected:
	IpFilterDialog() {}
public:
	enum { ID_SRC = FXDialogBox::ID_LAST, ID_DST, ID_PROTO, ID_OK };
	IpFilterDialog(FXWindow* owner, const PacketFilter& f)
		: FXDialogBox(owner, "IP-Filter", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,4);
		srcCheck = new FXCheckButton(main, "Quell&netzwerk", this, ID_SRC);
		FXVerticalFrame* sf = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 16,0,0,0, 0,2);
		auto row = [&](FXComposite* p, const char* label, std::vector<FXWindow*>* reg) {
			FXHorizontalFrame* r = new FXHorizontalFrame(p, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			FXLabel* l = new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,110,0);
			FXTextField* tf = new FXTextField(r, 16, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			if (reg) { reg->push_back(l); reg->push_back(tf); }
			return tf;
		};
		srcAddr = row(sf, "&IP-Adresse:", &srcCtrl);
		srcMask = row(sf, "Subnetz&maske:", &srcCtrl);
		dstCheck = new FXCheckButton(main, "&Zielnetzwerk", this, ID_DST);
		FXVerticalFrame* df = new FXVerticalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 16,0,0,0, 0,2);
		dstAddr = row(df, "IP-&Adresse:", &dstCtrl);
		dstMask = row(df, "S&ubnetzmaske:", &dstCtrl);
		FXHorizontalFrame* pr = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,6,0);
		new FXLabel(pr, "&Protokoll:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,110,0);
		protoBox = new FXListBox(pr, this, ID_PROTO, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		// Reihenfolge und Namen wie rtrfiltr.dll (Texte 12-15).
		protoBox->appendItem("Beliebig");
		protoBox->appendItem("TCP");
		protoBox->appendItem("UDP");
		protoBox->appendItem("ICMP");
		protoBox->setNumVisible(4);
		sport = row(main, "&Quellport:", NULL);
		dport = row(main, "Zie&lport:", NULL);

		srcCheck->setCheck(!f.src.empty());
		dstCheck->setCheck(!f.dst.empty());
		srcAddr->setText(f.src.c_str()); srcMask->setText(f.srcMask.empty() ? "255.255.255.0" : f.srcMask.c_str());
		dstAddr->setText(f.dst.c_str()); dstMask->setText(f.dstMask.empty() ? "255.255.255.0" : f.dstMask.c_str());
		protoBox->setCurrentItem(f.proto == "tcp" ? 1 : f.proto == "udp" ? 2 : f.proto == "icmp" ? 3 : 0);
		sport->setText(f.sport.c_str());
		dport->setText(f.dport.c_str());

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		update2();
	}
	void update2() {
		for (auto* w : srcCtrl) { if (srcCheck->getCheck()) w->enable(); else w->disable(); }
		for (auto* w : dstCtrl) { if (dstCheck->getCheck()) w->enable(); else w->disable(); }
		bool ports = protoBox->getCurrentItem() == 1 || protoBox->getCurrentItem() == 2;
		if (ports) { sport->enable(); dport->enable(); } else { sport->disable(); dport->disable(); }
	}
	long onToggle(FXObject*, FXSelector, void*) { update2(); return 1; }
	long onOk(FXObject*, FXSelector, void*) {
		unsigned a,b,c,d;
		if (srcCheck->getCheck() && sscanf(svcprobe::trimmed(srcAddr->getText().text()).c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) {
			FXMessageBox::error(this, MBOX_OK, "IP-Filter", "Geben Sie eine IP-Adresse für die Quelle an."); return 1;
		}
		if (dstCheck->getCheck() && sscanf(svcprobe::trimmed(dstAddr->getText().text()).c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) {
			FXMessageBox::error(this, MBOX_OK, "IP-Filter", "Geben Sie eine IP-Adresse für das Ziel an."); return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	PacketFilter filter() const {
		PacketFilter f;
		if (srcCheck->getCheck()) { f.src = svcprobe::trimmed(srcAddr->getText().text()); f.srcMask = svcprobe::trimmed(srcMask->getText().text()); }
		if (dstCheck->getCheck()) { f.dst = svcprobe::trimmed(dstAddr->getText().text()); f.dstMask = svcprobe::trimmed(dstMask->getText().text()); }
		int p = protoBox->getCurrentItem();
		f.proto = p == 1 ? "tcp" : p == 2 ? "udp" : p == 3 ? "icmp" : "";
		if (p == 1 || p == 2) { f.sport = svcprobe::trimmed(sport->getText().text()); f.dport = svcprobe::trimmed(dport->getText().text()); }
		return f;
	}
	virtual ~IpFilterDialog() {}
};
FXDEFMAP(IpFilterDialog) IpFilterDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, IpFilterDialog::ID_SRC, IpFilterDialog::onToggle),
	FXMAPFUNC(SEL_COMMAND, IpFilterDialog::ID_DST, IpFilterDialog::onToggle),
	FXMAPFUNC(SEL_COMMAND, IpFilterDialog::ID_PROTO, IpFilterDialog::onToggle),
	FXMAPFUNC(SEL_COMMAND, IpFilterDialog::ID_OK, IpFilterDialog::onOk),
};
FXIMPLEMENT(IpFilterDialog, FXDialogBox, IpFilterDialogMap, ARRAYNUMBER(IpFilterDialogMap))

// Dialog "Eingabefilter"/"Ausgabefilter" (rtrfiltr.dll, 14002).
class FilterListDialog : public FXDialogBox {
	FXDECLARE(FilterListDialog)
private:
	std::vector<PacketFilter> filters;   // nur die dieser Schnittstelle/Richtung
	std::string iface;
	bool input = true;
	FXint action = 0;                    // 0 = alle annehmen ausser..., 1 = alle verwerfen ausser...
	FXDataTarget actionTarget;
	FXIconList* list = nullptr;
protected:
	FilterListDialog() {}
public:
	enum { ID_ADD = FXDialogBox::ID_LAST, ID_EDIT, ID_REMOVE };
	FilterListDialog(FXWindow* owner, const std::string& iface_, bool input_, const std::vector<PacketFilter>& initial)
		: FXDialogBox(owner, input_ ? "Eingabefilter" : "Ausgabefilter", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,620,420),
		  filters(initial), iface(iface_), input(input_), actionTarget(action) {
		if (!filters.empty()) action = filters[0].dropExcept ? 1 : 0;
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, input
			? "Diese Filter steuern, welche Pakete für Weiterleitung oder Verarbeitung auf\ndieser Schnittstelle empfangen werden."
			: "Diese Filter steuern, welche Pakete über diese Schnittstelle gesendet werden.", NULL, JUSTIFY_LEFT);
		new FXRadioButton(main, input ? "Alle Pakete e&mpfangen, mit Ausnahme derjenigen, die die unten aufgeführten Kriterien erfüllen"
		                              : "Alle Pakete über&tragen, mit Ausnahme derjenigen, die die unten aufgeführten Kriterien erfüllen",
		                  &actionTarget, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(main, "Alle Pakete &verwerfen, mit Ausnahme derjenigen, die die unten aufgeführten Kriterien erfüllen",
		                  &actionTarget, FXDataTarget::ID_OPTION + 1);
		new FXLabel(main, "&Filter:", NULL, JUSTIFY_LEFT);
		FXPacker* lf = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		list = new FXIconList(lf, NULL, 0, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		// Spalten wie rtrfiltr.dll (Texte 5-11).
		for (auto& c : { std::make_pair("Quelladresse", 110), std::make_pair("Quellmaske", 110), std::make_pair("Zieladresse", 110),
		                 std::make_pair("Zielmaske", 110), std::make_pair("Protokoll", 80), std::make_pair("Quellport oder -typ", 120),
		                 std::make_pair("Zielport oder -code", 120) })
			list->appendHeader(c.first, NULL, c.second);
		FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXButton(btns, "&Hinzufügen...", NULL, this, ID_ADD, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "Be&arbeiten...", NULL, this, ID_EDIT, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXButton(btns, "&Entfernen", NULL, this, ID_REMOVE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 10,10,3,3);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		reload();
	}
	void reload() {
		list->clearItems();
		for (auto& f : filters) {
			FXString proto = f.proto.empty() ? "Beliebig" : f.proto == "tcp" ? "TCP" : f.proto == "udp" ? "UDP" : "ICMP";
			list->appendItem(FXString(f.src.empty() ? "Beliebig" : f.src.c_str()) + "\t" + (f.srcMask.empty() ? "-" : f.srcMask.c_str()) + "\t" +
			                 (f.dst.empty() ? "Beliebig" : f.dst.c_str()) + "\t" + (f.dstMask.empty() ? "-" : f.dstMask.c_str()) + "\t" +
			                 proto + "\t" + (f.sport.empty() ? "-" : f.sport.c_str()) + "\t" + (f.dport.empty() ? "-" : f.dport.c_str()));
		}
	}
	long onAdd(FXObject*, FXSelector, void*) {
		IpFilterDialog dlg(this, PacketFilter());
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		PacketFilter f = dlg.filter();
		f.iface = iface; f.input = input;
		filters.push_back(f);
		reload();
		return 1;
	}
	long onEdit(FXObject*, FXSelector, void*) {
		int i = list->getCurrentItem();
		if (i < 0 || i >= (int)filters.size()) return 1;
		IpFilterDialog dlg(this, filters[i]);
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		PacketFilter f = dlg.filter();
		f.iface = iface; f.input = input;
		filters[i] = f;
		reload();
		return 1;
	}
	long onRemove(FXObject*, FXSelector, void*) {
		int i = list->getCurrentItem();
		if (i >= 0 && i < (int)filters.size()) { filters.erase(filters.begin() + i); reload(); }
		return 1;
	}
	std::vector<PacketFilter> result() const {
		std::vector<PacketFilter> out = filters;
		for (auto& f : out) f.dropExcept = (action == 1);
		return out;
	}
	virtual ~FilterListDialog() {}
};
FXDEFMAP(FilterListDialog) FilterListDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, FilterListDialog::ID_ADD, FilterListDialog::onAdd),
	FXMAPFUNC(SEL_COMMAND, FilterListDialog::ID_EDIT, FilterListDialog::onEdit),
	FXMAPFUNC(SEL_COMMAND, FilterListDialog::ID_REMOVE, FilterListDialog::onRemove),
};
FXIMPLEMENT(FilterListDialog, FXDialogBox, FilterListDialogMap, ARRAYNUMBER(FilterListDialogMap))

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
	           *ipGeneralItem = nullptr, *staticRoutesItem = nullptr, *clientsItem = nullptr;
	std::vector<VpnClient> shownClients;
	FXIconList* itemList = nullptr;
	std::vector<RouteInfo> shownRoutes;
	FXIcon *icoRoot = nullptr, *icoStatus = nullptr, *icoServerStopped = nullptr, *icoServerStarted = nullptr,
	       *icoInfo = nullptr, *icoNetwork = nullptr;
	RrasState state;
protected:
	RrasWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_CONFIGURE, ID_DEACTIVATE, ID_PROPERTIES, ID_REFRESH, ID_ABOUT,
	       ID_LIST, ID_NEW_ROUTE, ID_DELETE_ROUTE, ID_IN_FILTER, ID_OUT_FILTER, ID_NEW_CLIENT, ID_DELETE_CLIENT };

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
	long onFilter(FXObject*, FXSelector, void*);
	long onNewClient(FXObject*, FXSelector, void*);
	long onDeleteClient(FXObject*, FXSelector, void*);
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
	FXMAPFUNCS(SEL_COMMAND, RrasWindow::ID_IN_FILTER, RrasWindow::ID_OUT_FILTER, RrasWindow::onFilter),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_NEW_CLIENT, RrasWindow::onNewClient),
	FXMAPFUNC(SEL_COMMAND, RrasWindow::ID_DELETE_CLIENT, RrasWindow::onDeleteClient),
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
	for (FXTreeItem* it : { staticRoutesItem, ipGeneralItem, ipRoutingItem, clientsItem, portsItem, ifacesItem })
		if (it) tree->removeItem(it);
	ifacesItem = portsItem = ipRoutingItem = ipGeneralItem = staticRoutesItem = clientsItem = nullptr;
	if (!state.configured()) return;
	ifacesItem = tree->appendItem(serverItem, "Routingschnittstellen", icoNetwork, icoNetwork);
	portsItem = tree->appendItem(serverItem, "Ports", icoStatus, icoStatus);
	// "RAS-Clients" (mprsnap.dll, Text 20) -- hier die Peers bzw. Benutzer
	// des eingerichteten VPN-Dienstes.
	if (state.role == ROLE_VPN) clientsItem = tree->appendItem(serverItem, "RAS-Clients", icoNetwork, icoNetwork);
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
	if (item && (item == ifacesItem || item == portsItem || item == ipGeneralItem || item == staticRoutesItem || item == clientsItem)) {
		rightPane->setCurrent(2);
		shownRoutes.clear();
		shownClients.clear();
		if (item == clientsItem) {
			setColumns({ { "Name", 220 }, { "Typ", 180 }, { "Details", 300 } });
			shownClients = listVpnClients(state);
			FXString typeName = state.vpnBackend == "wireguard" ? "WireGuard-Peer"
			                  : state.vpnBackend == "openvpn" ? "OpenVPN-Zertifikat" : "EAP-Benutzer";
			for (auto& c : shownClients)
				itemList->appendItem(FXString(c.name.c_str()) + "\t" + typeName + "\t" + c.detail.c_str(), icoNetwork, icoNetwork);
			statusbar->setText(" Rechtsklick in die Liste: Neuen Client anlegen oder einen Client löschen.");
			return;
		}
		if (item == ifacesItem) {
			// Spalten wie mprsnap.dll (14-17).
			setColumns({ { "Schnittstelle", 200 }, { "Typ", 160 }, { "Status", 120 }, { "Status der Verbindung", 160 } });
			for (auto& i : listInterfaces())
				itemList->appendItem(FXString(i.name.c_str()) + "\t" + i.type.c_str() + "\t" +
				                     (i.up ? "Aktiviert" : "Deaktiviert") + "\t" + (i.running ? "Verbunden" : "Getrennt"),
				                     icoNetwork, icoNetwork);
			statusbar->setText(" LAN-Schnittstellen und Schnittstellen für Wählen bei Bedarf");
		} else if (item == portsItem) {
			setColumns({ { "Name", 220 }, { "Gerät", 200 }, { "Status", 220 } });
			VpnConfig c;
			c.backend = state.vpnBackend == "wireguard" ? VPN_WIREGUARD : state.vpnBackend == "openvpn" ? VPN_OPENVPN
			          : state.vpnBackend == "strongswan" ? VPN_STRONGSWAN : VPN_NONE;
			c.name = state.vpnName;
			for (auto& p : listVpnPorts(c))
				itemList->appendItem(FXString(p.name.c_str()) + "\t" + p.device.c_str() + "\t" + p.status.c_str(), icoNetwork, icoNetwork);
			statusbar->setText(state.role == ROLE_VPN
				? FXString(" VPN-Server: ") + state.vpnBackend.c_str() + ", Netzwerk " + state.vpnSubnet.c_str() + ", Port " + state.vpnPort.c_str()
				: FXString(" Es ist kein VPN-Server eingerichtet. Einwählanschlüsse (Modem/ISDN) sind nicht umgesetzt."));
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
	std::string vpnNote;
	if (st.role == ROLE_VPN) {
		VpnSetupDialog vdlg(this);
		if (!vdlg.execute(PLACEMENT_OWNER)) return 1;
		VpnConfig c = vdlg.config();
		if (!setupVpn(c, vdlg.createPki(), vpnNote, errorMsg)) {
			FXMessageBox::error(this, MBOX_OK, "VPN-Server", "%s", errorMsg.text());
			return 1;
		}
		st.vpnBackend = vpnKeyword(c.backend);
		st.vpnName = c.name;
		st.vpnPort = c.port;
		st.vpnSubnet = c.subnet;
		st.vpnServerIp = c.serverIp;
	}
	if (!applyForwarding(true, errorMsg) || !writeState(st, errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "%s", errorMsg.text());
		reload();
		return 1;
	}
	// Damit Routen und Filter einen Neustart überstehen.
	{
		FXString e;
		if (installRrasUnit(e)) {
			std::string note;
			enableRrasUnit(true, note);
			if (!note.empty()) vpnNote += (vpnNote.empty() ? "" : "\n\n") + note;
		} else {
			vpnNote += (vpnNote.empty() ? "" : "\n\n") + std::string(e.text());
		}
	}
	// Gemerkte Paketfilter wieder laden.
	{
		std::vector<PacketFilter> f = loadFilters();
		if (!f.empty()) { FXString e; applyFilters(f, e); }
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
	FXString msg = "Routing und RAS wurde aktiviert.\n\nDie IP-Weiterleitung ist eingeschaltet und bleibt es auch nach einem Neustart.";
	if (!vpnNote.empty()) msg += FXString("\n\n") + vpnNote.c_str();
	FXMessageBox::information(this, MBOX_OK, "Routing und RAS", "%s", msg.text());
	return 1;
}

long RrasWindow::onDeactivate(FXObject*, FXSelector, void*) {
	if (FXMessageBox::question(this, MBOX_YES_NO, "Routing und RAS",
	        "Möchten Sie Routing und RAS wirklich deaktivieren?\n\n"
	        "Die IP-Weiterleitung wird abgeschaltet.") != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	RrasState st = state;
	st.role = ROLE_NONE;
	std::string note;
	enableRrasUnit(false, note);
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
	FXEvent* ev = (FXEvent*)ptr;
	// Schnittstellenliste: Ein-/Ausgabefilter wie im Original.
	if (tree->getCurrentItem() == ifacesItem || tree->getCurrentItem() == ipGeneralItem) {
		FXint idx = itemList->getItemAt(ev->win_x, ev->win_y);
		if (idx < 0) return 1;
		itemList->setCurrentItem(idx);
		itemList->selectItem(idx);
		FXMenuPane menu(this);
		new FXMenuCommand(&menu, "&Eingabefilter...", NULL, this, ID_IN_FILTER);
		new FXMenuCommand(&menu, "&Ausgabefilter...", NULL, this, ID_OUT_FILTER);
		menu.create();
		menu.popup(NULL, ev->root_x, ev->root_y);
		getApp()->runModalWhileShown(&menu);
		return 1;
	}
	if (tree->getCurrentItem() == clientsItem) {
		FXint idx = itemList->getItemAt(ev->win_x, ev->win_y);
		if (idx >= 0) { itemList->setCurrentItem(idx); itemList->selectItem(idx); }
		FXMenuPane menu(this);
		new FXMenuCommand(&menu, "&Neuer Client...", NULL, this, ID_NEW_CLIENT);
		if (idx >= 0 && idx < (int)shownClients.size()) {
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETE_CLIENT);
		}
		menu.create();
		menu.popup(NULL, ev->root_x, ev->root_y);
		getApp()->runModalWhileShown(&menu);
		return 1;
	}
	if (tree->getCurrentItem() != staticRoutesItem) return 1;
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

// Ein-/Ausgabefilter der markierten Schnittstelle.
long RrasWindow::onFilter(FXObject* , FXSelector sel, void*) {
	bool input = FXSELID(sel) == ID_IN_FILTER;
	int idx = itemList->getCurrentItem();
	if (idx < 0) return 1;
	std::string iface = itemList->getItemText(idx).section('\t', 0).text();
	std::vector<PacketFilter> all = loadFilters(), mine, others;
	for (auto& f : all) {
		if (f.iface == iface && f.input == input) mine.push_back(f);
		else others.push_back(f);
	}
	FilterListDialog dlg(this, iface, input, mine);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	std::vector<PacketFilter> result = others;
	for (auto& f : dlg.result()) result.push_back(f);
	FXString errorMsg;
	if (!saveFilters(result, errorMsg))
		FXMessageBox::error(this, MBOX_OK, input ? "Eingabefilter" : "Ausgabefilter", "%s", errorMsg.text());
	return 1;
}

// Neuer Peer (WireGuard), neues Clientzertifikat (OpenVPN) oder neuer
// EAP-Benutzer (strongSwan).
long RrasWindow::onNewClient(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "Routing und RAS", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	bool needPassword = state.vpnBackend == "strongswan";
	FXString backendLabel = state.vpnBackend == "wireguard" ? "WireGuard" : state.vpnBackend == "openvpn" ? "OpenVPN" : "strongSwan";
	NewVpnClientDialog dlg(this, backendLabel, needPassword);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	std::string config;
	FXString errorMsg;
	getApp()->beginWaitCursor();
	bool ok = addVpnClient(state, dlg.name(), dlg.password(), config, errorMsg);
	getApp()->endWaitCursor();
	if (!ok) { FXMessageBox::error(this, MBOX_OK, "Neuer Client", "%s", errorMsg.text()); return 1; }
	showFor(tree->getCurrentItem());
	if (!config.empty()) {
		std::string file = dlg.name() + (state.vpnBackend == "wireguard" ? ".conf" : ".ovpn");
		ClientConfigDialog cfg(this, FXString("Clientkonfiguration für ") + dlg.name().c_str(), config, file);
		cfg.execute(PLACEMENT_OWNER);
	} else {
		FXMessageBox::information(this, MBOX_OK, "Neuer Client", "Der Benutzer wurde angelegt.");
	}
	return 1;
}

long RrasWindow::onDeleteClient(FXObject*, FXSelector, void*) {
	int idx = itemList->getCurrentItem();
	if (idx < 0 || idx >= (int)shownClients.size()) return 1;
	if (FXMessageBox::question(this, MBOX_YES_NO, "Client löschen",
	        "Möchten Sie den Client \"%s\" wirklich löschen?", shownClients[idx].name.c_str()) != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	if (!removeVpnClient(state, shownClients[idx], errorMsg))
		FXMessageBox::error(this, MBOX_OK, "Client löschen", "%s", errorMsg.text());
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
