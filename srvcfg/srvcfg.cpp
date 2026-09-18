// srvcfg.cpp
//
// "Konfiguration des Servers" fuer ice2k -- Nachbau von "Windows 2000
// Server konfigurieren". Aufbau wie im Original: oben das Kopfbanner,
// links die dunkelblaue Navigationsleiste mit aufklappbaren Gruppen,
// rechts die Inhaltsseite mit Text und Verweisen.
//
// Die Verweise starten die Programme dieses Projekts (dsadmin, dnsmgr,
// dhcpmgr, rras, compmgmt, services, termsvc, secpol, dcpromo). Fuer
// Dienste, die es hier (noch) nicht gibt, sagt die Seite das ausdruecklich
// und nennt, was unter Linux an deren Stelle traete.

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <unistd.h>
#include <sys/wait.h>

static FXApp* app = NULL;

// Farben des Originals
static const FXColor NAV_BG = FXRGB(0, 0, 128);
static const FXColor NAV_FG = FXRGB(255, 255, 255);
static const FXColor PAGE_BG = FXRGB(192, 192, 192);
static const FXColor LINK_FG = FXRGB(0, 0, 192);

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

static std::string trimStr(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

// Ausgabe eines Kommandos einsammeln (ohne root -- hier wird nur gelesen).
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
		char buf[4096];
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

static bool commandExists(const std::string& name) {
	std::string out;
	return runCaptured({ "sh", "-c", "command -v " + name }, out) == 0;
}

static bool unitActive(const std::string& unit) {
	std::string out;
	runCaptured({ "systemctl", "is-active", unit }, out);
	return trimStr(out) == "active";
}

// Startet ein Programm im Hintergrund; leerer Rueckgabewert = gestartet.
static std::string launch(const std::string& program) {
	if (!commandExists(program)) return program;
	pid_t pid = fork();
	if (pid == 0) {
		setsid();
		execlp(program.c_str(), program.c_str(), (char*)NULL);
		_exit(127);
	}
	return "";
}

static std::string launchWithArg(const std::string& program, const std::string& arg) {
	if (!commandExists(program)) return program;
	pid_t pid = fork();
	if (pid == 0) {
		setsid();
		execlp(program.c_str(), program.c_str(), arg.c_str(), (char*)NULL);
		_exit(127);
	}
	return "";
}

// ---------------------------------------------------------------------
// Zustand der Dienste -- das Original schreibt auf jeder Seite, ob der
// Dienst schon eingerichtet ist ("Auf diesem Server ist DHCP
// installiert"). Genauso hier, nur eben anhand der Linux-Dienste.
// ---------------------------------------------------------------------
struct ServerFacts {
	bool isDC = false;
	std::string realm;
	bool dns = false, dhcp = false, smb = false, cups = false, web = false;
	bool rras = false;
	std::string rrasRole;
	bool xrdp = false;
};

static ServerFacts collectFacts() {
	ServerFacts f;
	std::string smb = readFileUnprivileged("/etc/samba/smb.conf");
	for (auto& line : splitLines(smb)) {
		std::string l = trimStr(line);
		size_t eq = l.find('=');
		if (eq == std::string::npos) continue;
		std::string key = trimStr(l.substr(0, eq)), val = trimStr(l.substr(eq + 1));
		for (auto& c : key) c = tolower(c);
		if (key == "server role" && val.find("domain controller") != std::string::npos) f.isDC = true;
		if (key == "realm") f.realm = val;
	}
	f.dns = commandExists("named") || unitActive("named") || unitActive("bind9");
	f.dhcp = commandExists("kea-dhcp4") || unitActive("kea-dhcp4-server");
	f.smb = unitActive("smbd") || unitActive("samba-ad-dc");
	f.cups = unitActive("cups");
	f.web = unitActive("apache2") || unitActive("nginx");
	f.xrdp = unitActive("xrdp");
	for (auto& line : splitLines(readFileUnprivileged("/etc/ice2k/rras.conf"))) {
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		if (trimStr(line.substr(0, eq)) != "role") continue;
		f.rrasRole = trimStr(line.substr(eq + 1));
		f.rras = f.rrasRole != "none" && !f.rrasRole.empty();
	}
	return f;
}

// ---------------------------------------------------------------------
// Inhaltsseiten
// ---------------------------------------------------------------------
enum PageId {
	PG_START = 0, PG_REGISTER, PG_AD, PG_FILE, PG_PRINT,
	PG_WEBMEDIA, PG_WEB, PG_MEDIA,
	PG_NETWORK, PG_DHCP, PG_DNS, PG_REMOTE, PG_ROUTING,
	PG_APPS, PG_COMPONENTS, PG_TERMINAL, PG_DATABASE, PG_MAIL,
	PG_ADVANCED, PG_MANAGEMENT, PG_SECURITY,
	PG_COUNT
};

struct PageLink {
	FXString text;       // angezeigter Verweis
	std::string program; // zu startendes Programm ("" = nur Text)
	std::string arg;
};

struct Page {
	FXString title;
	std::vector<FXString> paragraphs;
	std::vector<PageLink> links;
	std::vector<FXString> after;   // Text unterhalb der Verweise
};

class SrvCfgWindow : public FXMainWindow {
	FXDECLARE(SrvCfgWindow)
private:
	FXTreeList* nav = nullptr;
	FXSwitcher* pages = nullptr;
	FXVerticalFrame* pageFrames[PG_COUNT] = { nullptr };
	FXCheckButton* showAtStart = nullptr;
	std::map<FXTreeItem*, int> itemPage;
	std::map<FXObject*, PageLink> linkTargets;
	ServerFacts facts;
	FXIcon *icoNav = nullptr, *icoLink = nullptr, *icoBanner = nullptr;
protected:
	SrvCfgWindow() {}
public:
	enum { ID_NAV = FXMainWindow::ID_LAST, ID_LINK, ID_SHOWSTART, ID_LAST_ };

	SrvCfgWindow(FXApp* a);
	virtual void create();
	long onNav(FXObject*, FXSelector, void*);
	long onLink(FXObject*, FXSelector, void*);
	long onShowAtStart(FXObject*, FXSelector, void*);
	void buildPage(int id, const Page& p);
	Page makePage(int id);
	virtual ~SrvCfgWindow() {}
};

FXDEFMAP(SrvCfgWindow) SrvCfgWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, SrvCfgWindow::ID_NAV, SrvCfgWindow::onNav),
	FXMAPFUNC(SEL_COMMAND, SrvCfgWindow::ID_LINK, SrvCfgWindow::onLink),
	FXMAPFUNC(SEL_COMMAND, SrvCfgWindow::ID_SHOWSTART, SrvCfgWindow::onShowAtStart),
};
FXIMPLEMENT(SrvCfgWindow, FXMainWindow, SrvCfgWindowMap, ARRAYNUMBER(SrvCfgWindowMap))

// Texte der Seiten -- soweit sinnvoll wortgleich aus dem Original, mit den
// Linux-Diensten an den Stellen, an denen Windows eigene Produkte nennt.
Page SrvCfgWindow::makePage(int id) {
	Page p;
	switch (id) {
		case PG_START:
			p.title = "Konfiguration des Servers";
			p.paragraphs = {
				"Wählen Sie vom Menü auf der linken Seite die Dienste, die Sie auf\n"
				"dem Server ausführen möchten. Sie können einen oder alle Dienste\n"
				"für die Anpassung des Netzwerkes installieren.",
				"•  Klicken Sie im Menü auf den Dienstnamen, um weitere\n"
				"    Informationen über den Dienst zu erhalten.",
				"•  Klicken Sie auf Start, Programme, Verwaltung und dann auf\n"
				"    Konfiguration des Servers, um das Fenster jederzeit wieder zu öffnen." };
			break;
		case PG_REGISTER:
			p.title = "Jetzt registrieren";
			p.paragraphs = {
				"Eine Registrierung wie bei Windows 2000 gibt es hier nicht: ice2k baut auf\n"
				"freier Software auf.",
				"Die verwendeten Dienste und ihre Lizenzen finden Sie in der Dokumentation\n"
				"des Projekts." };
			break;
		case PG_AD:
			p.title = "Active Directory";
			p.paragraphs = { facts.isDC
				? FXString("Active Directory ist bereits installiert. Sie können nun\n"
				          "Benutzerkennungen und Gruppeneinstellungen installieren und\n"
				          "verwalten.") + (facts.realm.empty() ? "" : FXString("\n\nDomäne: ") + facts.realm.c_str())
				: FXString("Auf diesem Server ist Active Directory nicht installiert.\n"
				          "Mit dem Assistenten richten Sie diesen Server als Domänencontroller ein.") };
			p.links = {
				{ "Verwalten von Benutzerkonten und Gruppeneinstellungen", "dsadmin", "" },
				{ "Installieren oder Entfernen von Active Directory (dcpromo)", "dcpromo", "" },
				{ "Sicherheitsrichtlinie für Domänen", "secpol", "--domain" } };
			p.after = { "Wichtig\n"
			            "Wenn Sie Active Directory entfernen, wird dieser Server zum Mitgliedsserver\n"
			            "oder eigenständigen Server zurückgestuft. Vergewissern Sie sich vorher, dass\n"
			            "keine abhängigen Server mit diesem Server verbunden sind." };
			break;
		case PG_FILE:
			p.title = "Dateiserver";
			p.paragraphs = {
				FXString("Verwenden Sie die Computerverwaltung, um neue Freigaben zu erstellen.\n"
				         "Windows-, Linux- und macOS-Clients können über Samba auf Dateien in einem\n"
				         "freigegebenen Ordner zugreifen."),
				facts.smb ? FXString("Der Dateiserverdienst (Samba) läuft auf diesem Server.")
				          : FXString("Der Dateiserverdienst (Samba) läuft zurzeit nicht.") };
			p.links = { { "Öffnen der Computerverwaltung (Freigegebene Ordner)", "compmgmt", "" } };
			break;
		case PG_PRINT:
			p.title = "Druckserver";
			p.paragraphs = {
				"Unter Linux übernimmt CUPS die Aufgaben des Druckservers: Drucker\n"
				"einrichten, freigeben und im Netzwerk bekannt machen.",
				facts.cups ? FXString("Der Druckdienst (CUPS) läuft auf diesem Server.")
				           : FXString("Der Druckdienst (CUPS) läuft zurzeit nicht."),
				"Eine eigene Druckerverwaltung im Windows-2000-Stil gibt es in diesem\n"
				"Projekt noch nicht; bis dahin hilft die Weboberfläche von CUPS." };
			break;
		case PG_WEBMEDIA:
			p.title = "Web- und Mediaserver";
			p.paragraphs = {
				"Dieser Server kann Web- und Medieninhalte bereitstellen.",
				"•  Klicken Sie auf Webserver, um Apache oder nginx einzurichten.",
				"•  Klicken Sie auf Medienserver, um Streaming-Dienste einzurichten." };
			break;
		case PG_WEB:
			p.title = "Webserver";
			p.paragraphs = {
				"An die Stelle der Internetinformationsdienste (IIS) treten unter Linux\n"
				"Apache oder nginx. Damit stellen Sie Web- und Intranetseiten bereit.",
				facts.web ? FXString("Auf diesem Server läuft bereits ein Webserver.")
				          : FXString("Auf diesem Server läuft zurzeit kein Webserver."),
				"Eine eigene Verwaltung im Windows-2000-Stil gibt es dafür noch nicht.\n"
				"Dienst starten und beenden können Sie über \"Dienste\"." };
			p.links = { { "Öffnen der Dienstverwaltung", "services", "" } };
			break;
		case PG_MEDIA:
			p.title = "Medienserver";
			p.paragraphs = {
				"Die Windows-Mediendienste haben unter Linux kein unmittelbares Gegenstück.\n"
				"Für Streaming kommen z.B. Icecast oder ein Medienserver wie Jellyfin infrage.",
				"In diesem Projekt ist dafür nichts umgesetzt." };
			break;
		case PG_NETWORK:
			p.title = "Netzwerk";
			p.paragraphs = {
				"Wählen Sie im Menü auf der linken Seite die Netzwerkdienste, die Sie auf\n"
				"dem Server ausführen möchten.",
				"DHCP vergibt Adressen, DNS löst Namen auf, Remotezugriff und Routing\n"
				"verbinden Netzwerke miteinander." };
			break;
		case PG_DHCP:
			p.title = "DHCP";
			p.paragraphs = {
				facts.dhcp ? FXString("Auf diesem Server ist DHCP (Kea) installiert. Der Bereichserstellungs-\n"
				                      "Assistent dient zur Festlegung von Bereichen von IP-Adressen für Clients.")
				           : FXString("Auf diesem Server ist DHCP (Kea) nicht installiert."),
				"Vorsicht\n"
				"Setzen Sie den Vorgang nicht fort, wenn auf einem weiteren Server im\n"
				"Netzwerk bereits DHCP ausgeführt wird." };
			p.links = { { "Verwalten von DHCP", "dhcpmgr", "" } };
			break;
		case PG_DNS:
			p.title = "DNS";
			p.paragraphs = {
				facts.dns ? FXString("Auf diesem Server ist DNS (BIND) installiert. Zonen ordnen die DNS-\n"
				                     "Hostnamen den zugehörigen IP-Adressen zu.")
				          : FXString("Auf diesem Server ist DNS (BIND) nicht installiert."),
				"Hinweis\n"
				"Klicken Sie auf den Namen des Servers in der Konsolenstruktur." };
			p.links = { { "Verwalten von DNS", "dnsmgr", "" } };
			break;
		case PG_REMOTE:
			p.title = "Remotezugriff";
			p.paragraphs = {
				facts.rras && facts.rrasRole == "vpn"
					? FXString("Auf diesem Server ist der Remotezugriff eingerichtet. Er ermöglicht die\n"
					           "Einwahl von einem beliebigen Ort aus, um Zugriff zum internen Netzwerk zu\n"
					           "erhalten.")
					: FXString("Auf diesem Server ist der Remotezugriff nicht eingerichtet. Über \"Routing\n"
					           "und RAS\" richten Sie einen VPN-Server mit WireGuard, OpenVPN oder\n"
					           "strongSwan ein.") };
			p.links = { { "Verwalten von Routing und RAS", "rras", "" } };
			break;
		case PG_ROUTING:
			p.title = "Routing";
			p.paragraphs = {
				facts.rras ? FXString("Auf diesem Server ist Routing eingerichtet.")
				           : FXString("Auf diesem Server ist Routing nicht eingerichtet."),
				"Routing verbindet die Netzwerke dieses Servers miteinander; dazu kommen\n"
				"statische Routen und Paketfilter." };
			p.links = { { "Verwalten von Routing und RAS", "rras", "" } };
			break;
		case PG_APPS:
			p.title = "Anwendungsserver";
			p.paragraphs = {
				"Dieser Server kann als Anwendungsserver dienen.",
				"•  Gruppenrichtlinien — verteilen Sie Einstellungen und Software auf die\n"
				"    Clients Ihres Netzwerks.",
				"•  Terminaldienste — stellen Sie Anwendungen für verschiedene Clients\n"
				"    bereit. Klicken Sie auf Terminaldienste im Menü auf der linken Seite." };
			break;
		case PG_COMPONENTS:
			p.title = "Komponentendienste";
			p.paragraphs = {
				"Die Komponentendienste (COM+) haben unter Linux kein Gegenstück.",
				"In diesem Projekt ist dafür nichts vorgesehen." };
			break;
		case PG_TERMINAL:
			p.title = "Terminaldienste";
			p.paragraphs = {
				facts.xrdp ? FXString("Auf diesem Server laufen die Terminaldienste (xrdp).")
				           : FXString("Auf diesem Server sind die Terminaldienste (xrdp) nicht eingerichtet."),
				"Wählen Sie aus folgenden Verwaltungsfunktionen, um mit den\n"
				"Terminaldiensten zu starten:" };
			p.links = { { "Konfiguration des Terminaldienstes", "termsvc", "" } };
			p.after = { "Der Terminaldienste-Manager (angemeldete Sitzungen) ist noch nicht\n"
			            "umgesetzt." };
			break;
		case PG_DATABASE:
			p.title = "Datenbankserver";
			p.paragraphs = {
				"Als Datenbankserver kommen unter Linux z.B. PostgreSQL oder MariaDB\n"
				"infrage; beide lassen sich über die Paketverwaltung installieren.",
				"Eine eigene Verwaltung gibt es in diesem Projekt nicht; Starten und\n"
				"Beenden erledigt \"Dienste\"." };
			p.links = { { "Öffnen der Dienstverwaltung", "services", "" } };
			break;
		case PG_MAIL:
			p.title = "E-Mail-Server";
			p.paragraphs = {
				"Für E-Mail treten unter Linux Postfix und Dovecot an die Stelle des\n"
				"Windows-E-Mail-Dienstes.",
				"Eine eigene Verwaltung gibt es in diesem Projekt nicht; Starten und\n"
				"Beenden erledigt \"Dienste\"." };
			p.links = { { "Öffnen der Dienstverwaltung", "services", "" } };
			break;
		case PG_ADVANCED:
			p.title = "Erweitert";
			p.paragraphs = { "Weitere Verwaltungsprogramme dieses Servers." };
			break;
		case PG_MANAGEMENT:
			p.title = "Computerverwaltung";
			p.paragraphs = {
				"Die Computerverwaltung führt lokale Benutzer und Gruppen, freigegebene\n"
				"Ordner sowie die Dienste dieses Servers zusammen." };
			p.links = { { "Öffnen der Computerverwaltung", "compmgmt", "" },
			            { "Öffnen der Dienstverwaltung", "services", "" } };
			break;
		case PG_SECURITY:
			p.title = "Sicherheitsrichtlinien";
			p.paragraphs = {
				"Kennwort- und Kontosperrungsrichtlinien, Benutzerrechte und\n"
				"Sicherheitsoptionen dieses Servers." };
			p.links = { { "Lokale Sicherheitsrichtlinie", "secpol", "--local" },
			            { "Sicherheitsrichtlinie für Domänen", "secpol", "--domain" },
			            { "Sicherheitsrichtlinie für Domänencontroller", "secpol", "--dc" } };
			break;
	}
	return p;
}

void SrvCfgWindow::buildPage(int id, const Page& p) {
	FXVerticalFrame* frame = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
	FXScrollWindow* sw = new FXScrollWindow(frame, LAYOUT_FILL_X | LAYOUT_FILL_Y | HSCROLLING_OFF);
	FXVerticalFrame* body = new FXVerticalFrame(sw, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 18,18,14,14, 0,10);
	body->setBackColor(PAGE_BG);
	sw->setBackColor(PAGE_BG);

	FXLabel* title = new FXLabel(body, p.title, NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
	title->setBackColor(PAGE_BG);
	title->setFont(new FXFont(getApp(), "helvetica", 18, FXFont::Bold));
	title->setTextColor(FXRGB(0, 0, 0));

	for (auto& para : p.paragraphs) {
		FXLabel* l = new FXLabel(body, para, NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		l->setBackColor(PAGE_BG);
	}
	for (auto& link : p.links) {
		FXHorizontalFrame* row = new FXHorizontalFrame(body, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 8,0);
		row->setBackColor(PAGE_BG);
		FXLabel* ic = new FXLabel(row, "", icoLink, LAYOUT_CENTER_Y);
		ic->setBackColor(PAGE_BG);
		// Verweise wie im Original: blau und anklickbar.
		FXButton* b = new FXButton(row, link.text, NULL, this, ID_LINK, BUTTON_TOOLBAR | FRAME_NONE | LAYOUT_CENTER_Y | JUSTIFY_LEFT, 0,0,0,0, 0,0,2,2);
		b->setBackColor(PAGE_BG);
		b->setTextColor(LINK_FG);
		linkTargets[b] = link;
	}
	for (auto& para : p.after) {
		FXLabel* l = new FXLabel(body, para, NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
		l->setBackColor(PAGE_BG);
	}
	pageFrames[id] = frame;
}

SrvCfgWindow::SrvCfgWindow(FXApp* a)
	: FXMainWindow(a, "ice2k Server konfigurieren", NULL, NULL, DECOR_ALL, 0,0, 780,560) {
	facts = collectFacts();
	icoNav = new FXPNGIcon(a, resico_server, IMAGE_NEAREST);
	icoLink = new FXPNGIcon(a, resico_network, IMAGE_NEAREST);
	icoBanner = new FXGIFIcon(a, resico_srvcfg_32);
	for (FXIcon* i : { icoNav, icoLink, icoBanner }) i->create();

	// ---- Kopfbanner ----
	FXHorizontalFrame* banner = new FXHorizontalFrame(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED, 0,0,0,0, 16,16,10,10, 12,0);
	banner->setBackColor(FXRGB(255,255,255));
	FXLabel* bico = new FXLabel(banner, "", icoBanner, LAYOUT_CENTER_Y);
	bico->setBackColor(FXRGB(255,255,255));
	FXVerticalFrame* btext = new FXVerticalFrame(banner, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 0,0);
	btext->setBackColor(FXRGB(255,255,255));
	FXLabel* b1 = new FXLabel(btext, "ice2k", NULL, JUSTIFY_LEFT);
	b1->setBackColor(FXRGB(255,255,255));
	b1->setFont(new FXFont(getApp(), "helvetica", 16, FXFont::Bold));
	FXLabel* b2 = new FXLabel(btext, "Server konfigurieren", NULL, JUSTIFY_LEFT);
	b2->setBackColor(FXRGB(255,255,255));
	b2->setFont(new FXFont(getApp(), "helvetica", 20, FXFont::Bold));

	// ---- Fußzeile mit "Dialog beim Start anzeigen" ----
	FXHorizontalFrame* foot = new FXHorizontalFrame(this, LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X, 0,0,0,0, 16,16,6,8);
	foot->setBackColor(PAGE_BG);
	new FXFrame(foot, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	showAtStart = new FXCheckButton(foot, "Dialog beim &Start anzeigen", this, ID_SHOWSTART);
	showAtStart->setBackColor(PAGE_BG);
	showAtStart->setCheck(readFileUnprivileged((std::string(getenv("HOME") ? getenv("HOME") : "/root") + "/.ice2k-srvcfg-off").c_str()).empty());

	// ---- Navigation links, Inhalt rechts ----
	FXHorizontalFrame* main = new FXHorizontalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
	FXPacker* navframe = new FXPacker(main, FRAME_NONE | LAYOUT_FILL_Y | LAYOUT_FIX_WIDTH, 0,0,185,0, 0,0,0,0);
	navframe->setBackColor(NAV_BG);
	nav = new FXTreeList(navframe, this, ID_NAV, LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_BROWSESELECT | TREELIST_SHOWS_LINES);
	nav->setBackColor(NAV_BG);
	nav->setTextColor(NAV_FG);
	nav->setSelBackColor(FXRGB(0,0,180));
	nav->setSelTextColor(NAV_FG);
	nav->setLineColor(NAV_BG);

	pages = new FXSwitcher(main, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	for (int i = 0; i < PG_COUNT; i++) buildPage(i, makePage(i));

	// Reihenfolge wie im Original, mit den Gruppen als aufklappbare Punkte.
	auto add = [&](FXTreeItem* parent, const char* label, int page) {
		FXTreeItem* it = nav->appendItem(parent, label, icoNav, icoNav);
		itemPage[it] = page;
		return it;
	};
	FXTreeItem* start = add(NULL, "Startseite", PG_START);
	add(NULL, "Jetzt registrieren", PG_REGISTER);
	add(NULL, "Active Directory", PG_AD);
	add(NULL, "Dateiserver", PG_FILE);
	add(NULL, "Druckserver", PG_PRINT);
	FXTreeItem* webmedia = add(NULL, "Web-/Mediaserver", PG_WEBMEDIA);
	add(webmedia, "Webserver", PG_WEB);
	add(webmedia, "Medienserver", PG_MEDIA);
	FXTreeItem* network = add(NULL, "Netzwerk", PG_NETWORK);
	add(network, "DHCP", PG_DHCP);
	add(network, "DNS", PG_DNS);
	add(network, "Remotezugriff", PG_REMOTE);
	add(network, "Routing", PG_ROUTING);
	FXTreeItem* apps = add(NULL, "Anwendungsserver", PG_APPS);
	add(apps, "Komponentendienste", PG_COMPONENTS);
	add(apps, "Terminaldienste", PG_TERMINAL);
	add(apps, "Datenbankserver", PG_DATABASE);
	add(apps, "E-Mail-Server", PG_MAIL);
	FXTreeItem* adv = add(NULL, "Erweitert", PG_ADVANCED);
	add(adv, "Computerverwaltung", PG_MANAGEMENT);
	add(adv, "Sicherheitsrichtlinien", PG_SECURITY);

	nav->setCurrentItem(start);
	nav->selectItem(start);
	pages->setCurrent(PG_START);
}

void SrvCfgWindow::create() {
	FXMainWindow::create();
	show(PLACEMENT_SCREEN);
}

long SrvCfgWindow::onNav(FXObject*, FXSelector, void*) {
	auto it = itemPage.find(nav->getCurrentItem());
	if (it == itemPage.end()) return 1;
	// Gruppen klappen wie im Original auf, wenn man sie anklickt.
	FXTreeItem* item = nav->getCurrentItem();
	if (item->getFirst()) nav->expandTree(item);
	pages->setCurrent(it->second);
	return 1;
}

long SrvCfgWindow::onLink(FXObject* sender, FXSelector, void*) {
	auto it = linkTargets.find(sender);
	if (it == linkTargets.end()) return 1;
	std::string missing = it->second.arg.empty() ? launch(it->second.program)
	                                             : launchWithArg(it->second.program, it->second.arg);
	if (!missing.empty())
		FXMessageBox::error(this, MBOX_OK, "Konfiguration des Servers",
			"Das Programm \"%s\" wurde nicht gefunden.\n\n"
			"Installieren Sie es (make install im entsprechenden Verzeichnis) oder\n"
			"starten Sie es aus seinem Bauverzeichnis heraus.", missing.c_str());
	return 1;
}

// Wie im Original merkt sich das Fenster, ob es beim Anmelden erscheinen
// soll; ausgewertet wird das von der Autostart-Datei in ice2k.
long SrvCfgWindow::onShowAtStart(FXObject*, FXSelector, void*) {
	std::string path = std::string(getenv("HOME") ? getenv("HOME") : "/root") + "/.ice2k-srvcfg-off";
	if (showAtStart->getCheck()) {
		unlink(path.c_str());
	} else {
		std::ofstream out(path);
		out << "Der Dialog \"Konfiguration des Servers\" wird beim Start nicht angezeigt.\n";
	}
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("SrvCfg", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	new SrvCfgWindow(&application);
	application.create();
	return application.run();
}
