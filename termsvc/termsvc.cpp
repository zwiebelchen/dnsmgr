// termsvc.cpp
//
// Terminaldienste fuer ice2k -- reines Full-Desktop-RDP ueber xrdp
// (kein RemoteApp/RAIL, das konnte Windows 2000 noch nicht). Prueft
// benoetigte Pakete, richtet die Authentifizierung ein (gegen die
// Active-Directory-Domaene, falls der Server domaenenbeigetreten ist,
// sonst gegen lokale Linux-Konten -- ueber die Standard-PAM/NSS-
// Winbind-Kaskade, die BEIDES gleichzeitig unterstuetzt), und
// versieht den xrdp-Anmeldebildschirm mit einem eigenen,
// Windows-2000-angelehnten Erscheinungsbild (kein Microsoft-Material,
// eigenes Logo).

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>

FXApp* app;
static bool g_haveRoot = false;

// ---------------------------------------------------------------------
// Root-Rechte ueber i2ksudo -- identisches Muster wie in den anderen
// ice2k-Werkzeugen.
// ---------------------------------------------------------------------
static int runAsRoot(const std::vector<FXString>& args) {
	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	for (auto& a : args) argv.push_back((char*)a.text());
	argv.push_back(NULL);
	pid_t pid = fork();
	if (pid == 0) { execvp("i2ksudo", argv.data()); _exit(127); }
	else if (pid > 0) {
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
		close(pipefd[0]); close(pipefd[1]);
		execvp("i2ksudo", argv.data());
		_exit(127);
	} else if (pid > 0) {
		close(pipefd[1]);
		char buf[4096]; ssize_t n;
		while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) output.append(buf, n);
		close(pipefd[0]);
		int status = 0;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) return WEXITSTATUS(status);
		return -1;
	}
	return -1;
}

static bool writeFileAsRoot(const FXString& path, const std::string& content) {
	char tmpname[] = "/tmp/termsvc_XXXXXX";
	int fd = mkstemp(tmpname);
	if (fd < 0) return false;
	FILE* f = fdopen(fd, "w");
	if (!f) { close(fd); unlink(tmpname); return false; }
	fwrite(content.data(), 1, content.size(), f);
	fclose(f);
	int rc = runAsRoot({ FXString("cp"), FXString(tmpname), path });
	unlink(tmpname);
	if (rc != 0) return false;
	runAsRoot({ FXString("chmod"), FXString("644"), path });
	return true;
}

static std::string readFileUnprivileged(const FXString& path) {
	std::ifstream in(path.text());
	if (!in.is_open()) return "";
	return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static bool isServiceActive(const FXString& name) {
	std::string out;
	runAsRootCaptured({ FXString("systemctl"), FXString("is-active"), name }, out);
	while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
	return out == "active";
}

static bool isPackageInstalled(const FXString& pkg) {
	std::string out;
	runAsRootCaptured({ FXString("dpkg"), FXString("-s"), pkg }, out);
	return out.find("Status: install ok installed") != std::string::npos;
}

static bool installMissingPackages(const std::vector<FXString>& pkgs, std::string& log, FXString& errorMsg) {
	log += "Aktualisiere Paketlisten (apt-get update)...\n";
	std::string out;
	runAsRootCaptured({ FXString("apt-get"), FXString("update") }, out);
	log += out + "\n";

	FXString pkgList;
	for (auto& p : pkgs) pkgList += p + " ";
	log += "Installiere fehlende Pakete: " + std::string(pkgList.text()) + "\n";

	std::vector<FXString> args = {
		FXString("env"), FXString("DEBIAN_FRONTEND=noninteractive"),
		FXString("apt-get"), FXString("install"), FXString("-y"),
		FXString("-o"), FXString("Dpkg::Options::=--force-confold"),
	};
	for (auto& p : pkgs) args.push_back(p);

	out.clear();
	int rc = runAsRootCaptured(args, out);
	log += out + "\n";
	if (rc != 0) { errorMsg = "Installation der fehlenden Pakete ist fehlgeschlagen (siehe Protokoll)."; return false; }
	log += "Pakete erfolgreich installiert.\n\n";
	return true;
}

// ---------------------------------------------------------------------
// Domaenen-Erkennung -- identisches Muster wie in compmgmt/dcpromo:
// smb.conf "server role" auswerten (Domaenencontroller ODER
// beigetretener Domaenenmitglied-Server zaehlen beide als "Domaene").
// ---------------------------------------------------------------------
static bool isDomainJoined() {
	std::string conf = readFileUnprivileged("/etc/samba/smb.conf");
	std::istringstream iss(conf);
	std::string line;
	while (std::getline(iss, line)) {
		size_t p = line.find('=');
		if (p == std::string::npos) continue;
		std::string k = line.substr(0, p);
		size_t a = k.find_first_not_of(" \t");
		size_t b = k.find_last_not_of(" \t");
		if (a == std::string::npos) continue;
		k = k.substr(a, b - a + 1);
		if (k != "server role") continue;
		return line.find("domain controller") != std::string::npos || line.find("member server") != std::string::npos;
	}
	return false;
}

// ---------------------------------------------------------------------
// Eigenes, von Microsoft unabhaengiges Logo im Stil eines vierfarbigen
// Flaggensymbols (240x140, BMP -- von xrdp immer unterstuetzt), als
// eingebettete Ressource ueber ImageMagick zur Installationszeit
// erzeugt (kein mitgeliefertes Bild noetig).
// ---------------------------------------------------------------------
static bool generateLogo(const FXString& destPath, FXString& errorMsg) {
	FXString tmpPath = "/tmp/termsvc-logo.bmp";
	std::string out;
	int rc = runAsRootCaptured({
		FXString("convert"), FXString("-size"), FXString("240x140"), FXString("xc:#D4D0C8"),
		FXString("-fill"), FXString("#C34A36"), FXString("-draw"), FXString("rectangle 60,20 110,60"),
		FXString("-fill"), FXString("#3E8E41"), FXString("-draw"), FXString("rectangle 112,20 162,60"),
		FXString("-fill"), FXString("#3468C0"), FXString("-draw"), FXString("rectangle 60,62 110,102"),
		FXString("-fill"), FXString("#E0A72E"), FXString("-draw"), FXString("rectangle 112,62 162,102"),
		FXString("-font"), FXString("DejaVu-Sans-Bold"), FXString("-pointsize"), FXString("20"),
		FXString("-fill"), FXString("#000080"), FXString("-gravity"), FXString("South"),
		FXString("-annotate"), FXString("+0+8"), FXString("ice2k"),
		tmpPath
	}, out);
	if (rc != 0) { errorMsg = "Logo-Erzeugung fehlgeschlagen (ImageMagick): " + FXString(out.c_str()); return false; }
	rc = runAsRoot({ FXString("cp"), tmpPath, destPath });
	runAsRoot({ FXString("rm"), FXString("-f"), tmpPath });
	if (rc != 0) { errorMsg = "Konnte Logo nicht nach " + destPath + " kopieren."; return false; }
	return true;
}

// Setzt die Windows-2000-angelehnten Anmeldebildschirm-Werte in
// xrdp.ini (klassisches Windows-2000-Blaugruen als Hintergrund,
// klassisches Dialog-Grau fuer die Box selbst, eigenes Logo).
// Ersetzt ganze Zeilen (nicht nur ein Text-Praefix) -- sonst wuerde
// ein zweiter Lauf z.B. "ls_logo_filename=/pfad" zu
// "ls_logo_filename=/pfad/pfad" verstuemmeln, weil der alte,
// bereits gesetzte Wert als Teilstring des Suchmusters uebrig bleibt.
static std::string setIniLine(const std::string& content, const std::string& key, const std::string& value) {
	std::istringstream iss(content);
	std::ostringstream oss;
	std::string line;
	bool replaced = false;
	while (std::getline(iss, line)) {
		std::string trimmed = line;
		size_t start = trimmed.find_first_not_of(" \t");
		std::string bare = (start == std::string::npos) ? "" : trimmed.substr(start);
		bool isKeyLine = bare.rfind(key + "=", 0) == 0 || bare.rfind("#" + key + "=", 0) == 0;
		if (isKeyLine && !replaced) {
			oss << key << "=" << value << "\n";
			replaced = true;
		} else {
			oss << line << "\n";
		}
	}
	return oss.str();
}

static bool applyIce2kTheme(FXString& errorMsg) {
	if (!generateLogo("/etc/xrdp/ice2k-logo.bmp", errorMsg)) return false;

	std::string content = readFileUnprivileged("/etc/xrdp/xrdp.ini");
	if (content.empty()) { errorMsg = "/etc/xrdp/xrdp.ini nicht gefunden -- ist xrdp installiert?"; return false; }

	content = setIniLine(content, "ls_title", "Anmeldung bei ice2k");
	content = setIniLine(content, "ls_top_window_bg_color", "008080");
	content = setIniLine(content, "ls_bg_color", "d4d0c8");
	content = setIniLine(content, "ls_logo_filename", "/etc/xrdp/ice2k-logo.bmp");
	content = setIniLine(content, "ls_logo_width", "240");
	content = setIniLine(content, "ls_logo_height", "140");

	if (!writeFileAsRoot("/etc/xrdp/xrdp.ini", content)) { errorMsg = "Konnte xrdp.ini nicht schreiben."; return false; }
	return true;
}

// Richtet die duale Authentifizierung ein: PAM probiert lokale
// Linux-Konten UND (falls die Domaene erreichbar ist) Active-
// Directory-Konten ueber winbind -- ganz ohne Sonderfall-Logik, da
// winbind bei fehlender Domaene einfach erfolglos durchgereicht wird
// und pam_unix uebernimmt.
static bool configureAuthentication(std::string& log, FXString& errorMsg) {
	std::string out;
	int rc = runAsRootCaptured({ FXString("pam-auth-update"), FXString("--enable"), FXString("winbind"),
	                              FXString("--enable"), FXString("unix"), FXString("--enable"), FXString("mkhomedir") }, out);
	log += out + "\n";
	if (rc != 0) { errorMsg = "Einrichten der PAM-Authentifizierung fehlgeschlagen (siehe Protokoll)."; return false; }
	return true;
}

// ---------------------------------------------------------------------
// Hintergrund-Worker fuer die eigentliche Einrichtung (Paketinstallation
// kann dauern) -- gleiches Muster wie ProvisionWorker in dcpromo.
// ---------------------------------------------------------------------
class SetupWorker : public FXThread {
public:
	bool success = false;
	std::string log;
	FXString errorMsg;
	bool finished = false;

	virtual FXint run() {
		std::vector<FXString> missing;
		for (auto& pkg : { FXString("xrdp"), FXString("xorgxrdp"), FXString("libpam-winbind"), FXString("libnss-winbind") }) {
			if (!isPackageInstalled(pkg)) missing.push_back(pkg);
		}
		bool ok = true;
		if (!missing.empty()) {
			ok = installMissingPackages(missing, log, errorMsg);
		} else {
			log += "Alle benötigten Pakete sind bereits installiert.\n\n";
		}
		if (ok) {
			log += "Richte Authentifizierung ein (lokale Konten + Active Directory über winbind)...\n";
			ok = configureAuthentication(log, errorMsg);
		}
		if (ok) {
			log += "Wende ice2k-Anmeldebildschirm-Erscheinungsbild an...\n";
			ok = applyIce2kTheme(errorMsg);
			if (ok) log += "Erscheinungsbild angewendet.\n\n";
		}
		if (ok) {
			log += "Aktiviere und starte Dienste (winbind, xrdp)...\n";
			runAsRoot({ FXString("systemctl"), FXString("enable"), FXString("--now"), FXString("winbind") });
			runAsRoot({ FXString("systemctl"), FXString("enable"), FXString("--now"), FXString("xrdp") });
			log += "Dienste aktiviert.\n";
		}
		success = ok;
		finished = true;
		return 0;
	}
};

// ---------------------------------------------------------------------
// Hauptfenster -- Statusanzeige + "Terminaldienste aktivieren".
// ---------------------------------------------------------------------
class TermSvcWindow : public FXMainWindow {
	FXDECLARE(TermSvcWindow)
private:
	FXLabel *statusXrdpLabel, *statusServiceLabel, *statusAuthLabel;
	FXText* logText;
	FXButton* activateBtn;
	SetupWorker* worker = NULL;
protected:
	TermSvcWindow() {}
public:
	enum { ID_ACTIVATE = FXMainWindow::ID_LAST, ID_POLL, ID_REFRESH };
	long onActivate(FXObject*, FXSelector, void*);
	long onPoll(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);

	void refreshStatus() {
		bool xrdpInstalled = isPackageInstalled("xrdp");
		statusXrdpLabel->setText(xrdpInstalled ? "xrdp ist installiert." : "xrdp ist nicht installiert.");
		bool serviceOn = isServiceActive("xrdp");
		statusServiceLabel->setText(serviceOn ? "Terminaldienste-Dienst läuft." : "Terminaldienste-Dienst läuft nicht.");
		bool domain = isDomainJoined();
		statusAuthLabel->setText(domain
			? "Authentifizierung: Active-Directory-Domäne erkannt (zusätzlich lokale Konten möglich)."
			: "Authentifizierung: keine Domäne erkannt (nur lokale Linux-Konten).");
	}

	TermSvcWindow(FXApp* a) : FXMainWindow(a, "Terminaldienstekonfiguration", NULL, NULL, DECOR_ALL, 0, 0, 560, 420) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Terminaldienste (Remotedesktop)", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		new FXLabel(main, "Ermöglicht Benutzern die Anmeldung an einem vollständigen Desktop\nüber das Remotedesktopprotokoll (RDP) -- ohne Remoteanwendungen,\ngenau wie unter Windows 2000.");

		FXGroupBox* statusGroup = new FXGroupBox(main, "Status", GROUPBOX_NORMAL | FRAME_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* statusFrame = new FXVerticalFrame(statusGroup, LAYOUT_FILL_X);
		statusXrdpLabel = new FXLabel(statusFrame, "");
		statusServiceLabel = new FXLabel(statusFrame, "");
		statusAuthLabel = new FXLabel(statusFrame, "");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,8);
		activateBtn = new FXButton(btnf, "&Terminaldienste aktivieren", NULL, this, ID_ACTIVATE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(btnf, "&Aktualisieren", NULL, this, ID_REFRESH, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		new FXLabel(main, "Protokoll:");
		logText = new FXText(main, NULL, 0, TEXT_READONLY | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		refreshStatus();
	}
	virtual void create() {
		FXMainWindow::create();
		show(PLACEMENT_SCREEN);
	}
	virtual ~TermSvcWindow() {}
};
FXDEFMAP(TermSvcWindow) TermSvcWindowMap[] = {
	FXMAPFUNC(SEL_COMMAND, TermSvcWindow::ID_ACTIVATE, TermSvcWindow::onActivate),
	FXMAPFUNC(SEL_COMMAND, TermSvcWindow::ID_REFRESH, TermSvcWindow::onRefresh),
	FXMAPFUNC(SEL_TIMEOUT, TermSvcWindow::ID_POLL, TermSvcWindow::onPoll),
};
FXIMPLEMENT(TermSvcWindow, FXMainWindow, TermSvcWindowMap, ARRAYNUMBER(TermSvcWindowMap))

long TermSvcWindow::onRefresh(FXObject*, FXSelector, void*) {
	refreshStatus();
	return 1;
}

long TermSvcWindow::onActivate(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können die Terminaldienste nicht eingerichtet werden.");
		return 1;
	}
	activateBtn->disable();
	logText->setText("Einrichtung gestartet...\n");
	worker = new SetupWorker();
	worker->start();
	getApp()->addTimeout(this, ID_POLL, 300);
	return 1;
}

long TermSvcWindow::onPoll(FXObject*, FXSelector, void*) {
	if (!worker) return 1;
	if (!worker->finished) {
		getApp()->addTimeout(this, ID_POLL, 300);
		return 1;
	}
	logText->setText(worker->log.c_str());
	if (worker->success) {
		FXMessageBox::information(this, MBOX_OK, "Fertig", "Die Terminaldienste wurden erfolgreich eingerichtet.");
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", worker->errorMsg.text());
	}
	worker->join();
	delete worker;
	worker = NULL;
	activateBtn->enable();
	refreshStatus();
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("TermSvc", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	TermSvcWindow* win = new TermSvcWindow(&application);
	application.create();

	if (!g_haveRoot) {
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\nDie Terminaldienste können nicht eingerichtet werden.");
	}

	return application.run();
}
