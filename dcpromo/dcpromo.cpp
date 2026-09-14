// dcpromo.cpp
//
// Assistent zum Installieren von Active Directory fuer ice2k --
// Nachbau des Windows-2000-"dcpromo"-Assistenten. Backend: Samba als
// AD-Domain-Controller (samba-tool domain provision).
//
// Bietet zwei Wege fuer den DNS-Teil der Domaene:
//  - "Windows-2000-kompatibel": Funktionsebene 2000, Sambas eigener
//    DNS-Server (SAMBA_INTERNAL) auf Port 53; BIND9 (das dnsmgr
//    verwaltet) zieht auf einen anderen Port um und wird ueber
//    Sambas "dns forwarder" fuer alle anderen Zonen erreichbar.
//  - "Moderne AD-Integration": Funktionsebene 2003, BIND9 bedient die
//    AD-Zone direkt ueber das DLZ-Modul, bleibt alleiniger
//    Port-53-Server.
// Ein spaeterer Wechsel von Windows-2000-kompatibel zur modernen
// Variante ist als eigene Aktion moeglich (samba_upgradedns).

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>

FXApp* app;
static bool g_haveRoot = false;

static const char* SMB_CONF = "/etc/samba/smb.conf";
static const char* BIND_LOCAL = "/etc/bind/named.conf.local";
static const char* BIND_OPTIONS = "/etc/bind/named.conf.options";
static const int BIND_ALT_PORT = 5353; // Port, auf den BIND9 im Win2k-kompatiblen Modus ausweicht

// ---------------------------------------------------------------------
// Root-Rechte ueber i2ksudo -- identisches Muster wie in dnsmgr/dhcpmgr/
// compmgmt.
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

static int runAsRootWithStdin(const std::vector<FXString>& args, const std::string& input) __attribute__((unused));
static int runAsRootWithStdin(const std::vector<FXString>& args, const std::string& input) {
	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	for (auto& a : args) argv.push_back((char*)a.text());
	argv.push_back(NULL);

	int pipefd[2];
	if (pipe(pipefd) != 0) return -1;

	pid_t pid = fork();
	if (pid == 0) {
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execvp("i2ksudo", argv.data());
		_exit(127);
	} else if (pid > 0) {
		close(pipefd[0]);
		ssize_t written = write(pipefd[1], input.data(), input.size());
		(void)written;
		close(pipefd[1]);
		int status = 0;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) return WEXITSTATUS(status);
		return -1;
	}
	return -1;
}

// Wie runAsRoot(), gibt aber zusaetzlich die kombinierte stdout/stderr-
// Ausgabe zurueck -- fuer das Fortschritts-Protokoll im Assistenten.
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

static bool writeFileAsRoot(const FXString& path, const std::string& content) {
	char tmpname[] = "/tmp/dcpromo_XXXXXX";
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

// ---------------------------------------------------------------------
// Aktuellen Domaenenstatus ermitteln -- reines Auslesen von smb.conf,
// unprivilegiert (die Datei ist nach der Provisionierung 644).
// ---------------------------------------------------------------------
struct DomainState {
	bool isProvisioned = false;
	bool win2kCompatible = false; // true = SAMBA_INTERNAL + dns forwarder, false = BIND9_DLZ
	FXString realm, workgroup;
};

static FXString smbConfValue(const std::string& conf, const char* key) {
	std::istringstream iss(conf);
	std::string line;
	while (std::getline(iss, line)) {
		size_t p = line.find('=');
		if (p == std::string::npos) continue;
		std::string k = line.substr(0, p);
		// Trim
		size_t a = k.find_first_not_of(" \t");
		size_t b = k.find_last_not_of(" \t");
		if (a == std::string::npos) continue;
		k = k.substr(a, b - a + 1);
		if (k != key) continue;
		std::string v = line.substr(p + 1);
		a = v.find_first_not_of(" \t");
		b = v.find_last_not_of(" \t\r\n");
		if (a == std::string::npos) return "";
		return FXString(v.substr(a, b - a + 1).c_str());
	}
	return "";
}

static DomainState detectDomainState() {
	DomainState st;
	std::string conf = readFileUnprivileged(SMB_CONF);
	if (conf.empty()) return st;
	FXString role = smbConfValue(conf, "server role");
	if (role.find("domain controller") < 0) return st;
	st.isProvisioned = true;
	st.realm = smbConfValue(conf, "realm");
	st.workgroup = smbConfValue(conf, "workgroup");
	FXString forwarder = smbConfValue(conf, "dns forwarder");
	st.win2kCompatible = !forwarder.empty();
	return st;
}

// ---------------------------------------------------------------------
// Hilfsfunktionen fuer die BIND9-Seite (analog zu den Handgriffen, die
// wir beim manuellen Testen gebraucht haben).
// ---------------------------------------------------------------------

// Ersetzt/ergaenzt eine einzelne Zeile (z.B. "listen-on port ...") in
// der options{}-Sektion von named.conf.options, direkt nach der
// dnssec-validation-Zeile.
static bool bindOptionsAddLine(std::string& conf, const std::string& marker, const std::string& line) {
	if (conf.find(line) != std::string::npos) return true; // schon vorhanden
	size_t pos = conf.find(marker);
	if (pos == std::string::npos) return false;
	pos = conf.find('\n', pos);
	if (pos == std::string::npos) pos = conf.length();
	conf.insert(pos + 1, "\t" + line + "\n");
	return true;
}

static void bindOptionsRemoveLineContaining(std::string& conf, const std::string& needle) {
	std::istringstream iss(conf);
	std::string line, out;
	while (std::getline(iss, line)) {
		if (line.find(needle) == std::string::npos) out += line + "\n";
	}
	conf = out;
}

// Stellt BIND9 auf den Win2k-kompatiblen Modus um: Port BIND_ALT_PORT
// statt 53, damit Samba (SAMBA_INTERNAL) Port 53 fuer sich hat.
static bool configureBindForWin2k(FXString& errorMsg) {
	std::string opts = readFileUnprivileged(BIND_OPTIONS);
	if (opts.empty()) { errorMsg = "named.conf.options nicht gefunden."; return false; }

	bindOptionsRemoveLineContaining(opts, "listen-on port");
	bindOptionsRemoveLineContaining(opts, "tkey-gssapi-keytab");
	bindOptionsRemoveLineContaining(opts, "minimal-responses yes;");

	std::string portLine = "listen-on port " + std::to_string(BIND_ALT_PORT) + " { 127.0.0.1; };";
	if (!bindOptionsAddLine(opts, "dnssec-validation auto;", portLine)) {
		errorMsg = "Konnte named.conf.options nicht anpassen (Marker fehlt).";
		return false;
	}
	return writeFileAsRoot(BIND_OPTIONS, opts);
}

// Stellt BIND9 auf die moderne AD-Integration um: Port 53, DLZ-Include,
// GSS-TSIG-Keytab. Gibt ueber "dlzModuleFile" den Namen des zur
// installierten BIND-Version passenden dlz_bind9_XX.so zurueck.
static FXString detectDlzModuleName() {
	// named -v liefert z.B. "BIND 9.18.39-...": wir extrahieren die
	// Minor-Version und suchen die naechstliegende vorhandene .so-Datei.
	std::string out;
	FXString dummy;
	runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString("named -v 2>&1") }, out);
	int major = 9, minor = 18;
	size_t p = out.find("BIND ");
	if (p != std::string::npos) sscanf(out.c_str() + p, "BIND %d.%d", &major, &minor);

	std::vector<int> candidates = { minor, 18, 16, 14, 12, 11, 10, 9 };
	for (int m : candidates) {
		FXString path = FXString("/usr/lib/x86_64-linux-gnu/samba/bind9/dlz_bind9_") + FXString(std::to_string(m).c_str()) + ".so";
		if (access(path.text(), F_OK) == 0) return FXString("dlz_bind9_") + FXString(std::to_string(m).c_str()) + ".so";
	}
	return "dlz_bind9_9.so";
}

static bool configureBindForModernAd(const FXString& realm, FXString& errorMsg) {
	FXString bindDnsConf = "/var/lib/samba/bind-dns/named.conf";
	std::string snippet = readFileUnprivileged(bindDnsConf);
	if (snippet.empty()) { errorMsg = "Von Samba erzeugte BIND-Konfiguration nicht gefunden (" + bindDnsConf + ")."; return false; }

	FXString moduleName = detectDlzModuleName();
	std::string commentedLine = "# database \"dlopen /usr/lib/x86_64-linux-gnu/samba/bind9/" + std::string(moduleName.text()) + "\";";
	std::string activeLine = "database \"dlopen /usr/lib/x86_64-linux-gnu/samba/bind9/" + std::string(moduleName.text()) + "\";";
	size_t p = snippet.find(commentedLine);
	if (p != std::string::npos) snippet.replace(p, commentedLine.length(), activeLine);
	if (!writeFileAsRoot(bindDnsConf, snippet)) { errorMsg = "Konnte " + bindDnsConf + " nicht schreiben."; return false; }

	runAsRoot({ FXString("chgrp"), FXString("-R"), FXString("bind"), FXString("/var/lib/samba/bind-dns") });
	runAsRoot({ FXString("chmod"), FXString("-R"), FXString("g+rX"), FXString("/var/lib/samba/bind-dns") });

	std::string local = "// BIND9-DLZ: bedient die AD-Zone direkt aus der Samba-Datenbank.\n"
	                     "// Von dnsmgr verwaltete Zonen stehen als eigene zone{}-Bloecke weiterhin\n"
	                     "// unabhaengig davon in dieser Datei bzw. per include.\n"
	                     "include \"/var/lib/samba/bind-dns/named.conf\";\n";
	if (!writeFileAsRoot(BIND_LOCAL, local)) { errorMsg = "Konnte named.conf.local nicht schreiben."; return false; }

	std::string opts = readFileUnprivileged(BIND_OPTIONS);
	if (opts.empty()) { errorMsg = "named.conf.options nicht gefunden."; return false; }
	bindOptionsRemoveLineContaining(opts, "listen-on port");
	bindOptionsAddLine(opts, "dnssec-validation auto;", "tkey-gssapi-keytab \"/var/lib/samba/bind-dns/dns.keytab\";");
	bindOptionsAddLine(opts, "dnssec-validation auto;", "minimal-responses yes;");
	return writeFileAsRoot(BIND_OPTIONS, opts);
}

// ---------------------------------------------------------------------
// Editiert smb.conf: setzt/entfernt eine "key = value"-Zeile im
// [global]-Abschnitt. Wird fuer "dns forwarder" und "server services"
// gebraucht.
// ---------------------------------------------------------------------
static std::string smbConfSetOrRemove(const std::string& conf, const char* key, const std::string& value /* leer = entfernen */) {
	std::istringstream iss(conf);
	std::string line, out;
	bool replaced = false;
	bool inGlobal = false;
	while (std::getline(iss, line)) {
		std::string trimmed = line;
		size_t a = trimmed.find_first_not_of(" \t");
		if (a != std::string::npos) trimmed = trimmed.substr(a); else trimmed = "";
		if (!trimmed.empty() && trimmed[0] == '[') inGlobal = (trimmed.substr(0, 8) == "[global]");

		size_t p = line.find('=');
		bool isKeyLine = false;
		if (p != std::string::npos) {
			std::string k = line.substr(0, p);
			size_t ka = k.find_first_not_of(" \t");
			size_t kb = k.find_last_not_of(" \t");
			if (ka != std::string::npos) {
				k = k.substr(ka, kb - ka + 1);
				isKeyLine = (k == key);
			}
		}
		if (isKeyLine && inGlobal) {
			replaced = true;
			if (!value.empty()) out += "\t" + std::string(key) + " = " + value + "\n";
			continue; // Zeile weglassen (bzw. durch neue ersetzen)
		}
		out += line + "\n";
	}
	if (!replaced && !value.empty()) {
		// [global] Abschnitt suchen und Zeile direkt danach einfuegen
		size_t gp = out.find("[global]");
		if (gp != std::string::npos) {
			size_t nl = out.find('\n', gp);
			if (nl != std::string::npos) {
				out.insert(nl + 1, "\t" + std::string(key) + " = " + value + "\n");
			}
		}
	}
	return out;
}

// ---------------------------------------------------------------------
// Provisioniert eine komplett neue Domaene (neue Domaenenstruktur,
// neue Gesamtstruktur -- die einzige Variante, die dieser Assistent
// unterstuetzt; siehe README fuer die bewusst weggelassenen Faelle).
// ---------------------------------------------------------------------
static bool provisionDomain(const FXString& dnsName, const FXString& netbios, const FXString& adminPass,
                             bool win2kCompatible, std::string& log, FXString& errorMsg) {
	log += "Bestehende smb.conf sichern (falls vorhanden)...\n";
	if (access(SMB_CONF, F_OK) == 0) {
		runAsRoot({ FXString("mv"), FXString(SMB_CONF), FXString(SMB_CONF) + FXString(".vor-dcpromo") });
	}

	std::vector<FXString> args = {
		FXString("samba-tool"), FXString("domain"), FXString("provision"),
		FXString("--realm=") + dnsName,
		FXString("--domain=") + netbios,
		FXString("--server-role=dc"),
		FXString("--adminpass=") + adminPass,
	};
	if (win2kCompatible) {
		args.push_back(FXString("--dns-backend=SAMBA_INTERNAL"));
		args.push_back(FXString("--function-level=2000"));
		args.push_back(FXString("--option=dns forwarder=127.0.0.1:") + FXString(std::to_string(BIND_ALT_PORT).c_str()));
	} else {
		args.push_back(FXString("--dns-backend=BIND9_DLZ"));
		args.push_back(FXString("--function-level=2003"));
	}

	log += "Führe 'samba-tool domain provision' aus -- das kann einen Moment dauern...\n";
	std::string out;
	int rc = runAsRootCaptured(args, out);
	log += out + "\n";
	if (rc != 0) { errorMsg = "samba-tool domain provision ist fehlgeschlagen (siehe Protokoll)."; return false; }
	log += "Provisionierung abgeschlossen.\n";

	if (win2kCompatible) {
		log += "Stelle BIND9 auf Port " + std::to_string(BIND_ALT_PORT) + " um (Samba braucht Port 53 für sich)...\n";
		if (!configureBindForWin2k(errorMsg)) return false;
	} else {
		log += "Richte BIND9-DLZ-Integration ein (BIND9 bedient die AD-Zone direkt)...\n";
		if (!configureBindForModernAd(dnsName, errorMsg)) return false;
	}

	log += "Starte kea-dhcp4-server unveraendert weiter; starte bind9 und samba neu...\n";
	bool r1 = runAsRoot({ FXString("systemctl"), FXString("restart"), FXString("bind9") }) == 0;
	bool r2 = runAsRoot({ FXString("systemctl"), FXString("restart"), FXString("samba-ad-dc") }) == 0;
	if (!r1 || !r2) {
		log += "Achtung: bind9/samba-ad-dc konnten nicht automatisch neu gestartet werden -- bitte manuell prüfen.\n";
	} else {
		log += "Dienste neu gestartet.\n";
	}
	return true;
}

// ---------------------------------------------------------------------
// Migration: Windows-2000-Kompatibilität aufheben, auf die moderne
// BIND9-DLZ-Integration wechseln.
// ---------------------------------------------------------------------
static bool migrateToModernAd(const FXString& dnsName, std::string& log, FXString& errorMsg) {
	log += "Hebe Funktions-/Gesamtstrukturebene auf 2003 an...\n";
	std::string out;
	int rc = runAsRootCaptured({ FXString("samba-tool"), FXString("domain"), FXString("level"), FXString("raise"),
	                              FXString("--domain-level=2003"), FXString("--forest-level=2003") }, out);
	log += out + "\n";
	if (rc != 0) { errorMsg = "Anheben der Funktionsebene fehlgeschlagen (siehe Protokoll)."; return false; }

	log += "Migriere DNS-Backend auf BIND9_DLZ ('samba_upgradedns')...\n";
	out.clear();
	rc = runAsRootCaptured({ FXString("samba_upgradedns"), FXString("--dns-backend=BIND9_DLZ") }, out);
	log += out + "\n";
	if (rc != 0) { errorMsg = "samba_upgradedns ist fehlgeschlagen (siehe Protokoll)."; return false; }

	log += "Passe smb.conf an (Sambas eigenen DNS-Dienst abschalten)...\n";
	std::string conf = readFileUnprivileged(SMB_CONF);
	conf = smbConfSetOrRemove(conf, "dns forwarder", "");
	conf = smbConfSetOrRemove(conf, "server services",
		"s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate");
	if (!writeFileAsRoot(SMB_CONF, conf)) { errorMsg = "Konnte smb.conf nicht schreiben."; return false; }

	log += "Richte BIND9-DLZ-Integration ein...\n";
	if (!configureBindForModernAd(dnsName, errorMsg)) return false;

	log += "Starte bind9 und samba-ad-dc neu...\n";
	bool r1 = runAsRoot({ FXString("systemctl"), FXString("restart"), FXString("bind9") }) == 0;
	bool r2 = runAsRoot({ FXString("systemctl"), FXString("restart"), FXString("samba-ad-dc") }) == 0;
	if (!r1 || !r2) {
		log += "Achtung: bind9/samba-ad-dc konnten nicht automatisch neu gestartet werden -- bitte manuell prüfen.\n";
	} else {
		log += "Dienste neu gestartet.\n";
	}
	log += "Migration abgeschlossen -- Windows-2000-Kompatibilität wurde aufgehoben.\n";
	return true;
}

// ---------------------------------------------------------------------
// Assistent (Hauptfenster) -- Seiten per FXSwitcher, mit
// Zurück/Weiter/Abbrechen/Fertig-stellen-Navigation, wie im Original.
// ---------------------------------------------------------------------

enum {
	PAGE_STATUS = 0,     // Falls schon eine Domaene existiert: Status + ggf. Migration
	PAGE_WELCOME,
	PAGE_DOMAINDATA,
	PAGE_DNSCHOICE,
	PAGE_SUMMARY,
	PAGE_RUNNING,
	PAGE_FINISH
};

class DcPromoWizard : public FXMainWindow {
	FXDECLARE(DcPromoWizard)
private:
	FXSwitcher* switcher;
	FXButton *btnBack, *btnNext, *btnCancel, *btnFinish;

	// Status-Seite
	FXLabel* statusLabel;
	FXButton* btnMigrate;

	// Domaenendaten
	FXTextField *dnsNameField, *netbiosField, *adminPwField, *adminPwConfirmField;
	bool netbiosAutoFilled;

	// DNS-Wahl
	FXRadioButton *rbWin2k, *rbModern;

	// Zusammenfassung
	FXText* summaryText;

	// Ausfuehren
	FXText* logText;

	DomainState domainState;
	bool migrating; // true, wenn PAGE_RUNNING fuer die Migration statt Neuprovisionierung laeuft

protected:
	DcPromoWizard() {}
public:
	enum {
		ID_BACK = FXMainWindow::ID_LAST, ID_NEXT, ID_CANCEL, ID_FINISH, ID_MIGRATE,
		ID_DNSCHOICE_WIN2K, ID_DNSCHOICE_MODERN, ID_DNSNAME_CHANGED, ID_NETBIOS_CHANGED
	};

	long onBack(FXObject*, FXSelector, void*);
	long onNext(FXObject*, FXSelector, void*);
	long onCancelBtn(FXObject*, FXSelector, void*);
	long onFinish(FXObject*, FXSelector, void*);
	long onMigrate(FXObject*, FXSelector, void*);
	long onDnsChoice(FXObject*, FXSelector, void*);
	long onDnsNameChanged(FXObject*, FXSelector, void*);
	long onNetbiosChanged(FXObject*, FXSelector, void*);

	DcPromoWizard(FXApp* a);
	void gotoPage(int page);
	void runProvisioningNow();
	void runMigrationNow();
	virtual void create();
	virtual ~DcPromoWizard() {}
};

FXDEFMAP(DcPromoWizard) DcPromoWizardMap[] = {
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_BACK, DcPromoWizard::onBack),
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_NEXT, DcPromoWizard::onNext),
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_CANCEL, DcPromoWizard::onCancelBtn),
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_FINISH, DcPromoWizard::onFinish),
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_MIGRATE, DcPromoWizard::onMigrate),
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_DNSCHOICE_WIN2K, DcPromoWizard::onDnsChoice),
	FXMAPFUNC(SEL_COMMAND, DcPromoWizard::ID_DNSCHOICE_MODERN, DcPromoWizard::onDnsChoice),
	FXMAPFUNC(SEL_CHANGED, DcPromoWizard::ID_DNSNAME_CHANGED, DcPromoWizard::onDnsNameChanged),
	FXMAPFUNC(SEL_CHANGED, DcPromoWizard::ID_NETBIOS_CHANGED, DcPromoWizard::onNetbiosChanged),
};
FXIMPLEMENT(DcPromoWizard, FXMainWindow, DcPromoWizardMap, ARRAYNUMBER(DcPromoWizardMap))

DcPromoWizard::DcPromoWizard(FXApp* a)
	: FXMainWindow(a, "Assistent zum Installieren von Active Directory", NULL, NULL, DECOR_ALL, 0, 0, 640, 460, 0,0,0,0,0,0),
	  netbiosAutoFilled(true), migrating(false) {

	domainState = detectDomainState();

	FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);

	switcher = new FXSwitcher(main, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 20,20,20,20);

	// --- PAGE_STATUS ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "Active Directory bereits installiert", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		statusLabel = new FXLabel(p, "", NULL, LABEL_NORMAL | JUSTIFY_LEFT | LAYOUT_FILL_X);
		new FXFrame(p, LAYOUT_FILL_Y);
		btnMigrate = new FXButton(p, "&Windows-2000-Kompatibilität aufheben...", NULL, this, ID_MIGRATE,
		                          BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,6,6);
	}

	// --- PAGE_WELCOME ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "Willkommen", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		new FXLabel(p,
			"Mit diesem Assistenten werden die Active Directory-Dienste\n"
			"auf diesem Server installiert, und dadurch wird der Server zu\n"
			"einem Domänencontroller.\n\n"
			"Dieser Assistent legt eine komplett neue Domäne in einer neuen\n"
			"Gesamtstruktur an (der mit Abstand häufigste Fall). Einem\n"
			"bestehenden Baum beizutreten oder ein zusätzlicher\n"
			"Domänencontroller einer vorhandenen Domäne zu werden wird\n"
			"(noch) nicht unterstützt.\n\n"
			"Klicken Sie auf \"Weiter\", um den Vorgang fortzusetzen.",
			NULL, JUSTIFY_LEFT);
	}

	// --- PAGE_DOMAINDATA ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "Name der neuen Domäne", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		new FXLabel(p, "Geben Sie den gesamten DNS-Namen für die neue Domäne ein.", NULL, JUSTIFY_LEFT);
		new FXLabel(p, "Gesamter DNS-Name für die neue Domäne:");
		dnsNameField = new FXTextField(p, 30, this, ID_DNSNAME_CHANGED, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(p, "NetBIOS-Domänenname (für ältere Clients):");
		netbiosField = new FXTextField(p, 30, this, ID_NETBIOS_CHANGED, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(p, "Administrator-Kennwort:");
		adminPwField = new FXTextField(p, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
		new FXLabel(p, "Kennwort bestätigen:");
		adminPwConfirmField = new FXTextField(p, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);
	}

	// --- PAGE_DNSCHOICE ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "DNS-Integration der Domäne", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		new FXLabel(p,
			"Windows 2000 selbst kannte das AD-integrierte DNS-Speichermodell\n"
			"(\"DomainDnsZones\"), das für die direkte BIND9-Integration nötig\n"
			"ist, noch nicht -- das kam erst mit Windows Server 2003.",
			NULL, JUSTIFY_LEFT);
		rbWin2k = new FXRadioButton(p, "&Windows-2000-kompatibel", this, ID_DNSCHOICE_WIN2K);
		new FXLabel(p, "  (Funktionsebene 2000, Sambas eigener DNS-Server, BIND9 nur für andere Zonen)", NULL, JUSTIFY_LEFT);
		rbModern = new FXRadioButton(p, "&Moderne AD-Integration", this, ID_DNSCHOICE_MODERN);
		new FXLabel(p, "  (Funktionsebene 2003, BIND9 bedient die AD-Zone direkt über DLZ)", NULL, JUSTIFY_LEFT);
		rbWin2k->setCheck(TRUE);
		new FXLabel(p,
			"(Ein späterer Wechsel von \"Windows-2000-kompatibel\" zur modernen\n"
			"Variante ist über \"Windows-2000-Kompatibilität aufheben\" möglich.)",
			NULL, JUSTIFY_LEFT);
	}

	// --- PAGE_SUMMARY ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "Zusammenfassung", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		new FXLabel(p, "Stellen Sie sicher, dass die gewählten Optionen richtig sind.", NULL, JUSTIFY_LEFT);
		summaryText = new FXText(p, NULL, 0, TEXT_READONLY | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	}

	// --- PAGE_RUNNING ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "Active Directory konfigurieren", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		logText = new FXText(p, NULL, 0, TEXT_READONLY | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	}

	// --- PAGE_FINISH ---
	{
		FXVerticalFrame* p = new FXVerticalFrame(switcher, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p, "Fertigstellen des Assistenten", NULL, LABEL_NORMAL | JUSTIFY_LEFT);
		new FXLabel(p,
			"Active Directory wurde konfiguriert.\n\n"
			"Damit alle Dienste den neuen Zustand übernehmen, wird ein\n"
			"Neustart der betroffenen Dienste (bzw. des Systems) empfohlen.\n\n"
			"Klicken Sie auf \"Schließen\", um den Assistenten zu beenden.",
			NULL, JUSTIFY_LEFT);
	}

	new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 14,14,10,10);
	new FXFrame(btnf, LAYOUT_FILL_X);
	btnBack = new FXButton(btnf, "< &Zurück", NULL, this, ID_BACK, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	btnNext = new FXButton(btnf, "&Weiter >", NULL, this, ID_NEXT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	btnCancel = new FXButton(btnf, "&Abbrechen", NULL, this, ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	btnFinish = new FXButton(btnf, "&Schließen", NULL, this, ID_FINISH, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

	gotoPage(domainState.isProvisioned ? PAGE_STATUS : PAGE_WELCOME);
}

void DcPromoWizard::gotoPage(int page) {
	switcher->setCurrent(page);

	// Standard-Sichtbarkeit: Zurueck/Weiter/Abbrechen an, Schliessen aus.
	btnBack->show(); btnNext->show(); btnCancel->show(); btnFinish->hide();
	btnBack->enable(); btnNext->enable();

	if (page == PAGE_STATUS) {
		FXString txt = "Domäne: " + domainState.realm + "  (NetBIOS: " + domainState.workgroup + ")\n"
			+ FXString("DNS-Modus: ") + (domainState.win2kCompatible ? FXString("Windows-2000-kompatibel (Sambas eigener DNS-Server)")
			                                                          : FXString("Moderne AD-Integration (BIND9-DLZ)"));
		statusLabel->setText(txt);
		btnMigrate->show();
		if (!domainState.win2kCompatible) btnMigrate->disable(); else btnMigrate->enable();
		btnBack->hide(); btnNext->hide(); btnCancel->hide();
		btnFinish->show();
	} else if (page == PAGE_WELCOME) {
		btnBack->disable();
	} else if (page == PAGE_RUNNING) {
		btnBack->disable();
		btnCancel->hide();
		btnNext->setText(migrating ? "&Weiter >" : "&Weiter >");
	} else if (page == PAGE_FINISH) {
		btnBack->hide(); btnNext->hide(); btnCancel->hide();
		btnFinish->show();
	}
}

long DcPromoWizard::onDnsNameChanged(FXObject*, FXSelector, void*) {
	if (!netbiosAutoFilled) return 1;
	FXString dns = dnsNameField->getText();
	int dot = dns.find('.');
	FXString first = (dot >= 0) ? dns.left(dot) : dns;
	first.upper();
	netbiosField->setText(first);
	return 1;
}

long DcPromoWizard::onNetbiosChanged(FXObject*, FXSelector, void*) {
	netbiosAutoFilled = false; // Benutzer hat selbst eingegriffen -- nicht mehr automatisch ueberschreiben
	return 1;
}

long DcPromoWizard::onDnsChoice(FXObject* sender, FXSelector, void*) {
	bool win2k = (sender == rbWin2k);
	rbWin2k->setCheck(win2k);
	rbModern->setCheck(!win2k);
	return 1;
}

long DcPromoWizard::onBack(FXObject*, FXSelector, void*) {
	int cur = switcher->getCurrent();
	if (cur > PAGE_WELCOME) gotoPage(cur - 1);
	return 1;
}

long DcPromoWizard::onNext(FXObject*, FXSelector, void*) {
	int cur = switcher->getCurrent();

	if (cur == PAGE_WELCOME) {
		gotoPage(PAGE_DOMAINDATA);

	} else if (cur == PAGE_DOMAINDATA) {
		if (dnsNameField->getText().trim().empty() || netbiosField->getText().trim().empty()) {
			FXMessageBox::error(this, MBOX_OK, "Angaben fehlen", "Bitte DNS-Namen und NetBIOS-Namen der Domäne angeben.");
			return 1;
		}
		if (adminPwField->getText().empty()) {
			FXMessageBox::error(this, MBOX_OK, "Kennwort fehlt", "Bitte ein Administrator-Kennwort angeben.");
			return 1;
		}
		if (adminPwField->getText() != adminPwConfirmField->getText()) {
			FXMessageBox::error(this, MBOX_OK, "Kennwörter stimmen nicht überein", "Die beiden eingegebenen Kennwörter sind unterschiedlich.");
			return 1;
		}
		gotoPage(PAGE_DNSCHOICE);

	} else if (cur == PAGE_DNSCHOICE) {
		FXString mode = rbWin2k->getCheck() ? FXString("Windows-2000-kompatibel (Funktionsebene 2000, Sambas eigener DNS-Server)")
		                                     : FXString("Moderne AD-Integration (Funktionsebene 2003, BIND9-DLZ)");
		FXString summary =
			"Folgendes wurde gewählt:\n\n"
			"Dieser Server wird als erster Domänencontroller in einer neuen\n"
			"Gesamtstruktur von Domänenstrukturen konfiguriert.\n\n"
			"Der neue Domänenname ist \"" + dnsNameField->getText() + "\".\n"
			"Dies ist auch der Name der neuen Gesamtstruktur.\n\n"
			"Der NetBIOS-Name der Domäne ist \"" + netbiosField->getText() + "\".\n\n"
			"DNS-Integration: " + mode + "\n\n"
			"Klicken Sie auf \"Weiter\", um den Assistenten die Konfiguration\n"
			"jetzt durchführen zu lassen.";
		summaryText->setText(summary);
		gotoPage(PAGE_SUMMARY);

	} else if (cur == PAGE_SUMMARY) {
		if (!g_haveRoot) {
			FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann Active Directory nicht installiert werden.");
			return 1;
		}
		migrating = false;
		gotoPage(PAGE_RUNNING);
		getApp()->repaint();
		getApp()->flush();
		runProvisioningNow();

	} else if (cur == PAGE_RUNNING) {
		gotoPage(PAGE_FINISH);
	}
	return 1;
}

long DcPromoWizard::onCancelBtn(FXObject*, FXSelector, void*) {
	if (FXMessageBox::question(this, MBOX_YES_NO, "Abbrechen",
	        "Assistent wirklich abbrechen? Bisher wurde noch nichts verändert.") == MBOX_CLICKED_YES) {
		getApp()->exit(0);
	}
	return 1;
}

long DcPromoWizard::onFinish(FXObject*, FXSelector, void*) {
	getApp()->exit(0);
	return 1;
}

long DcPromoWizard::onMigrate(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann die Migration nicht durchgeführt werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Windows-2000-Kompatibilität aufheben",
	        "Die Domäne \"%s\" wird dauerhaft auf die moderne AD-Integration (BIND9-DLZ,\n"
	        "Funktionsebene 2003) umgestellt. Dieser Schritt lässt sich nicht rückgängig\n"
	        "machen. Fortfahren?", domainState.realm.text()) != MBOX_CLICKED_YES) {
		return 1;
	}
	migrating = true;
	gotoPage(PAGE_RUNNING);
	getApp()->repaint();
	getApp()->flush();
	runMigrationNow();
	return 1;
}

void DcPromoWizard::runProvisioningNow() {
	std::string log;
	FXString errorMsg;
	bool ok = provisionDomain(dnsNameField->getText().trim(), netbiosField->getText().trim(),
	                           adminPwField->getText(), rbWin2k->getCheck(), log, errorMsg);
	logText->setText(log.c_str());
	if (!ok) {
		logText->appendText(("\nFEHLER: " + std::string(errorMsg.text()) + "\n").c_str());
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	} else {
		logText->appendText("\nErfolgreich abgeschlossen.\n");
	}
}

void DcPromoWizard::runMigrationNow() {
	std::string log;
	FXString errorMsg;
	bool ok = migrateToModernAd(domainState.realm, log, errorMsg);
	logText->setText(log.c_str());
	if (!ok) {
		logText->appendText(("\nFEHLER: " + std::string(errorMsg.text()) + "\n").c_str());
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	} else {
		logText->appendText("\nErfolgreich abgeschlossen.\n");
		domainState = detectDomainState();
	}
}

void DcPromoWizard::create() {
	FXMainWindow::create();
	show(PLACEMENT_SCREEN);
}

int main(int argc, char* argv[]) {
	FXApp application("DcPromo", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	DcPromoWizard* win = new DcPromoWizard(&application);
	application.create();
	win->show(PLACEMENT_SCREEN);

	if (!g_haveRoot) {
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\n"
			"Der Assistent kann den aktuellen Status anzeigen, aber keine\n"
			"Änderungen vornehmen.");
	}

	return application.run();
}
