// certsrv.cpp
//
// "Zertifizierungsstelle" fuer ice2k -- Nachbau von certsrv.msc aus
// Windows 2000 Server.
//
// Unterbau ist eine openssl-CA unter /etc/ice2k/ca mit der ueblichen
// Ablage: ca.crt, private/ca.key, index.txt (die Datenbank von
// "openssl ca"), serial, newcerts/ und crl.pem. Aus index.txt kommen die
// Listen "Ausgestellte Zertifikate" und "Gesperrte Zertifikate"; Sperren
// und Sperrliste erledigt ebenfalls "openssl ca".

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
#include <ctime>
#include <unistd.h>
#include <sys/wait.h>

static FXApp* app = NULL;
static bool g_haveRoot = false;

static const char* CA_DIR = "/etc/ice2k/ca";

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

static std::vector<std::string> splitOn(const std::string& s, char sep) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : s) { if (c == sep) { out.push_back(cur); cur.clear(); } else cur += c; }
	out.push_back(cur);
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

static bool rootShell(const std::string& cmd, std::string& out) {
	return runAsRootCaptured({ "sh", "-c", cmd }, out) == 0;
}

static std::string readAsRoot(const std::string& path) {
	std::string out;
	if (runAsRootCaptured({ "cat", path }, out) != 0) return "";
	return out;
}

static bool writeFileAsRoot(const std::string& path, const std::string& content, FXString& errorMsg) {
	std::string tmp = "/tmp/ice2k-certsrv.tmp";
	{
		std::ofstream out(tmp, std::ios::binary);
		if (!out) { errorMsg = "Temporäre Datei konnte nicht geschrieben werden."; return false; }
		out << content;
	}
	std::string out;
	int rc = runAsRootCaptured({ "cp", tmp, path }, out);
	runAsRoot({ "rm", "-f", tmp });
	if (rc != 0) {
		errorMsg = FXString("Die Datei konnte nicht geschrieben werden:\n") + path.c_str() + "\n\n" + trimStr(out).c_str();
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------
// Zustand der Zertifizierungsstelle
// ---------------------------------------------------------------------
struct CertEntry {
	char state = 'V';        // V gültig, R gesperrt, E abgelaufen
	std::string expiry;      // YYMMDDHHMMSSZ
	std::string revoked;     // dito, nur bei R
	std::string serial;
	std::string subject;
	std::string commonName;
	std::string reason;      // Sperrgrund
};

static bool caExists() {
	return runAsRoot({ "test", "-f", std::string(CA_DIR) + "/ca.crt" }) == 0;
}

// "250918120000Z" -> "18.09.2025 12:00"
static FXString formatCertTime(const std::string& t) {
	if (t.size() < 13) return t.c_str();
	std::string yy = t.substr(0, 2), mm = t.substr(2, 2), dd = t.substr(4, 2),
	            hh = t.substr(6, 2), mi = t.substr(8, 2);
	int year = atoi(yy.c_str());
	year += (year < 50) ? 2000 : 1900;
	char buf[40];
	snprintf(buf, sizeof(buf), "%s.%s.%d %s:%s", dd.c_str(), mm.c_str(), year, hh.c_str(), mi.c_str());
	return buf;
}

// index.txt: Status \t Ablauf \t [Sperrdatum[,Grund]] \t Seriennummer \t Datei \t Betreff
static std::vector<CertEntry> listCertificates() {
	std::vector<CertEntry> out;
	for (auto& line : splitLines(readAsRoot(std::string(CA_DIR) + "/index.txt"))) {
		if (trimStr(line).empty()) continue;
		std::vector<std::string> f = splitOn(line, '\t');
		if (f.size() < 6) continue;
		CertEntry c;
		c.state = f[0].empty() ? 'V' : f[0][0];
		c.expiry = f[1];
		if (!f[2].empty()) {
			size_t comma = f[2].find(',');
			c.revoked = comma == std::string::npos ? f[2] : f[2].substr(0, comma);
			if (comma != std::string::npos) c.reason = f[2].substr(comma + 1);
		}
		c.serial = f[3];
		c.subject = f[5];
		size_t cn = c.subject.find("CN=");
		if (cn != std::string::npos) {
			c.commonName = trimStr(c.subject.substr(cn + 3));
			size_t slash = c.commonName.find('/');
			if (slash != std::string::npos) c.commonName = trimStr(c.commonName.substr(0, slash));
		}
		out.push_back(c);
	}
	return out;
}

static std::string caSubject() {
	std::string out;
	rootShell(std::string("openssl x509 -noout -subject -in ") + CA_DIR + "/ca.crt 2>/dev/null | sed 's/^subject=//'", out);
	return trimStr(out);
}

static std::string caValidUntil() {
	std::string out;
	rootShell(std::string("openssl x509 -noout -enddate -in ") + CA_DIR + "/ca.crt 2>/dev/null | cut -d= -f2", out);
	return trimStr(out);
}

// Konfiguration für "openssl ca" -- ohne sie kennt openssl weder
// Datenbank noch Vorgaben.
static std::string opensslConfig() {
	return std::string(
		"# Von ice2k \"Zertifizierungsstelle\" erzeugt.\n"
		"[ ca ]\n"
		"default_ca = ice2k_ca\n\n"
		"[ ice2k_ca ]\n"
		"dir               = ") + CA_DIR + "\n"
		"database          = $dir/index.txt\n"
		"new_certs_dir     = $dir/newcerts\n"
		"certificate       = $dir/ca.crt\n"
		"private_key       = $dir/private/ca.key\n"
		"serial            = $dir/serial\n"
		"crlnumber         = $dir/crlnumber\n"
		"crl               = $dir/crl.pem\n"
		"default_md        = sha256\n"
		"default_days      = 730\n"
		"default_crl_days  = 30\n"
		"policy            = policy_any\n"
		"email_in_dn       = no\n"
		"unique_subject    = no\n"
		"copy_extensions   = none\n\n"
		"[ policy_any ]\n"
		"commonName        = supplied\n"
		"countryName       = optional\n"
		"stateOrProvinceName = optional\n"
		"organizationName  = optional\n"
		"organizationalUnitName = optional\n"
		"emailAddress      = optional\n\n"
		"[ v3_server ]\n"
		"basicConstraints = CA:FALSE\n"
		"keyUsage = digitalSignature, keyEncipherment\n"
		"extendedKeyUsage = serverAuth\n\n"
		"[ v3_client ]\n"
		"basicConstraints = CA:FALSE\n"
		"keyUsage = digitalSignature\n"
		"extendedKeyUsage = clientAuth\n\n"
		"[ v3_user ]\n"
		"basicConstraints = CA:FALSE\n"
		"keyUsage = digitalSignature, keyEncipherment\n"
		"extendedKeyUsage = clientAuth, emailProtection\n";
}

static bool setupCa(const std::string& name, int years, int bits, FXString& errorMsg) {
	if (!writeFileAsRoot("/tmp/ice2k-ca.cnf", opensslConfig(), errorMsg)) return false;
	std::string cmd =
		std::string("set -e\numask 077\n") +
		"mkdir -p " + CA_DIR + "/private " + CA_DIR + "/newcerts " + CA_DIR + "/certs\n"
		"cp /tmp/ice2k-ca.cnf " + CA_DIR + "/openssl.cnf\n"
		"rm -f /tmp/ice2k-ca.cnf\n"
		"[ -f " + CA_DIR + "/index.txt ] || : > " + CA_DIR + "/index.txt\n"
		"[ -f " + CA_DIR + "/serial ] || echo 1000 > " + CA_DIR + "/serial\n"
		"[ -f " + CA_DIR + "/crlnumber ] || echo 1000 > " + CA_DIR + "/crlnumber\n"
		"openssl req -x509 -newkey rsa:" + std::to_string(bits) + " -nodes "
		"-keyout " + CA_DIR + "/private/ca.key -out " + CA_DIR + "/ca.crt "
		"-days " + std::to_string(years * 365) + " -subj '/CN=" + name + "'\n"
		"chmod 600 " + CA_DIR + "/private/ca.key\n";
	std::string out;
	if (!rootShell(cmd, out)) {
		errorMsg = FXString("Die Zertifizierungsstelle konnte nicht eingerichtet werden:\n") + trimStr(out).c_str();
		return false;
	}
	return true;
}

// Stellt ein Zertifikat aus und liefert Schlüssel und Zertifikat zurück.
static bool issueCertificate(const std::string& cn, const std::string& profile, int days,
                             std::string& keyPem, std::string& certPem, FXString& errorMsg) {
	std::string tmpKey = "/tmp/ice2k-cert.key", tmpCsr = "/tmp/ice2k-cert.csr", tmpCrt = "/tmp/ice2k-cert.crt";
	std::string cmd =
		std::string("set -e\numask 077\n") +
		"openssl req -newkey rsa:2048 -nodes -keyout " + tmpKey + " -out " + tmpCsr + " -subj '/CN=" + cn + "'\n"
		"openssl ca -batch -config " + CA_DIR + "/openssl.cnf -extensions " + profile +
		" -days " + std::to_string(days) + " -in " + tmpCsr + " -out " + tmpCrt + "\n";
	std::string out;
	if (!rootShell(cmd, out)) {
		errorMsg = FXString("Das Zertifikat konnte nicht ausgestellt werden:\n") + trimStr(out).c_str();
		rootShell("rm -f " + tmpKey + " " + tmpCsr + " " + tmpCrt, out);
		return false;
	}
	keyPem = readAsRoot(tmpKey);
	certPem = readAsRoot(tmpCrt);
	rootShell("rm -f " + tmpKey + " " + tmpCsr + " " + tmpCrt, out);
	return true;
}

static bool revokeCertificate(const std::string& serial, const std::string& reason, FXString& errorMsg) {
	std::string out;
	std::string cmd =
		std::string("set -e\n") +
		"openssl ca -config " + CA_DIR + "/openssl.cnf -revoke " + CA_DIR + "/newcerts/" + serial + ".pem"
		" -crl_reason " + reason + "\n"
		// Sperrliste gleich neu schreiben, sonst geht der Widerruf ins Leere.
		"openssl ca -config " + CA_DIR + "/openssl.cnf -gencrl -out " + CA_DIR + "/crl.pem\n";
	if (!rootShell(cmd, out)) {
		errorMsg = FXString("Das Zertifikat konnte nicht gesperrt werden:\n") + trimStr(out).c_str();
		return false;
	}
	return true;
}

static bool publishCrl(FXString& errorMsg) {
	std::string out;
	if (!rootShell(std::string("openssl ca -config ") + CA_DIR + "/openssl.cnf -gencrl -out " + CA_DIR + "/crl.pem 2>&1", out)) {
		errorMsg = FXString("Die Sperrliste konnte nicht erzeugt werden:\n") + trimStr(out).c_str();
		return false;
	}
	return true;
}

static bool exportFileAsRoot(const std::string& source, const FXString& target, FXString& errorMsg) {
	std::string content = readAsRoot(source);
	if (content.empty()) { errorMsg = FXString("Die Datei ist leer oder fehlt:\n") + source.c_str(); return false; }
	std::ofstream out(target.text(), std::ios::binary);
	if (!out) { errorMsg = FXString("Die Datei konnte nicht geschrieben werden:\n") + target; return false; }
	out << content;
	return true;
}

// ---------------------------------------------------------------------
// Dialoge
// ---------------------------------------------------------------------
class SetupCaDialog : public FXDialogBox {
	FXDECLARE(SetupCaDialog)
private:
	FXTextField* nameField = nullptr;
	FXSpinner *yearsField = nullptr;
	FXListBox* bitsBox = nullptr;
protected:
	SetupCaDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	SetupCaDialog(FXWindow* owner, const std::string& suggestion)
		: FXDialogBox(owner, "Zertifizierungsstelle einrichten", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,480,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Diese Zertifizierungsstelle stellt Zertifikate für Server, Clients und\n"
		                  "Benutzer aus. Ihr eigenes Zertifikat gehört auf alle beteiligten Rechner.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXMatrix* m = new FXMatrix(main, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
		new FXLabel(m, "&Name:", NULL, JUSTIFY_LEFT);
		nameField = new FXTextField(m, 28, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		nameField->setText(suggestion.c_str());
		new FXLabel(m, "&Gültigkeit (Jahre):", NULL, JUSTIFY_LEFT);
		yearsField = new FXSpinner(m, 5, NULL, 0, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		yearsField->setRange(1, 20);
		yearsField->setValue(10);
		new FXLabel(m, "&Schlüssellänge:", NULL, JUSTIFY_LEFT);
		bitsBox = new FXListBox(m, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		bitsBox->appendItem("2048 Bit");
		bitsBox->appendItem("4096 Bit");
		bitsBox->setNumVisible(2);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (trimStr(nameField->getText().text()).empty()) {
			ice2kui::error(this, MBOX_OK, "Zertifizierungsstelle", "Geben Sie einen Namen an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string name() const { return trimStr(nameField->getText().text()); }
	int years() const { return yearsField->getValue(); }
	int bits() const { return bitsBox->getCurrentItem() == 1 ? 4096 : 2048; }
	virtual ~SetupCaDialog() {}
};
FXDEFMAP(SetupCaDialog) SetupCaDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, SetupCaDialog::ID_OK, SetupCaDialog::onOk),
};
FXIMPLEMENT(SetupCaDialog, FXDialogBox, SetupCaDialogMap, ARRAYNUMBER(SetupCaDialogMap))

class IssueDialog : public FXDialogBox {
	FXDECLARE(IssueDialog)
private:
	FXTextField* nameField = nullptr;
	FXListBox* typeBox = nullptr;
	FXSpinner* daysField = nullptr;
protected:
	IssueDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	IssueDialog(FXWindow* owner)
		: FXDialogBox(owner, "Neues Zertifikat", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,460,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Die Zertifizierungsstelle stellt ein neues Zertifikat aus und zeigt\n"
		                  "anschließend Schlüssel und Zertifikat zum Speichern an.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXMatrix* m = new FXMatrix(main, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
		new FXLabel(m, "&Name (CN):", NULL, JUSTIFY_LEFT);
		nameField = new FXTextField(m, 26, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		new FXLabel(m, "&Verwendungszweck:", NULL, JUSTIFY_LEFT);
		typeBox = new FXListBox(m, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		typeBox->appendItem("Serverauthentifizierung");
		typeBox->appendItem("Clientauthentifizierung");
		typeBox->appendItem("Benutzer (Anmeldung und E-Mail)");
		typeBox->setNumVisible(3);
		new FXLabel(m, "&Gültigkeit (Tage):", NULL, JUSTIFY_LEFT);
		daysField = new FXSpinner(m, 6, NULL, 0, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		daysField->setRange(1, 3650);
		daysField->setValue(730);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		std::string n = trimStr(nameField->getText().text());
		if (n.empty() || n.find('/') != std::string::npos) {
			ice2kui::error(this, MBOX_OK, "Neues Zertifikat", "Geben Sie einen Namen ohne Schrägstrich an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string name() const { return trimStr(nameField->getText().text()); }
	std::string profile() const {
		int i = typeBox->getCurrentItem();
		return i == 0 ? "v3_server" : i == 1 ? "v3_client" : "v3_user";
	}
	int days() const { return daysField->getValue(); }
	virtual ~IssueDialog() {}
};
FXDEFMAP(IssueDialog) IssueDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, IssueDialog::ID_OK, IssueDialog::onOk),
};
FXIMPLEMENT(IssueDialog, FXDialogBox, IssueDialogMap, ARRAYNUMBER(IssueDialogMap))

// Zeigt Schlüssel und Zertifikat zum Speichern (wie in Routing und RAS).
class PemDialog : public FXDialogBox {
	FXDECLARE(PemDialog)
private:
	FXText* text = nullptr;
	std::string suggested;
protected:
	PemDialog() {}
public:
	enum { ID_SAVE = FXDialogBox::ID_LAST };
	PemDialog(FXWindow* owner, const FXString& title, const std::string& content, const std::string& suggestedFile)
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,620,460), suggested(suggestedFile) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, "Schlüssel und Zertifikat -- die Zertifizierungsstelle bewahrt den\n"
		                  "privaten Schlüssel nicht auf.", NULL, JUSTIFY_LEFT);
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
		if (!out) { ice2kui::error(this, MBOX_OK, "Speichern", "Die Datei konnte nicht geschrieben werden."); return 1; }
		out << text->getText().text();
		return 1;
	}
	virtual ~PemDialog() {}
};
FXDEFMAP(PemDialog) PemDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, PemDialog::ID_SAVE, PemDialog::onSave),
};
FXIMPLEMENT(PemDialog, FXDialogBox, PemDialogMap, ARRAYNUMBER(PemDialogMap))

// Sperrgrund wie im Original.
class RevokeDialog : public FXDialogBox {
	FXDECLARE(RevokeDialog)
private:
	FXListBox* reasonBox = nullptr;
protected:
	RevokeDialog() {}
public:
	RevokeDialog(FXWindow* owner, const std::string& cn)
		: FXDialogBox(owner, "Zertifikat sperren", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		new FXLabel(main, FXString("Das Zertifikat \"") + cn.c_str() + "\" wird gesperrt und in die\n"
		                  "Sperrliste aufgenommen. Das lässt sich nicht rückgängig machen.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXLabel(r, "&Grund:", NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,120,0);
		reasonBox = new FXListBox(r, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		// Gründe des Originals (RFC 5280).
		reasonBox->appendItem("Nicht angegeben");
		reasonBox->appendItem("Schlüssel kompromittiert");
		reasonBox->appendItem("Zertifizierungsstelle kompromittiert");
		reasonBox->appendItem("Zugehörigkeit geändert");
		reasonBox->appendItem("Ersetzt");
		reasonBox->appendItem("Betrieb eingestellt");
		reasonBox->appendItem("Sperrung vorläufig");
		reasonBox->setNumVisible(7);
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	std::string reason() const {
		static const char* reasons[] = { "unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
		                                 "superseded", "cessationOfOperation", "certificateHold" };
		int i = reasonBox->getCurrentItem();
		return reasons[(i >= 0 && i < 7) ? i : 0];
	}
	virtual ~RevokeDialog() {}
};
FXIMPLEMENT(RevokeDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
enum NodeKind { NK_ROOT, NK_CA, NK_ISSUED, NK_REVOKED };

class CertSrvWindow : public FXMainWindow {
	FXDECLARE(CertSrvWindow)
private:
	FXTreeList* tree = nullptr;
	FXIconList* list = nullptr;
	FXLabel* statusbar = nullptr;
	FXIcon *icoRoot = nullptr, *icoCa = nullptr, *icoFolder = nullptr, *icoCert = nullptr;
	std::map<FXTreeItem*, NodeKind> nodes;
	std::vector<CertEntry> certs, shown;
protected:
	CertSrvWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_SETUP, ID_ISSUE, ID_REVOKE, ID_PUBLISH_CRL,
	       ID_EXPORT_CA, ID_EXPORT_CRL, ID_REFRESH, ID_ABOUT };

	CertSrvWindow(FXApp* a);
	virtual void create();
	long onTree(FXObject*, FXSelector, void*);
	long onListRight(FXObject*, FXSelector, void*);
	long onSetup(FXObject*, FXSelector, void*);
	long onIssue(FXObject*, FXSelector, void*);
	long onRevoke(FXObject*, FXSelector, void*);
	long onPublishCrl(FXObject*, FXSelector, void*);
	long onExportCa(FXObject*, FXSelector, void*);
	long onExportCrl(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	void reload();
	void showFor(FXTreeItem* item);
	NodeKind currentKind();
	virtual ~CertSrvWindow() {}
};

FXDEFMAP(CertSrvWindow) CertSrvWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, CertSrvWindow::ID_TREE, CertSrvWindow::onTree),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, CertSrvWindow::ID_LIST, CertSrvWindow::onListRight),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_SETUP, CertSrvWindow::onSetup),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_ISSUE, CertSrvWindow::onIssue),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_REVOKE, CertSrvWindow::onRevoke),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_PUBLISH_CRL, CertSrvWindow::onPublishCrl),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_EXPORT_CA, CertSrvWindow::onExportCa),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_EXPORT_CRL, CertSrvWindow::onExportCrl),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_REFRESH, CertSrvWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, CertSrvWindow::ID_ABOUT, CertSrvWindow::onAbout),
};
FXIMPLEMENT(CertSrvWindow, FXMainWindow, CertSrvWindowMap, ARRAYNUMBER(CertSrvWindowMap))

CertSrvWindow::CertSrvWindow(FXApp* a)
	: FXMainWindow(a, "Zertifizierungsstelle", NULL, NULL, DECOR_ALL, 0,0, 920,560) {
	icoRoot = new FXPNGIcon(a, resico_key, IMAGE_NEAREST);
	icoCa = new FXPNGIcon(a, resico_server, IMAGE_NEAREST);
	icoFolder = new FXPNGIcon(a, resico_folder, IMAGE_NEAREST);
	icoCert = new FXPNGIcon(a, resico_key, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoCa, icoFolder, icoCert }) i->create();

	FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	FXMenuPane* vorgang = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
	new FXMenuCommand(vorgang, "Zertifizierungsstelle ein&richten...", NULL, this, ID_SETUP);
	new FXMenuCommand(vorgang, "&Neues Zertifikat...", NULL, this, ID_ISSUE);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "Sperrliste &veröffentlichen", NULL, this, ID_PUBLISH_CRL);
	new FXMenuCommand(vorgang, "&CA-Zertifikat exportieren...", NULL, this, ID_EXPORT_CA);
	new FXMenuCommand(vorgang, "&Sperrliste exportieren...", NULL, this, ID_EXPORT_CRL);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Aktualisieren", NULL, this, ID_REFRESH);
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
	tb("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
	tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	new FXToolTip(getApp());

	statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);

	FXSplitter* splitter = new FXSplitter(this, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,300,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
	FXPacker* listframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(listframe, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
}

void CertSrvWindow::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

void CertSrvWindow::reload() {
	NodeKind sel = nodes.count(tree->getCurrentItem()) ? nodes[tree->getCurrentItem()] : NK_ROOT;
	getApp()->beginWaitCursor();
	certs = caExists() ? listCertificates() : std::vector<CertEntry>();
	getApp()->endWaitCursor();
	tree->clearItems();
	nodes.clear();
	char host[256] = { 0 };
	gethostname(host, sizeof(host) - 1);
	FXTreeItem* root = tree->appendItem(0, FXString("Zertifizierungsstelle (Lokal: ") + host + ")", icoRoot, icoRoot);
	nodes[root] = NK_ROOT;
	FXTreeItem* select = root;
	if (caExists()) {
		// openssl schreibt je nach Fassung "CN=..." oder "CN = ...".
		std::string subject = caSubject();
		std::string name = subject;
		size_t cn = subject.find("CN");
		if (cn != std::string::npos) {
			size_t eq = subject.find('=', cn);
			if (eq != std::string::npos) name = trimStr(subject.substr(eq + 1));
		}
		FXTreeItem* ca = tree->appendItem(root, name.c_str(), icoCa, icoCa);
		nodes[ca] = NK_CA;
		FXTreeItem* issued = tree->appendItem(ca, "Ausgestellte Zertifikate", icoFolder, icoFolder);
		nodes[issued] = NK_ISSUED;
		FXTreeItem* revoked = tree->appendItem(ca, "Gesperrte Zertifikate", icoFolder, icoFolder);
		nodes[revoked] = NK_REVOKED;
		tree->expandTree(ca);
		if (sel == NK_ISSUED) select = issued;
		else if (sel == NK_REVOKED) select = revoked;
		else if (sel == NK_CA) select = ca;
	}
	tree->expandTree(root);
	tree->setCurrentItem(select);
	tree->selectItem(select);
	showFor(select);
}

NodeKind CertSrvWindow::currentKind() {
	auto it = nodes.find(tree->getCurrentItem());
	return it == nodes.end() ? NK_ROOT : it->second;
}

void CertSrvWindow::showFor(FXTreeItem* item) {
	while (list->getNumHeaders() > 0) list->removeHeader(0);
	list->clearItems();
	shown.clear();
	NodeKind kind = nodes.count(item) ? nodes[item] : NK_ROOT;
	if (!caExists()) {
		list->appendHeader("Hinweis", NULL, 600);
		list->appendItem("Auf diesem Server ist keine Zertifizierungsstelle eingerichtet.", icoRoot, icoRoot);
		list->appendItem("Menü \"Vorgang\" -> \"Zertifizierungsstelle einrichten...\"", icoRoot, icoRoot);
		statusbar->setText(" Keine Zertifizierungsstelle eingerichtet.");
		return;
	}
	if (kind == NK_ROOT || kind == NK_CA) {
		list->appendHeader("Name", NULL, 260);
		list->appendHeader("Beschreibung", NULL, 380);
		list->appendItem(FXString("Ausgestellte Zertifikate\tGültige und abgelaufene Zertifikate"), icoFolder, icoFolder);
		list->appendItem(FXString("Gesperrte Zertifikate\tZertifikate in der Sperrliste"), icoFolder, icoFolder);
		int valid = 0, revoked = 0;
		for (auto& c : certs) { if (c.state == 'R') revoked++; else valid++; }
		statusbar->setText(FXString(" ") + caSubject().c_str() + " -- gültig bis " + caValidUntil().c_str() +
		                   ",  " + FXString(std::to_string(valid).c_str()) + " ausgestellt, " +
		                   FXString(std::to_string(revoked).c_str()) + " gesperrt");
		return;
	}
	if (kind == NK_ISSUED) {
		// Spalten wie im Original.
		list->appendHeader("Anforderungs-ID", NULL, 130);
		list->appendHeader("Antragsteller", NULL, 220);
		list->appendHeader("Gültig bis", NULL, 160);
		list->appendHeader("Status", NULL, 120);
		for (auto& c : certs) {
			if (c.state == 'R') continue;
			shown.push_back(c);
			list->appendItem(FXString(c.serial.c_str()) + "\t" + c.commonName.c_str() + "\t" +
			                 formatCertTime(c.expiry) + "\t" + (c.state == 'E' ? "Abgelaufen" : "Gültig"), icoCert, icoCert);
		}
		statusbar->setText(shown.empty() ? FXString(" Noch kein Zertifikat ausgestellt. Rechtsklick: Neues Zertifikat.")
		                                 : FXString(" ") + FXString(std::to_string(shown.size()).c_str()) + " Zertifikat(e)");
		return;
	}
	list->appendHeader("Anforderungs-ID", NULL, 130);
	list->appendHeader("Antragsteller", NULL, 220);
	list->appendHeader("Sperrdatum", NULL, 160);
	list->appendHeader("Sperrgrund", NULL, 200);
	for (auto& c : certs) {
		if (c.state != 'R') continue;
		shown.push_back(c);
		list->appendItem(FXString(c.serial.c_str()) + "\t" + c.commonName.c_str() + "\t" +
		                 formatCertTime(c.revoked) + "\t" + (c.reason.empty() ? "Nicht angegeben" : c.reason.c_str()), icoCert, icoCert);
	}
	statusbar->setText(shown.empty() ? FXString(" Kein Zertifikat gesperrt.")
	                                 : FXString(" ") + FXString(std::to_string(shown.size()).c_str()) + " gesperrt");
}

long CertSrvWindow::onTree(FXObject*, FXSelector, void*) { showFor(tree->getCurrentItem()); return 1; }

long CertSrvWindow::onListRight(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx >= 0) { list->setCurrentItem(idx); list->selectItem(idx); }
	FXMenuPane menu(this);
	if (!caExists()) {
		new FXMenuCommand(&menu, "Zertifizierungsstelle ein&richten...", NULL, this, ID_SETUP);
	} else if (currentKind() == NK_ISSUED) {
		new FXMenuCommand(&menu, "&Neues Zertifikat...", NULL, this, ID_ISSUE);
		if (idx >= 0 && idx < (int)shown.size()) {
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "Zertifikat &sperren...", NULL, this, ID_REVOKE);
		}
	} else if (currentKind() == NK_REVOKED) {
		new FXMenuCommand(&menu, "Sperrliste &veröffentlichen", NULL, this, ID_PUBLISH_CRL);
		new FXMenuCommand(&menu, "Sperrliste &exportieren...", NULL, this, ID_EXPORT_CRL);
	} else {
		new FXMenuCommand(&menu, "&Neues Zertifikat...", NULL, this, ID_ISSUE);
		new FXMenuCommand(&menu, "&CA-Zertifikat exportieren...", NULL, this, ID_EXPORT_CA);
	}
	new FXMenuSeparator(&menu);
	new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long CertSrvWindow::onSetup(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Zertifizierungsstelle", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	if (caExists()) {
		ice2kui::information(this, MBOX_OK, "Zertifizierungsstelle",
			"Auf diesem Server ist bereits eine Zertifizierungsstelle eingerichtet.");
		return 1;
	}
	char host[256] = { 0 };
	gethostname(host, sizeof(host) - 1);
	SetupCaDialog dlg(this, std::string("ice2k CA auf ") + host);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	getApp()->beginWaitCursor();
	FXString errorMsg;
	bool ok = setupCa(dlg.name(), dlg.years(), dlg.bits(), errorMsg);
	getApp()->endWaitCursor();
	if (!ok) ice2kui::error(this, MBOX_OK, "Zertifizierungsstelle", "%s", errorMsg.text());
	else ice2kui::information(this, MBOX_OK, "Zertifizierungsstelle",
		"Die Zertifizierungsstelle wurde unter %s eingerichtet.\n\n"
		"Das CA-Zertifikat gehört auf alle Rechner, die den ausgestellten\n"
		"Zertifikaten vertrauen sollen.", CA_DIR);
	reload();
	return 1;
}

long CertSrvWindow::onIssue(FXObject*, FXSelector, void*) {
	if (!caExists()) { ice2kui::information(this, MBOX_OK, "Zertifizierungsstelle", "Richten Sie zuerst die Zertifizierungsstelle ein."); return 1; }
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Zertifizierungsstelle", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	IssueDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	std::string keyPem, certPem;
	FXString errorMsg;
	getApp()->beginWaitCursor();
	bool ok = issueCertificate(dlg.name(), dlg.profile(), dlg.days(), keyPem, certPem, errorMsg);
	getApp()->endWaitCursor();
	if (!ok) { ice2kui::error(this, MBOX_OK, "Neues Zertifikat", "%s", errorMsg.text()); return 1; }
	reload();
	PemDialog pem(this, FXString("Zertifikat für ") + dlg.name().c_str(), keyPem + certPem, dlg.name() + ".pem");
	pem.execute(PLACEMENT_OWNER);
	return 1;
}

long CertSrvWindow::onRevoke(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (currentKind() != NK_ISSUED || idx < 0 || idx >= (int)shown.size()) return 1;
	if (!g_haveRoot) { ice2kui::error(this, MBOX_OK, "Zertifizierungsstelle", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	RevokeDialog dlg(this, shown[idx].commonName);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!revokeCertificate(shown[idx].serial, dlg.reason(), errorMsg))
		ice2kui::error(this, MBOX_OK, "Zertifikat sperren", "%s", errorMsg.text());
	reload();
	return 1;
}

long CertSrvWindow::onPublishCrl(FXObject*, FXSelector, void*) {
	if (!caExists() || !g_haveRoot) return 1;
	FXString errorMsg;
	if (!publishCrl(errorMsg)) ice2kui::error(this, MBOX_OK, "Sperrliste", "%s", errorMsg.text());
	else ice2kui::information(this, MBOX_OK, "Sperrliste",
		"Die Sperrliste wurde neu erzeugt:\n%s/crl.pem", CA_DIR);
	return 1;
}

long CertSrvWindow::onExportCa(FXObject*, FXSelector, void*) {
	if (!caExists()) return 1;
	FXString target = FXFileDialog::getSaveFilename(this, "CA-Zertifikat exportieren", "ca.crt");
	if (target.empty()) return 1;
	FXString errorMsg;
	if (!exportFileAsRoot(std::string(CA_DIR) + "/ca.crt", target, errorMsg))
		ice2kui::error(this, MBOX_OK, "Exportieren", "%s", errorMsg.text());
	return 1;
}

long CertSrvWindow::onExportCrl(FXObject*, FXSelector, void*) {
	if (!caExists()) return 1;
	if (runAsRoot({ "test", "-f", std::string(CA_DIR) + "/crl.pem" }) != 0) {
		FXString errorMsg;
		if (!publishCrl(errorMsg)) { ice2kui::error(this, MBOX_OK, "Sperrliste", "%s", errorMsg.text()); return 1; }
	}
	FXString target = FXFileDialog::getSaveFilename(this, "Sperrliste exportieren", "crl.pem");
	if (target.empty()) return 1;
	FXString errorMsg;
	if (!exportFileAsRoot(std::string(CA_DIR) + "/crl.pem", target, errorMsg))
		ice2kui::error(this, MBOX_OK, "Exportieren", "%s", errorMsg.text());
	return 1;
}

long CertSrvWindow::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }

long CertSrvWindow::onAbout(FXObject*, FXSelector, void*) {
	ice2kui::information(this, MBOX_OK, "Info",
		"Zertifizierungsstelle (ice2k)\n\n"
		"Eine openssl-Zertifizierungsstelle unter %s:\n"
		"ca.crt, private/ca.key, index.txt, serial, newcerts und crl.pem.\n\n"
		"Ausstellen, Sperren und die Sperrliste erledigt \"openssl ca\".", CA_DIR);
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("CertSrv", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	g_haveRoot = (runAsRoot({ "true" }) == 0);
	CertSrvWindow* win = new CertSrvWindow(&application);
	application.create();
	if (!g_haveRoot)
		ice2kui::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\nDie Anzeige funktioniert, Änderungen sind nicht möglich.");
	return application.run();
}
