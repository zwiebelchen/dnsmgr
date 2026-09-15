// compmgmt.cpp
//
// Computerverwaltung fuer ice2k -- Nachbau des Windows 2000
// "Computerverwaltung"-MMC-Snapins, Zweige "Lokale Benutzer und
// Gruppen" und "Freigegebene Ordner" (Freigaben aus der smb.conf,
// Sitzungen/Geoeffnete Dateien live aus smbstatus).
//
// Backend: echte Linux-Benutzer/-Gruppen (useradd/usermod/userdel/
// groupadd/groupdel/gpasswd) UND parallel dazu Samba (smbpasswd/
// pdbedit), damit dasselbe Konto sowohl lokal als auch fuer
// SMB-Freigaben funktioniert -- genau wie ein lokales SAM-Konto unter
// Windows 2000 fuer beides gilt.

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "../common/svc/svcpanel.h"

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

// ---------------------------------------------------------------------
// Root-Rechte ueber i2ksudo -- identisches Muster wie in dnsmgr/dhcpmgr.
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

// Fuehrt ein Kommando als root aus und schickt "input" (ggf. mehrzeilig,
// z.B. ein Kennwort zweimal fuer smbpasswd/chpasswd) auf dessen Standard-
// eingabe. Gebraucht, weil chpasswd/smbpasswd das Kennwort nicht als
// Kommandozeilenargument nehmen (stuende sonst sichtbar im Prozessabbild).
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

// Fuehrt ein Kommando als root aus und liefert dessen Standardausgabe
// zurueck (fuer lesende Befehle wie "smbstatus --json").
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

// die Kea-Config beim DHCP-Manager gibt es hier kein Verzeichnisrechte-
// Problem.
// ---------------------------------------------------------------------
struct UserInfo {
	FXString username, uid, gid, fullName, description, homeDir, shell;
	bool locked = false;
};
struct GroupInfo {
	FXString groupname, gid;
	std::vector<FXString> members;
};
struct ShareInfo {
	FXString name, path, comment;
	bool readOnly = false;
};
struct SessionInfo {
	FXString username, remoteMachine, shares, dialect;
};
struct OpenFileInfo {
	FXString path, username, share;
};

static std::vector<std::string> splitStr(const std::string& s, char sep) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : s) { if (c == sep) { out.push_back(cur); cur.clear(); } else cur += c; }
	out.push_back(cur);
	return out;
}

// ---------------------------------------------------------------------
// Domaenencontroller-Erkennung -- gleiches Muster wie in dcpromo/dsadmin.
// Anders als bei Windows verschwinden die Linux-Konten (/etc/passwd)
// NICHT, wenn der Server zum AD-Domaenencontroller wird -- samba-tool
// domain provision ersetzt nur Sambas eigene Passwort-Datenbank
// (tdbsam), nicht die Unix-Konten selbst. Diese bleiben fuer SSH/sudo/
// Systemdienste weiterhin nötig. Deshalb sperren wir hier NICHT wie im
// Original, sondern deuten um: weiterhin nutzbar als Verwaltung fuer
// lokale Linux-Systemkonten, aber ohne Samba-Anbindung fuer neue/
// geaenderte Konten (die alte tdbsam-Datenbank ist nach der AD-
// Provisionierung ohnehin verwaist -- smbd/nmbd laufen dann gar nicht
// mehr, ihre Aufgabe uebernimmt der vereinheitlichte samba-ad-dc-Prozess).
static bool isDomainController() {
	std::ifstream in("/etc/samba/smb.conf");
	if (!in.is_open()) return false;
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	std::string line;
	std::istringstream iss(content);
	while (std::getline(iss, line)) {
		size_t p = line.find('=');
		if (p == std::string::npos) continue;
		std::string k = line.substr(0, p);
		size_t a = k.find_first_not_of(" \t");
		size_t b = k.find_last_not_of(" \t");
		if (a == std::string::npos) continue;
		k = k.substr(a, b - a + 1);
		if (k != "server role") continue;
		return line.find("domain controller") != std::string::npos;
	}
	return false;
}

static std::vector<UserInfo> parseUsers() {
	std::vector<UserInfo> out;
	std::ifstream in("/etc/passwd");
	std::string line;
	while (std::getline(in, line)) {
		auto f = splitStr(line, ':');
		if (f.size() < 7) continue;
		UserInfo u;
		u.username = f[0].c_str();
		u.uid = f[2].c_str();
		u.gid = f[3].c_str();
		// GECOS-Feld: "Vollstaendiger Name,,,Beschreibung" (wir nutzen das
		// vierte Unterfeld fuer unsere "Beschreibung", analog zum Original).
		auto gecos = splitStr(f[4], ',');
		u.fullName = gecos.size() > 0 ? gecos[0].c_str() : "";
		u.description = gecos.size() > 3 ? gecos[3].c_str() : "";
		u.homeDir = f[5].c_str();
		u.shell = f[6].c_str();
		out.push_back(u);
	}
	// Gesperrte Konten aus /etc/shadow ermitteln (Passwortfeld beginnt mit "!").
	std::ifstream sh("/etc/shadow");
	while (std::getline(sh, line)) {
		auto f = splitStr(line, ':');
		if (f.size() < 2) continue;
		bool locked = !f[1].empty() && f[1][0] == '!';
		for (auto& u : out) if (u.username == f[0].c_str()) u.locked = locked;
	}
	return out;
}

static std::vector<GroupInfo> parseGroups() {
	std::vector<GroupInfo> out;
	std::ifstream in("/etc/group");
	std::string line;
	while (std::getline(in, line)) {
		auto f = splitStr(line, ':');
		if (f.size() < 4) continue;
		GroupInfo g;
		g.groupname = f[0].c_str();
		g.gid = f[2].c_str();
		if (!f[3].empty()) {
			for (auto& m : splitStr(f[3], ',')) g.members.push_back(m.c_str());
		}
		out.push_back(g);
	}
	return out;
}

// ---------------------------------------------------------------------
// Freigegebene Ordner -- Freigaben werden als eigene Abschnitte in
// smb.conf verwaltet (ausser den technischen Abschnitten [global],
// [homes], [printers], [sysvol], [netlogon], die hier nicht angezeigt
// werden -- genau wie das Original administrative Freigaben wie C$
// standardmaessig ausblendet). Sitzungen/Geoeffnete Dateien kommen
// live von "smbstatus --json".
// ---------------------------------------------------------------------
static const char* HIDDEN_SHARE_NAMES[] = { "global", "homes", "printers", "print$", "sysvol", "netlogon" };
static bool isHiddenShareName(const FXString& name) {
	FXString lower = name; lower.lower();
	for (auto* h : HIDDEN_SHARE_NAMES) if (lower == h) return true;
	return false;
}

static std::vector<ShareInfo> parseShares() {
	std::vector<ShareInfo> out;
	std::ifstream in("/etc/samba/smb.conf");
	std::string line;
	ShareInfo cur;
	bool haveShare = false;
	auto flush = [&]() { if (haveShare && !isHiddenShareName(cur.name)) out.push_back(cur); cur = ShareInfo(); haveShare = false; };
	while (std::getline(in, line)) {
		FXString l = line.c_str();
		l.trim();
		if (l.empty() || l[0] == ';' || l[0] == '#') continue;
		if (l[0] == '[' && l[l.length() - 1] == ']') {
			flush();
			cur.name = l.mid(1, l.length() - 2);
			haveShare = true;
			continue;
		}
		if (!haveShare) continue;
		int eq = l.find('=');
		if (eq < 0) continue;
		FXString key = l.left(eq); key.trim(); key.lower();
		FXString val = l.mid(eq + 1, l.length() - eq - 1); val.trim();
		if (key == "path") cur.path = val;
		else if (key == "comment") cur.comment = val;
		else if (key == "read only") cur.readOnly = (val.lower() == "yes" || val.lower() == "true");
	}
	flush();
	return out;
}

static bool createShare(const FXString& name, const FXString& path, const FXString& comment, bool readOnly, FXString& errorMsg) {
	for (auto& s : parseShares()) if (s.name == name) { errorMsg = "Die Freigabe \"" + name + "\" existiert bereits."; return false; }
	std::string block = "\n[" + std::string(name.text()) + "]\n"
	                     "\tpath = " + path.text() + "\n"
	                     "\tcomment = " + comment.text() + "\n"
	                     "\tread only = " + std::string(readOnly ? "yes" : "no") + "\n"
	                     "\tguest ok = no\n";
	std::string out;
	int rc = runAsRootWithStdin({ FXString("bash"), FXString("-c"), FXString("cat >> /etc/samba/smb.conf") }, block);
	(void)out;
	if (rc != 0) { errorMsg = "Konnte smb.conf nicht schreiben."; return false; }
	runAsRoot({ FXString("smbcontrol"), FXString("all"), FXString("reload-config") });
	return true;
}

// Ersetzt eine bestehende Freigabe komplett (Pfad/Kommentar/Schreib-
// schutz) -- einfacher und robuster als gezieltes In-Place-Bearbeiten
// der smb.conf-Zeilen.
static bool modifyShare(const FXString& name, const FXString& newPath, const FXString& newComment, bool newReadOnly, FXString& errorMsg) {
	std::ifstream in("/etc/samba/smb.conf");
	std::stringstream out;
	std::string line;
	bool inTarget = false, wrote = false;
	while (std::getline(in, line)) {
		FXString l = line.c_str(); FXString trimmed = l; trimmed.trim();
		if (!trimmed.empty() && trimmed[0] == '[' && trimmed[trimmed.length() - 1] == ']') {
			FXString sectionName = trimmed.mid(1, trimmed.length() - 2);
			inTarget = (sectionName == name);
			if (inTarget) {
				out << "[" << name.text() << "]\n";
				out << "\tpath = " << newPath.text() << "\n";
				out << "\tcomment = " << newComment.text() << "\n";
				out << "\tread only = " << (newReadOnly ? "yes" : "no") << "\n";
				out << "\tguest ok = no\n";
				wrote = true;
				continue;
			}
			out << line << "\n";
			continue;
		}
		if (inTarget) continue; // alte Zeilen des Zielabschnitts ueberspringen, wir haben ihn schon neu geschrieben
		out << line << "\n";
	}
	if (!wrote) { errorMsg = "Freigabe \"" + name + "\" nicht in smb.conf gefunden."; return false; }
	int rc = runAsRootWithStdin({ FXString("bash"), FXString("-c"), FXString("cat > /etc/samba/smb.conf") }, out.str());
	if (rc != 0) { errorMsg = "Konnte smb.conf nicht schreiben."; return false; }
	runAsRoot({ FXString("smbcontrol"), FXString("all"), FXString("reload-config") });
	return true;
}

static bool deleteShare(const FXString& name, FXString& errorMsg) {
	std::ifstream in("/etc/samba/smb.conf");
	std::stringstream out;
	std::string line;
	bool inTarget = false, found = false;
	while (std::getline(in, line)) {
		FXString l = line.c_str(); FXString trimmed = l; trimmed.trim();
		if (!trimmed.empty() && trimmed[0] == '[' && trimmed[trimmed.length() - 1] == ']') {
			FXString sectionName = trimmed.mid(1, trimmed.length() - 2);
			inTarget = (sectionName == name);
			if (inTarget) { found = true; continue; }
			out << line << "\n";
			continue;
		}
		if (inTarget) continue;
		out << line << "\n";
	}
	if (!found) { errorMsg = "Freigabe \"" + name + "\" nicht in smb.conf gefunden."; return false; }
	int rc = runAsRootWithStdin({ FXString("bash"), FXString("-c"), FXString("cat > /etc/samba/smb.conf") }, out.str());
	if (rc != 0) { errorMsg = "Konnte smb.conf nicht schreiben."; return false; }
	runAsRoot({ FXString("smbcontrol"), FXString("all"), FXString("reload-config") });
	return true;
}

// Sitzungen und geoeffnete Dateien kommen live von "smbstatus --json"
// -- ueber ein kleines Python-Skript in TSV umgewandelt, das ist
// deutlich robuster als eigenes JSON-Parsing in C++ fuer eine reine
// Anzeige-Funktion.
static std::vector<SessionInfo> parseSessions() {
	std::vector<SessionInfo> out;
	std::string script =
		"import json,sys\n"
		"d = json.load(sys.stdin)\n"
		"tcons = d.get('tcons', {})\n"
		"for sid, s in d.get('sessions', {}).items():\n"
		"    shares = [t.get('service','') for t in tcons.values() if t.get('session_id') == sid]\n"
		"    print(s.get('username','') + '\\t' + s.get('remote_machine','') + '\\t' + ','.join(shares) + '\\t' + s.get('session_dialect',''))\n";
	std::string out1;
	runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString("smbstatus --json 2>/dev/null | python3 -c \"") + script.c_str() + "\"" }, out1);
	for (auto& line : splitStr(out1, (char)10)) {
		if (line.empty()) continue;
		auto f = splitStr(line, '\t');
		if (f.size() < 4) continue;
		SessionInfo s;
		s.username = f[0].c_str(); s.remoteMachine = f[1].c_str(); s.shares = f[2].c_str(); s.dialect = f[3].c_str();
		out.push_back(s);
	}
	return out;
}

static std::vector<OpenFileInfo> parseOpenFiles() {
	std::vector<OpenFileInfo> out;
	std::string script =
		"import json,sys\n"
		"d = json.load(sys.stdin)\n"
		"tcons = d.get('tcons', {})\n"
		"sessions = d.get('sessions', {})\n"
		"for fid, f in d.get('open_files', {}).items():\n"
		"    sid = f.get('session_id','')\n"
		"    user = sessions.get(sid, {}).get('username','')\n"
		"    tid = f.get('tcon_id','')\n"
		"    share = tcons.get(tid, {}).get('service','')\n"
		"    print(f.get('filename','') + '\\t' + user + '\\t' + share)\n";
	std::string out1;
	runAsRootCaptured({ FXString("bash"), FXString("-c"), FXString("smbstatus --json 2>/dev/null | python3 -c \"") + script.c_str() + "\"" }, out1);
	for (auto& line : splitStr(out1, (char)10)) {
		if (line.empty()) continue;
		auto f = splitStr(line, '\t');
		if (f.size() < 3) continue;
		OpenFileInfo o;
		o.path = f[0].c_str(); o.username = f[1].c_str(); o.share = f[2].c_str();
		out.push_back(o);
	}
	return out;
}

// ---------------------------------------------------------------------
// Dialog "Neuer Benutzer" -- wie im Original: "Erstellen" legt den
// Benutzer sofort an und der Dialog bleibt fuer weitere Benutzer offen,
// "Schließen" beendet.
// ---------------------------------------------------------------------
class CompMgmt; // vorwaertsdeklariert

class NewUserDialog : public FXDialogBox {
	FXDECLARE(NewUserDialog)
private:
	FXTextField *userField, *fullNameField, *descField, *pwField, *pwConfirmField;
	FXCheckButton *disabledCheck;
	CompMgmt* mgr;
protected:
	NewUserDialog() {}
public:
	enum { ID_CREATE = FXDialogBox::ID_LAST };
	long onCreate(FXObject*, FXSelector, void*);

	NewUserDialog(FXWindow* owner, CompMgmt* m)
		: FXDialogBox(owner, "Neuer Benutzer", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0, 0,0,0,0),
		  mgr(m) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		new FXLabel(main, "Benutzername:");
		userField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Vollständiger Name:");
		fullNameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Beschreibung:");
		descField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Kennwort:");
		pwField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);

		new FXLabel(main, "Kennwort bestätigen:");
		pwConfirmField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);

		disabledCheck = new FXCheckButton(main, "Konto ist deaktiviert");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Erstellen", NULL, this, ID_CREATE,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Schließen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	void resetFields() {
		userField->setText(""); fullNameField->setText(""); descField->setText("");
		pwField->setText(""); pwConfirmField->setText(""); disabledCheck->setCheck(FALSE);
		userField->setFocus();
	}
	virtual ~NewUserDialog() {}
};
FXDEFMAP(NewUserDialog) NewUserDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewUserDialog::ID_CREATE, NewUserDialog::onCreate),
};
FXIMPLEMENT(NewUserDialog, FXDialogBox, NewUserDialogMap, ARRAYNUMBER(NewUserDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" eines Benutzers -- Benutzername ist read-only
// (Umbenennen eines Unix-Kontos ist heikel wegen Home-Verzeichnis/
// Dateibesitz und wird hier bewusst nicht unterstuetzt), Vollstaendiger
// Name/Beschreibung/Deaktiviert sind editierbar.
// ---------------------------------------------------------------------
class UserPropertiesDialog : public FXDialogBox {
	FXDECLARE(UserPropertiesDialog)
private:
	FXTextField *fullNameField, *descField;
	FXCheckButton *disabledCheck;
protected:
	UserPropertiesDialog() {}
public:
	UserPropertiesDialog(FXWindow* owner, const UserInfo& u)
		: FXDialogBox(owner, "Eigenschaften von " + u.username, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,380,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		new FXLabel(main, "Benutzername:");
		FXTextField* userField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		userField->setText(u.username); userField->disable();

		new FXLabel(main, "Vollständiger Name:");
		fullNameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		fullNameField->setText(u.fullName);

		new FXLabel(main, "Beschreibung:");
		descField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		descField->setText(u.description);

		disabledCheck = new FXCheckButton(main, "Konto ist deaktiviert");
		disabledCheck->setCheck(u.locked);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getFullName() const { return fullNameField->getText(); }
	FXString getDescription() const { return descField->getText(); }
	FXbool getDisabled() const { return disabledCheck->getCheck(); }
	virtual ~UserPropertiesDialog() {}
};
FXIMPLEMENT(UserPropertiesDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Kennwort festlegen" -- eigener Menuepunkt im Original, nicht
// Teil der Eigenschaften.
// ---------------------------------------------------------------------
class SetPasswordDialog : public FXDialogBox {
	FXDECLARE(SetPasswordDialog)
private:
	FXTextField *pwField, *pwConfirmField;
protected:
	SetPasswordDialog() {}
public:
	SetPasswordDialog(FXWindow* owner, const FXString& username)
		: FXDialogBox(owner, "Kennwort festlegen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,360,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Neues Kennwort für: " + username);

		new FXLabel(main, "Neues Kennwort:");
		pwField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);

		new FXLabel(main, "Kennwort bestätigen:");
		pwConfirmField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_PASSWD);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getPassword() const { return pwField->getText(); }
	FXString getConfirm() const { return pwConfirmField->getText(); }
	virtual ~SetPasswordDialog() {}
};
FXIMPLEMENT(SetPasswordDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Neue Gruppe" -- Gruppenname anlegen; Mitglieder werden danach
// ueber die Eigenschaften der Gruppe verwaltet (wie im Original, wo man
// im New-Group-Dialog zwar auch schon Mitglieder hinzufuegen kann, wir
// das aber der Einfachheit halber in einem Schritt trennen).
// ---------------------------------------------------------------------
class NewGroupDialog : public FXDialogBox {
	FXDECLARE(NewGroupDialog)
private:
	FXTextField *nameField;
	CompMgmt* mgr;
protected:
	NewGroupDialog() {}
public:
	enum { ID_CREATE = FXDialogBox::ID_LAST };
	long onCreate(FXObject*, FXSelector, void*);

	NewGroupDialog(FXWindow* owner, CompMgmt* m)
		: FXDialogBox(owner, "Neue Gruppe", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,360,0, 0,0,0,0),
		  mgr(m) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Gruppenname:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Erstellen", NULL, this, ID_CREATE,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Schließen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	void resetFields() { nameField->setText(""); nameField->setFocus(); }
	virtual ~NewGroupDialog() {}
};
FXDEFMAP(NewGroupDialog) NewGroupDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewGroupDialog::ID_CREATE, NewGroupDialog::onCreate),
};
FXIMPLEMENT(NewGroupDialog, FXDialogBox, NewGroupDialogMap, ARRAYNUMBER(NewGroupDialogMap))

// ---------------------------------------------------------------------
// Dialog "Neue Freigabe" -- Ordner auswaehlen, Freigabename,
// Beschreibung, Schreibschutz. Wie bei "Neuer Benutzer" bleibt der
// Dialog nach dem Erstellen offen, damit gleich mehrere Freigaben
// angelegt werden koennen.
// ---------------------------------------------------------------------
class NewShareDialog : public FXDialogBox {
	FXDECLARE(NewShareDialog)
private:
	FXTextField *pathField, *nameField, *commentField;
	FXCheckButton *readOnlyCheck;
	CompMgmt* mgr;
protected:
	NewShareDialog() {}
public:
	enum { ID_BROWSE = FXDialogBox::ID_LAST, ID_CREATE };
	long onBrowse(FXObject*, FXSelector, void*) {
		FXString picked = FXDirDialog::getOpenDirectory(this, "Ordner auswählen", FXSystem::getHomeDirectory());
		if (!picked.empty()) {
			pathField->setText(picked);
			if (nameField->getText().empty()) {
				FXString base = picked;
				int slash = base.rfind('/');
				if (slash >= 0) base = base.mid(slash + 1, base.length() - slash - 1);
				nameField->setText(base);
			}
		}
		return 1;
	}
	long onCreate(FXObject*, FXSelector, void*);

	NewShareDialog(FXWindow* owner, CompMgmt* m)
		: FXDialogBox(owner, "Neue Freigabe", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0, 0,0,0,0),
		  mgr(m) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Ordnerpfad:");
		FXHorizontalFrame* pf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		pathField = new FXTextField(pf, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXButton(pf, "&Durchsuchen...", NULL, this, ID_BROWSE, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXLabel(main, "Freigabename:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXLabel(main, "Beschreibung:");
		commentField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		readOnlyCheck = new FXCheckButton(main, "Schreibgeschützt");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Erstellen", NULL, this, ID_CREATE,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Schließen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	void resetFields() { pathField->setText(""); nameField->setText(""); commentField->setText(""); readOnlyCheck->setCheck(false); pathField->setFocus(); }
	virtual ~NewShareDialog() {}
};
FXDEFMAP(NewShareDialog) NewShareDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewShareDialog::ID_BROWSE, NewShareDialog::onBrowse),
	FXMAPFUNC(SEL_COMMAND, NewShareDialog::ID_CREATE, NewShareDialog::onCreate),
};
FXIMPLEMENT(NewShareDialog, FXDialogBox, NewShareDialogMap, ARRAYNUMBER(NewShareDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer Freigabe -- Ordnerpfad/Beschreibung/
// Schreibschutz bearbeiten (Freigabename selbst bleibt fest, wie im
// Original -- dafuer muesste man die Freigabe aufheben und neu anlegen).
// ---------------------------------------------------------------------
class SharePropertiesDialog : public FXDialogBox {
	FXDECLARE(SharePropertiesDialog)
private:
	FXTextField *pathField, *commentField;
	FXCheckButton *readOnlyCheck;
	FXString shareName;
protected:
	SharePropertiesDialog() {}
public:
	SharePropertiesDialog(FXWindow* owner, const ShareInfo& s)
		: FXDialogBox(owner, "Eigenschaften von " + s.name, DECOR_TITLE | DECOR_BORDER, 0,0,420,0),
		  shareName(s.name) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Freigabename: " + s.name);
		new FXLabel(main, "Ordnerpfad:");
		pathField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		pathField->setText(s.path);
		new FXLabel(main, "Beschreibung:");
		commentField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		commentField->setText(s.comment);
		readOnlyCheck = new FXCheckButton(main, "Schreibgeschützt");
		readOnlyCheck->setCheck(s.readOnly);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getPath() const { return pathField->getText(); }
	FXString getComment() const { return commentField->getText(); }
	bool getReadOnly() const { return readOnlyCheck->getCheck(); }
	virtual ~SharePropertiesDialog() {}
};
FXIMPLEMENT(SharePropertiesDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer Gruppe -- Mitgliederliste mit
// Hinzufuegen/Entfernen, wie im Original.
// ---------------------------------------------------------------------
class GroupPropertiesDialog : public FXDialogBox {
	FXDECLARE(GroupPropertiesDialog)
private:
	FXList* memberList;
	FXTextField* addField;
public:
	enum { ID_ADDMEMBER = FXDialogBox::ID_LAST, ID_REMOVEMEMBER };
	long onAddMember(FXObject*, FXSelector, void*) {
		FXString name = addField->getText().trim();
		if (name.empty()) return 1;
		for (int i = 0; i < memberList->getNumItems(); ++i) {
			if (memberList->getItemText(i) == name) return 1; // schon drin
		}
		memberList->appendItem(name);
		addField->setText("");
		addField->setFocus();
		return 1;
	}
	long onRemoveMember(FXObject*, FXSelector, void*) {
		int sel = memberList->getCurrentItem();
		if (sel >= 0) memberList->removeItem(sel);
		return 1;
	}
protected:
	GroupPropertiesDialog() {}
public:
	GroupPropertiesDialog(FXWindow* owner, const GroupInfo& g)
		: FXDialogBox(owner, "Eigenschaften von " + g.groupname, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,360,380, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Gruppenname: " + g.groupname);
		new FXLabel(main, "Mitglieder:");

		memberList = new FXList(main, NULL, 0, LISTBOX_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		for (auto& m : g.members) memberList->appendItem(m);

		FXHorizontalFrame* addf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		addField = new FXTextField(addf, 20, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		new FXButton(addf, "&Hinzufügen", NULL, this, ID_ADDMEMBER, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);
		new FXButton(addf, "&Entfernen", NULL, this, ID_REMOVEMEMBER, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	std::vector<FXString> getMembers() const {
		std::vector<FXString> out;
		for (int i = 0; i < memberList->getNumItems(); ++i) out.push_back(memberList->getItemText(i));
		return out;
	}
	virtual ~GroupPropertiesDialog() {}
};
FXDEFMAP(GroupPropertiesDialog) GroupPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, GroupPropertiesDialog::ID_ADDMEMBER, GroupPropertiesDialog::onAddMember),
	FXMAPFUNC(SEL_COMMAND, GroupPropertiesDialog::ID_REMOVEMEMBER, GroupPropertiesDialog::onRemoveMember),
};
FXIMPLEMENT(GroupPropertiesDialog, FXDialogBox, GroupPropertiesDialogMap, ARRAYNUMBER(GroupPropertiesDialogMap))

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------

enum NodeKind { NK_NONE, NK_USERS, NK_GROUPS, NK_SHARES, NK_SESSIONS, NK_OPENFILES, NK_SERVICES };

class CompMgmt : public FXMainWindow {
	FXDECLARE(CompMgmt)
private:
	FXDockSite* topdock;
	FXHorizontalFrame* statusbarcont;
	FXLabel* statuslbl;

	FXToolBarShell* mbshell;
	FXMenuBar* menubar;
	FXMenuPane *konsolemenu, *vorgangmenu, *ansichtmenu, *fenstermenu, *hilfemenu;

	FXToolBarShell* tbshell;
	FXToolBar* toolbar;

	FXSplitter* splitter;
	FXTreeList* tree;
	FXIconList* list;

	FXTreeItem *rootItem, *sysToolsItem, *lugItem, *usersItem, *groupsItem;
	FXTreeItem *sharedFoldersItem, *sharesItem, *sessionsItem, *openFilesItem;
	FXTreeItem *svcAppsItem, *servicesItem;
	FXSwitcher* rightPane;   // 0 = normale Liste, 1 = Dienste-Ansicht
	SvcPanel* svcPanel;
	std::vector<UserInfo> users;
	std::vector<GroupInfo> groups;
	std::vector<ShareInfo> shares;
	std::vector<SessionInfo> sessions;
	std::vector<OpenFileInfo> openFiles;

	FXIcon *icoRoot, *icoFolder, *icoUser, *icoUsers, *icoKey;
	FXIcon *icoBack, *icoForward, *icoUp, *icoContree, *icoProperties, *icoRefresh, *icoHelp, *icoDelete;

	NodeKind currentNodeKind;
	FXString contextUserName, contextGroupName, contextShareName;
	bool isDC;
	FXLabel* dcNoticeLabel;

protected:
	CompMgmt() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_REFRESH, ID_ABOUT,
	       ID_NEWUSER, ID_NEWGROUP, ID_USERPROPS, ID_SETPASSWORD, ID_DELETEUSER,
	       ID_GROUPPROPS, ID_DELETEGROUP, ID_NEWSHARE, ID_SHAREPROPS, ID_DELETESHARE };

	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	long onNewUser(FXObject*, FXSelector, void*);
	long onNewGroup(FXObject*, FXSelector, void*);
	long onUserProperties(FXObject*, FXSelector, void*);
	long onSetPassword(FXObject*, FXSelector, void*);
	long onDeleteUser(FXObject*, FXSelector, void*);
	long onGroupProperties(FXObject*, FXSelector, void*);
	long onDeleteGroup(FXObject*, FXSelector, void*);
	long onNewShare(FXObject*, FXSelector, void*);
	long onShareProperties(FXObject*, FXSelector, void*);
	long onDeleteShare(FXObject*, FXSelector, void*);

	CompMgmt(FXApp* a);
	void loadAll();
	void showListFor(NodeKind kind);
	bool createUser(const FXString& username, const FXString& fullName, const FXString& desc,
	                const FXString& password, bool disabled, FXString& errorMsg);
	bool createGroup(const FXString& groupname, FXString& errorMsg);
	virtual void create();
	virtual ~CompMgmt() {}
};

FXDEFMAP(CompMgmt) CompMgmtMap[] = {
	FXMAPFUNC(SEL_CHANGED, CompMgmt::ID_TREE, CompMgmt::onTreeChanged),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, CompMgmt::ID_TREE, CompMgmt::onTreeRightClick),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, CompMgmt::ID_LIST, CompMgmt::onListRightClick),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_REFRESH, CompMgmt::onRefresh),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_ABOUT, CompMgmt::onAbout),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_NEWUSER, CompMgmt::onNewUser),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_NEWGROUP, CompMgmt::onNewGroup),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_USERPROPS, CompMgmt::onUserProperties),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_SETPASSWORD, CompMgmt::onSetPassword),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_DELETEUSER, CompMgmt::onDeleteUser),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_GROUPPROPS, CompMgmt::onGroupProperties),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_DELETEGROUP, CompMgmt::onDeleteGroup),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_NEWSHARE, CompMgmt::onNewShare),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_SHAREPROPS, CompMgmt::onShareProperties),
	FXMAPFUNC(SEL_COMMAND, CompMgmt::ID_DELETESHARE, CompMgmt::onDeleteShare),
};
FXIMPLEMENT(CompMgmt, FXMainWindow, CompMgmtMap, ARRAYNUMBER(CompMgmtMap))

static void setListColumns(FXIconList* list, std::vector<std::pair<FXString,int>> cols) {
	while (list->getNumHeaders() > 0) list->removeHeader(0);
	for (auto& c : cols) list->appendHeader(c.first, NULL, c.second);
}

CompMgmt::CompMgmt(FXApp* a)
	: FXMainWindow(a, "Computerverwaltung", NULL, NULL, DECOR_ALL, 0, 0, 820, 480, 0,0,0,0,0,0),
	  currentNodeKind(NK_NONE) {

	isDC = isDomainController();

	topdock = new FXDockSite(this, FRAME_SUNKEN | DOCKSITE_NO_WRAP | LAYOUT_SIDE_TOP | LAYOUT_FILL_X);

	statusbarcont = new FXHorizontalFrame(this, JUSTIFY_LEFT | LAYOUT_FILL_X | LAYOUT_SIDE_BOTTOM,
	                                       0,0,0,0, 0,1,2,0,2,2);
	statuslbl = new FXLabel(statusbarcont, " ", NULL,
	                         LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 1,1,1,1);

	mbshell = new FXToolBarShell(this, FRAME_SUNKEN);
	menubar = new FXMenuBar(topdock, mbshell,
	                         LAYOUT_DOCK_SAME | LAYOUT_SIDE_TOP | LAYOUT_FILL_Y | FRAME_RAISED,
	                         0,0,0,0, 2,6,2,2, 4,4);
	new FXToolBarGrip(menubar, menubar, FXMenuBar::ID_TOOLBARGRIP, TOOLBARGRIP_SINGLE, 0,0,0,0, 0,2,0,0);

	konsolemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Konsole", NULL, konsolemenu);
	new FXMenuCommand(konsolemenu, "&Beenden", NULL, getApp(), FXApp::ID_QUIT);

	vorgangmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Aktualisieren", NULL, this, ID_REFRESH);

	ansichtmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Ansicht", NULL, ansichtmenu);
	FXMenuCommand* mv = new FXMenuCommand(ansichtmenu, "&Details"); mv->disable();

	fenstermenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Fenster", NULL, fenstermenu);
	FXMenuCommand* mf = new FXMenuCommand(fenstermenu, "&Neues Fenster"); mf->disable();

	hilfemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&?", NULL, hilfemenu);
	new FXMenuCommand(hilfemenu, "&Info...", NULL, this, ID_ABOUT);

	tbshell = new FXToolBarShell(this, FRAME_SUNKEN);
	toolbar = new FXToolBar(topdock, tbshell,
	                         LAYOUT_FILL_Y | LAYOUT_DOCK_SAME | LAYOUT_SIDE_TOP | FRAME_RAISED,
	                         0,0,0,0, 0,5,0,0, 1,1);
	new FXToolBarGrip(toolbar, toolbar, FXToolBar::ID_TOOLBARGRIP, TOOLBARGRIP_SINGLE, 0,0,0,0, 2,3,2,2);

	icoBack = new FXGIFIcon(getApp(), resico_mmc_back);
	icoForward = new FXGIFIcon(getApp(), resico_mmc_forward);
	icoUp = new FXGIFIcon(getApp(), resico_mmc_up);
	icoContree = new FXGIFIcon(getApp(), resico_mmc_contree);
	icoProperties = new FXGIFIcon(getApp(), resico_mmc_properties);
	icoRefresh = new FXGIFIcon(getApp(), resico_mmc_refresh);
	icoHelp = new FXGIFIcon(getApp(), resico_mmc_help);
	icoDelete = new FXGIFIcon(getApp(), resico_mmc_delete);

	FXButton* btn;
	btn = new FXButton(toolbar, "\tZurück", icoBack, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	btn = new FXButton(toolbar, "\tVor", icoForward, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	btn = new FXButton(toolbar, "\tEbene nach oben", icoUp, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	btn = new FXButton(toolbar, "\tStruktur/Favoriten anzeigen/ausblenden", icoContree, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	btn = new FXButton(toolbar, "\tLöschen", icoDelete, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	btn = new FXButton(toolbar, "\tEigenschaften", icoProperties, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	btn = new FXButton(toolbar, "\tAktualisieren", icoRefresh, this, ID_REFRESH, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	btn = new FXButton(toolbar, "\tHilfe", icoHelp, this, ID_ABOUT, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);

	new FXSeparator(this, SEPARATOR_NONE|LAYOUT_FIX_HEIGHT, 0,0,0,2);

	dcNoticeLabel = new FXLabel(this,
		"Dieser Server ist ein Domänencontroller. Netzwerk-Anmeldekonten werden über \"Active Directory-Benutzer und -Computer\" verwaltet. Lokale Linux-Benutzerkonten (z.B. für SSH-Zugang) lassen sich hier weiterhin vollständig anlegen/bearbeiten/löschen -- nur die Samba-Netzwerkfreigabe-Anbindung ist deaktiviert.",
		NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 6,6,4,4);
	dcNoticeLabel->setBackColor(FXRGB(255, 250, 205));
	if (!isDC) dcNoticeLabel->hide();

	splitter = new FXSplitter(this, LAYOUT_FILL_X|LAYOUT_FILL_Y|SPLITTER_TRACKING);

	FXPacker* treeframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y, 0,0,270,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                       SCROLLERS_DONT_TRACK|FRAME_NORMAL|LAYOUT_FILL_X|LAYOUT_FILL_Y|
	                       TREELIST_SHOWS_BOXES|TREELIST_SHOWS_LINES|TREELIST_BROWSESELECT|TREELIST_ROOT_BOXES);

	FXPacker* listframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y|LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	// Die rechte Haelfte zeigt entweder die gewohnte Liste oder -- im
	// Zweig "Dienste und Anwendungen" -- dasselbe SvcPanel, das auch das
	// eigenstaendige "Dienste"-Programm verwendet.
	rightPane = new FXSwitcher(listframe, LAYOUT_FILL_X|LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(rightPane, this, ID_LIST,
	                       ICONLIST_DETAILED|ICONLIST_BROWSESELECT|LAYOUT_FILL_X|LAYOUT_FILL_Y|FRAME_NORMAL);

	icoRoot = new FXPNGIcon(getApp(), resico_network, IMAGE_NEAREST); icoRoot->create();
	icoFolder = new FXPNGIcon(getApp(), resico_folder, IMAGE_NEAREST); icoFolder->create();
	icoUser = new FXPNGIcon(getApp(), resico_user, IMAGE_NEAREST); icoUser->create();
	icoUsers = new FXPNGIcon(getApp(), resico_users, IMAGE_NEAREST); icoUsers->create();
	icoKey = new FXPNGIcon(getApp(), resico_key, IMAGE_NEAREST); icoKey->create();

	rootItem = tree->appendItem(0, "Computerverwaltung (Lokal)", icoRoot, icoRoot);
	sysToolsItem = tree->appendItem(rootItem, "Systemprogramme", icoFolder, icoFolder);
	lugItem = tree->appendItem(sysToolsItem, "Lokale Benutzer und Gruppen", icoUsers, icoUsers);
	usersItem = tree->appendItem(lugItem, "Benutzer", icoFolder, icoFolder);
	groupsItem = tree->appendItem(lugItem, "Gruppen", icoFolder, icoFolder);
	sharedFoldersItem = tree->appendItem(sysToolsItem, "Freigegebene Ordner", icoFolder, icoFolder);
	sharesItem = tree->appendItem(sharedFoldersItem, "Freigaben", icoFolder, icoFolder);
	sessionsItem = tree->appendItem(sharedFoldersItem, "Sitzungen", icoFolder, icoFolder);
	openFilesItem = tree->appendItem(sharedFoldersItem, "Geöffnete Dateien", icoFolder, icoFolder);
	svcAppsItem = tree->appendItem(rootItem, "Dienste und Anwendungen", icoFolder, icoFolder);
	servicesItem = tree->appendItem(svcAppsItem, "Dienste", icoKey, icoKey);
	svcPanel = new SvcPanel(rightPane, icoKey);
	tree->expandTree(rootItem);
	tree->expandTree(sysToolsItem);
	tree->expandTree(lugItem);
	tree->expandTree(sharedFoldersItem);
	tree->expandTree(svcAppsItem);

	loadAll();
}

void CompMgmt::loadAll() {
	users = parseUsers();
	groups = parseGroups();
	shares = parseShares();
}

void CompMgmt::showListFor(NodeKind kind) {
	currentNodeKind = kind;
	if (kind == NK_SERVICES) {
		// Eigene Ansicht -- die gemeinsame Liste bleibt unberuehrt.
		rightPane->setCurrent(1);
		svcPanel->reload();
		return;
	}
	rightPane->setCurrent(0);
	list->clearItems();
	if (kind == NK_USERS) {
		setListColumns(list, { {"Name", 140}, {"Vollständiger Name", 180}, {"Beschreibung", 220} });
		for (auto& u : users) {
			FXString name = u.locked ? (u.username + " (deaktiviert)") : u.username;
			FXString txt = name + "\t" + u.fullName + "\t" + u.description;
			list->appendItem(txt, icoUser, icoUser);
		}
	} else if (kind == NK_GROUPS) {
		setListColumns(list, { {"Name", 180}, {"Beschreibung", 260} });
		for (auto& g : groups) {
			FXString txt = g.groupname + "\t";
			list->appendItem(txt, icoUsers, icoUsers);
		}
	} else if (kind == NK_SHARES) {
		shares = parseShares();
		setListColumns(list, { {"Freigabename", 140}, {"Ordnerpfad", 220}, {"Beschreibung", 200} });
		for (auto& s : shares) {
			FXString txt = s.name + "\t" + s.path + "\t" + s.comment;
			list->appendItem(txt, icoFolder, icoFolder);
		}
	} else if (kind == NK_SESSIONS) {
		sessions = parseSessions();
		setListColumns(list, { {"Benutzer", 140}, {"Computer", 160}, {"Freigaben", 160}, {"Protokoll", 100} });
		for (auto& s : sessions) {
			FXString txt = s.username + "\t" + s.remoteMachine + "\t" + s.shares + "\t" + s.dialect;
			list->appendItem(txt, icoUser, icoUser);
		}
	} else if (kind == NK_OPENFILES) {
		openFiles = parseOpenFiles();
		setListColumns(list, { {"Geöffnete Datei", 240}, {"Benutzer", 140}, {"Freigabe", 140} });
		for (auto& o : openFiles) {
			FXString txt = o.path + "\t" + o.username + "\t" + o.share;
			list->appendItem(txt, icoFolder, icoFolder);
		}
	} else {
		setListColumns(list, {});
	}
}

long CompMgmt::onTreeChanged(FXObject*, FXSelector, void*) {
	FXTreeItem* cur = tree->getCurrentItem();
	if (!cur) return 1;
	if (cur == usersItem) { showListFor(NK_USERS); return 1; }
	if (cur == groupsItem) { showListFor(NK_GROUPS); return 1; }
	if (cur == sharesItem) { showListFor(NK_SHARES); return 1; }
	if (cur == sessionsItem) { showListFor(NK_SESSIONS); return 1; }
	if (cur == openFilesItem) { showListFor(NK_OPENFILES); return 1; }
	if (cur == servicesItem) { showListFor(NK_SERVICES); return 1; }
	rightPane->setCurrent(0);
	list->clearItems();
	setListColumns(list, {});
	currentNodeKind = NK_NONE;
	return 1;
}

long CompMgmt::onTreeRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);

	FXMenuPane menu(this);
	if (item == usersItem) {
		new FXMenuCommand(&menu, "&Neuer Benutzer...", NULL, this, ID_NEWUSER);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	} else if (item == groupsItem) {
		new FXMenuCommand(&menu, "&Neue Gruppe...", NULL, this, ID_NEWGROUP);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	} else if (item == sharesItem) {
		new FXMenuCommand(&menu, "&Neue Freigabe...", NULL, this, ID_NEWSHARE);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	} else if (item == sessionsItem || item == openFilesItem) {
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	} else {
		return 1;
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long CompMgmt::onListRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	if (currentNodeKind == NK_NONE) return 1;

	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx < 0) return 1;
	list->setCurrentItem(idx);
	list->selectItem(idx);

	FXMenuPane menu(this);
	if (currentNodeKind == NK_USERS) {
		if (idx >= (int)users.size()) return 1;
		contextUserName = users[idx].username;
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_USERPROPS);
		new FXMenuCommand(&menu, "&Kennwort festlegen...", NULL, this, ID_SETPASSWORD);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETEUSER);
	} else if (currentNodeKind == NK_GROUPS) {
		if (idx >= (int)groups.size()) return 1;
		contextGroupName = groups[idx].groupname;
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_GROUPPROPS);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETEGROUP);
	} else if (currentNodeKind == NK_SHARES) {
		if (idx >= (int)shares.size()) return 1;
		contextShareName = shares[idx].name;
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_SHAREPROPS);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "Freigabe &aufheben", NULL, this, ID_DELETESHARE);
	} else {
		return 1;
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long CompMgmt::onRefresh(FXObject*, FXSelector, void*) {
	loadAll();
	showListFor(currentNodeKind);
	statuslbl->setText("Aktualisiert.");
	return 1;
}

long CompMgmt::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Über Computerverwaltung",
		"Computerverwaltung für ice2k\n\n"
		"Ein Nachbau des Windows 2000 Computerverwaltung-Snapins\n"
		"(Lokale Benutzer und Gruppen).\n"
		"Verwaltet echte Linux-Benutzer/-Gruppen und hält Samba\n"
		"(smbpasswd/pdbedit) synchron.");
	return 1;
}

long CompMgmt::onNewUser(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Benutzer angelegt werden.");
		return 1;
	}
	NewUserDialog dlg(this, this);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long CompMgmt::onNewGroup(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann keine Gruppe angelegt werden.");
		return 1;
	}
	NewGroupDialog dlg(this, this);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long CompMgmt::onUserProperties(FXObject*, FXSelector, void*) {
	UserInfo* found = NULL;
	for (auto& u : users) if (u.username == contextUserName) { found = &u; break; }
	if (!found) return 1;
	UserInfo u = *found;

	UserPropertiesDialog dlg(this, u);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können keine Änderungen gespeichert werden.");
		return 1;
	}

	FXString gecos = dlg.getFullName() + ",,," + dlg.getDescription();
	runAsRoot({ FXString("usermod"), FXString("-c"), gecos, u.username });

	bool wantDisabled = dlg.getDisabled();
	if (wantDisabled != u.locked) {
		if (wantDisabled) {
			runAsRoot({ FXString("usermod"), FXString("-L"), u.username });
			if (!isDC) runAsRoot({ FXString("smbpasswd"), FXString("-d"), u.username });
		} else {
			runAsRoot({ FXString("usermod"), FXString("-U"), u.username });
			if (!isDC) runAsRoot({ FXString("smbpasswd"), FXString("-e"), u.username });
		}
	}

	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Eigenschaften von " + u.username + " aktualisiert.");
	return 1;
}

long CompMgmt::onSetPassword(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Kennwort gesetzt werden.");
		return 1;
	}
	SetPasswordDialog dlg(this, contextUserName);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	FXString pw = dlg.getPassword();
	FXString confirm = dlg.getConfirm();
	if (pw.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Kennwort fehlt", "Bitte ein Kennwort eingeben.");
		return 1;
	}
	if (pw != confirm) {
		FXMessageBox::error(this, MBOX_OK, "Kennwörter stimmen nicht überein", "Die beiden eingegebenen Kennwörter sind unterschiedlich.");
		return 1;
	}

	std::string chpasswdInput = std::string(contextUserName.text()) + ":" + pw.text() + "\n";
	runAsRootWithStdin({ FXString("chpasswd") }, chpasswdInput);

	if (!isDC) {
		std::string smbInput = std::string(pw.text()) + "\n" + pw.text() + "\n";
		runAsRootWithStdin({ FXString("smbpasswd"), FXString("-s"), FXString("-a"), contextUserName }, smbInput);
	}

	// chpasswd/"smbpasswd -a" setzen den Passwort-Hash komplett neu und
	// heben dabei nebenbei eine vorherige Sperre auf ("!"-Praefix bzw.
	// Samba-D-Flag verschwinden). Das widerspricht dem Original, wo
	// Kennwort und Aktiviert/Deaktiviert-Status unabhaengig voneinander
	// sind -- also den Sperrzustand von vorher explizit wiederherstellen.
	for (auto& u : users) {
		if (u.username == contextUserName && u.locked) {
			runAsRoot({ FXString("usermod"), FXString("-L"), contextUserName });
			if (!isDC) runAsRoot({ FXString("smbpasswd"), FXString("-d"), contextUserName });
			break;
		}
	}

	statuslbl->setText("Kennwort für " + contextUserName + " geändert.");
	return 1;
}

long CompMgmt::onDeleteUser(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts gelöscht werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen",
	        "Benutzer \"%s\" wirklich löschen? Das Home-Verzeichnis wird mit entfernt.", contextUserName.text())
	        != MBOX_CLICKED_YES) {
		return 1;
	}
	if (!isDC) runAsRoot({ FXString("smbpasswd"), FXString("-x"), contextUserName });
	int rc = runAsRoot({ FXString("userdel"), FXString("-r"), contextUserName });
	if (rc == 0) {
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Benutzer " + contextUserName + " gelöscht.");
	} else {
		statuslbl->setText("Fehler beim Löschen des Benutzers " + contextUserName + ".");
	}
	return 1;
}

long CompMgmt::onGroupProperties(FXObject*, FXSelector, void*) {
	GroupInfo* found = NULL;
	for (auto& g : groups) if (g.groupname == contextGroupName) { found = &g; break; }
	if (!found) return 1;
	GroupInfo g = *found;

	GroupPropertiesDialog dlg(this, g);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können keine Änderungen gespeichert werden.");
		return 1;
	}

	std::vector<FXString> newMembers = dlg.getMembers();
	FXString memberList;
	for (size_t i = 0; i < newMembers.size(); ++i) {
		if (i > 0) memberList += ",";
		memberList += newMembers[i];
	}
	runAsRoot({ FXString("gpasswd"), FXString("-M"), memberList, g.groupname });

	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Mitglieder von " + g.groupname + " aktualisiert.");
	return 1;
}

long CompMgmt::onDeleteGroup(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts gelöscht werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen",
	        "Gruppe \"%s\" wirklich löschen?", contextGroupName.text()) != MBOX_CLICKED_YES) {
		return 1;
	}
	int rc = runAsRoot({ FXString("groupdel"), contextGroupName });
	if (rc == 0) {
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Gruppe " + contextGroupName + " gelöscht.");
	} else {
		statuslbl->setText("Fehler beim Löschen der Gruppe " + contextGroupName + " (ist sie evtl. primäre Gruppe eines Benutzers?).");
	}
	return 1;
}

long CompMgmt::onNewShare(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann keine Freigabe angelegt werden.");
		return 1;
	}
	NewShareDialog dlg(this, this);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long CompMgmt::onShareProperties(FXObject*, FXSelector, void*) {
	ShareInfo* found = NULL;
	for (auto& s : shares) if (s.name == contextShareName) { found = &s; break; }
	if (!found) return 1;
	ShareInfo s = *found;

	SharePropertiesDialog dlg(this, s);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können keine Änderungen gespeichert werden.");
		return 1;
	}
	FXString errorMsg;
	if (modifyShare(s.name, dlg.getPath(), dlg.getComment(), dlg.getReadOnly(), errorMsg)) {
		showListFor(NK_SHARES);
		statuslbl->setText("Eigenschaften von " + s.name + " aktualisiert.");
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long CompMgmt::onDeleteShare(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts geändert werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Freigabe aufheben bestätigen",
	        "Freigabe \"%s\" wirklich aufheben? Der Ordner selbst und seine Dateien bleiben erhalten.", contextShareName.text()) != MBOX_CLICKED_YES) {
		return 1;
	}
	FXString errorMsg;
	if (deleteShare(contextShareName, errorMsg)) {
		showListFor(NK_SHARES);
		statuslbl->setText("Freigabe " + contextShareName + " aufgehoben.");
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

bool CompMgmt::createUser(const FXString& username, const FXString& fullName, const FXString& desc,
                          const FXString& password, bool disabled, FXString& errorMsg) {
	FXString uname = username; uname.trim();
	if (uname.empty()) { errorMsg = "Bitte einen Benutzernamen angeben."; return false; }
	for (auto& u : users) if (u.username == uname) { errorMsg = "Der Benutzer \"" + uname + "\" existiert bereits."; return false; }

	FXString gecos = fullName + ",,," + desc;
	int rc = runAsRoot({ FXString("useradd"), FXString("-m"), FXString("-c"), gecos, uname });
	if (rc != 0) { errorMsg = "Fehler beim Anlegen des Linux-Benutzers (useradd)."; return false; }

	if (!password.empty()) {
		std::string chpasswdInput = std::string(uname.text()) + ":" + password.text() + "\n";
		runAsRootWithStdin({ FXString("chpasswd") }, chpasswdInput);
		if (!isDC) {
			std::string smbInput = std::string(password.text()) + "\n" + password.text() + "\n";
			runAsRootWithStdin({ FXString("smbpasswd"), FXString("-s"), FXString("-a"), uname }, smbInput);
		}
	}

	if (disabled) {
		runAsRoot({ FXString("usermod"), FXString("-L"), uname });
		if (!isDC) runAsRoot({ FXString("smbpasswd"), FXString("-d"), uname });
	}

	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Benutzer " + uname + " angelegt.");
	return true;
}

bool CompMgmt::createGroup(const FXString& groupname, FXString& errorMsg) {
	FXString gname = groupname; gname.trim();
	if (gname.empty()) { errorMsg = "Bitte einen Gruppennamen angeben."; return false; }
	for (auto& g : groups) if (g.groupname == gname) { errorMsg = "Die Gruppe \"" + gname + "\" existiert bereits."; return false; }

	int rc = runAsRoot({ FXString("groupadd"), gname });
	if (rc != 0) { errorMsg = "Fehler beim Anlegen der Gruppe (groupadd)."; return false; }

	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Gruppe " + gname + " angelegt.");
	return true;
}

// Muss nach der vollstaendigen CompMgmt-Definition stehen.
long NewUserDialog::onCreate(FXObject*, FXSelector, void*) {
	FXString username = userField->getText().trim();
	FXString fullName = fullNameField->getText();
	FXString desc = descField->getText();
	FXString pw = pwField->getText();
	FXString pwConfirm = pwConfirmField->getText();

	if (pw != pwConfirm) {
		FXMessageBox::error(this, MBOX_OK, "Kennwörter stimmen nicht überein", "Die beiden eingegebenen Kennwörter sind unterschiedlich.");
		return 1;
	}

	FXString errorMsg;
	if (mgr->createUser(username, fullName, desc, pw, disabledCheck->getCheck(), errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neuer Benutzer",
			"Der Benutzer \"%s\" wurde erfolgreich erstellt.", username.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long NewGroupDialog::onCreate(FXObject*, FXSelector, void*) {
	FXString groupname = nameField->getText().trim();
	FXString errorMsg;
	if (mgr->createGroup(groupname, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neue Gruppe",
			"Die Gruppe \"%s\" wurde erfolgreich erstellt.", groupname.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long NewShareDialog::onCreate(FXObject*, FXSelector, void*) {
	FXString path = pathField->getText().trim();
	FXString name = nameField->getText().trim();
	FXString comment = commentField->getText().trim();
	if (path.empty() || name.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte sowohl Ordnerpfad als auch Freigabename angeben.");
		return 1;
	}
	FXString errorMsg;
	if (createShare(name, path, comment, readOnlyCheck->getCheck(), errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neue Freigabe",
			"Die Freigabe \"%s\" wurde erfolgreich erstellt.", name.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

void CompMgmt::create() {
	FXMainWindow::create();
	show(PLACEMENT_SCREEN);
}

int main(int argc, char* argv[]) {
	FXApp application("CompMgmt", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	// Root-Rechte anfragen, BEVOR das Hauptfenster aufgebaut wird -- wie
	// bei dnsmgr/dhcpmgr: i2ksudo zeigt die GUI-Passwortabfrage im
	// Win2k-Stil.
	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	CompMgmt* win = new CompMgmt(&application);
	application.create();
	win->show(PLACEMENT_SCREEN);

	if (!g_haveRoot) {
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\n"
			"Die Computerverwaltung kann bestehende Benutzer/Gruppen weiterhin\n"
			"anzeigen, aber keine Änderungen vornehmen.");
	}

	return application.run();
}
