// dfs.cpp
//
// "Verteiltes Dateisystem" (DFS) fuer ice2k -- Nachbau des Snap-Ins aus
// Windows 2000 Server.
//
// Unterbau ist Samba: Ein DFS-Stamm ist eine Freigabe mit
// "msdfs root = yes", eine DFS-Verknuepfung ein Symlink im Verzeichnis
// dieser Freigabe, dessen Ziel "msdfs:server\freigabe" lautet. Mehrere
// Ziele (im Original "Replikate") werden durch Komma getrennt:
// "msdfs:srv1\daten,srv2\daten".

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

static FXApp* app = NULL;
static bool g_haveRoot = false;

static const char* SMB_CONF = "/etc/samba/smb.conf";

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
	if (!cur.empty()) out.push_back(cur);
	return out;
}

static std::string lowerCopy(const std::string& s) {
	std::string o = s;
	std::transform(o.begin(), o.end(), o.begin(), ::tolower);
	return o;
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

static bool writeFileAsRoot(const std::string& path, const std::string& content, FXString& errorMsg) {
	std::string tmp = "/tmp/ice2k-dfs.tmp";
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
// DFS-Stämme und -Verknüpfungen
// ---------------------------------------------------------------------
struct DfsLink {
	std::string name;                   // Name der Verknüpfung
	std::vector<std::string> targets;   // "server\freigabe"
};

struct DfsRoot {
	std::string share;      // Freigabename = Stammname
	std::string path;       // lokales Verzeichnis
	std::string comment;
	std::vector<DfsLink> links;
};

static std::string netbiosName() {
	std::string out;
	runCaptured({ "sh", "-c", "testparm -s --parameter-name='netbios name' 2>/dev/null | tail -1" }, out);
	std::string n = trimStr(out);
	if (n.empty()) {
		char host[256] = { 0 };
		gethostname(host, sizeof(host) - 1);
		n = host;
		size_t dot = n.find('.');
		if (dot != std::string::npos) n = n.substr(0, dot);
		std::transform(n.begin(), n.end(), n.begin(), ::toupper);
	}
	return n;
}

// Liest smb.conf als root (fuer normale Benutzer oft nicht lesbar).
static std::string readSmbConf() {
	std::string out;
	if (runAsRootCaptured({ "cat", SMB_CONF }, out) != 0) return "";
	return out;
}

// Freigaben mit "msdfs root = yes" heraussuchen.
static std::vector<DfsRoot> listDfsRoots() {
	std::vector<DfsRoot> out;
	DfsRoot cur;
	bool isRoot = false, inSection = false;
	auto flush = [&]() {
		if (inSection && isRoot && !cur.share.empty() && !cur.path.empty()) out.push_back(cur);
		cur = DfsRoot();
		isRoot = false;
	};
	for (auto& line : splitLines(readSmbConf())) {
		std::string l = trimStr(line);
		if (l.empty() || l[0] == '#' || l[0] == ';') continue;
		if (l[0] == '[') {
			flush();
			inSection = true;
			cur.share = trimStr(l.substr(1, l.find(']') - 1));
			continue;
		}
		size_t eq = l.find('=');
		if (eq == std::string::npos) continue;
		std::string key = lowerCopy(trimStr(l.substr(0, eq)));
		std::string val = trimStr(l.substr(eq + 1));
		if (key == "path") cur.path = val;
		else if (key == "comment") cur.comment = val;
		else if (key == "msdfs root" && (lowerCopy(val) == "yes" || val == "1" || lowerCopy(val) == "true")) isRoot = true;
	}
	flush();
	// Verknüpfungen: Symlinks mit Ziel "msdfs:..."
	for (auto& r : out) {
		std::string raw;
		// "ls -l" liefert Name und Ziel in einer Zeile.
		runAsRootCaptured({ "sh", "-c", "ls -l --time-style=+ '" + r.path + "' 2>/dev/null" }, raw);
		for (auto& line : splitLines(raw)) {
			size_t arrow = line.find(" -> ");
			if (arrow == std::string::npos || line.empty() || line[0] != 'l') continue;
			std::string target = trimStr(line.substr(arrow + 4));
			if (target.rfind("msdfs:", 0) != 0) continue;
			// Name steht vor dem Pfeil, hinter der letzten Mehrfachleerstelle.
			std::string head = trimStr(line.substr(0, arrow));
			size_t sp = head.rfind("  ");
			std::string name = trimStr(sp == std::string::npos ? head : head.substr(sp));
			DfsLink link;
			link.name = name;
			for (auto& t : splitOn(target.substr(6), ',')) if (!trimStr(t).empty()) link.targets.push_back(trimStr(t));
			r.links.push_back(link);
		}
		std::sort(r.links.begin(), r.links.end(), [](const DfsLink& a, const DfsLink& b) { return a.name < b.name; });
	}
	return out;
}

static void reloadSamba() {
	std::string out;
	if (runAsRootCaptured({ "smbcontrol", "all", "reload-config" }, out) != 0)
		runAsRootCaptured({ "systemctl", "reload-or-restart", "samba-ad-dc" }, out);
}

// Legt eine Freigabe mit "msdfs root = yes" an.
static bool createDfsRoot(const std::string& share, const std::string& path, const std::string& comment, FXString& errorMsg) {
	std::string conf = readSmbConf();
	if (conf.empty()) { errorMsg = "Die Datei smb.conf konnte nicht gelesen werden."; return false; }
	for (auto& line : splitLines(conf))
		if (lowerCopy(trimStr(line)) == "[" + lowerCopy(share) + "]") {
			errorMsg = FXString("Es gibt bereits eine Freigabe namens \"") + share.c_str() + "\".";
			return false;
		}
	std::string out;
	if (runAsRootCaptured({ "mkdir", "-p", path }, out) != 0) {
		errorMsg = FXString("Das Verzeichnis konnte nicht angelegt werden:\n") + trimStr(out).c_str();
		return false;
	}
	std::string section = "\n[" + share + "]\n";
	if (!comment.empty()) section += "\tcomment = " + comment + "\n";
	section += "\tpath = " + path + "\n"
	           "\tmsdfs root = yes\n"
	           "\tread only = no\n";
	if (!writeFileAsRoot(SMB_CONF, conf + section, errorMsg)) return false;
	reloadSamba();
	return true;
}

static bool removeDfsRoot(const DfsRoot& root, FXString& errorMsg) {
	std::string conf = readSmbConf();
	std::string result;
	bool inTarget = false;
	for (auto& line : splitLines(conf)) {
		std::string l = trimStr(line);
		if (!l.empty() && l[0] == '[') inTarget = lowerCopy(l) == "[" + lowerCopy(root.share) + "]";
		if (inTarget) continue;
		result += line + "\n";
	}
	if (!writeFileAsRoot(SMB_CONF, result, errorMsg)) return false;
	reloadSamba();
	return true;
}

// Verknüpfung = Symlink "msdfs:ziel[,ziel...]"
static bool writeLink(const DfsRoot& root, const DfsLink& link, FXString& errorMsg) {
	std::string target = "msdfs:";
	for (size_t i = 0; i < link.targets.size(); i++) target += (i ? "," : "") + link.targets[i];
	std::string full = root.path + "/" + link.name;
	std::string out;
	runAsRootCaptured({ "rm", "-f", full }, out);
	if (runAsRootCaptured({ "ln", "-s", target, full }, out) != 0) {
		errorMsg = FXString("Die Verknüpfung konnte nicht angelegt werden:\n") + trimStr(out).c_str();
		return false;
	}
	return true;
}

static bool removeLink(const DfsRoot& root, const DfsLink& link, FXString& errorMsg) {
	std::string out;
	if (runAsRootCaptured({ "rm", "-f", root.path + "/" + link.name }, out) != 0) {
		errorMsg = FXString("Die Verknüpfung konnte nicht gelöscht werden:\n") + trimStr(out).c_str();
		return false;
	}
	return true;
}

// "\\server\freigabe" -> "server\freigabe"; leer, wenn ungültig.
static std::string normalizeTarget(const std::string& input) {
	std::string t = trimStr(input);
	while (t.size() > 1 && (t[0] == '\\' || t[0] == '/')) t.erase(0, 1);
	for (auto& c : t) if (c == '/') c = '\\';
	size_t sep = t.find('\\');
	if (sep == std::string::npos || sep == 0 || sep + 1 >= t.size()) return "";
	return t;
}

static FXString displayTarget(const std::string& t) { return FXString("\\\\") + t.c_str(); }

// ---------------------------------------------------------------------
// Dialoge
// ---------------------------------------------------------------------
class NewRootDialog : public FXDialogBox {
	FXDECLARE(NewRootDialog)
private:
	FXTextField *nameField = nullptr, *pathField = nullptr, *commentField = nullptr;
protected:
	NewRootDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	NewRootDialog(FXWindow* owner, const std::string& host)
		: FXDialogBox(owner, "Neuer DFS-Stamm", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,460,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,4);
		new FXLabel(main, FXString("Der Stamm entsteht als Freigabe auf ") + host.c_str() + " und ist danach\n"
		                  "unter \\\\" + host.c_str() + "\\<Stammname> erreichbar.", NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		auto row = [&](const char* label, const char* value) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,150,0);
			FXTextField* tf = new FXTextField(r, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			tf->setText(value);
			return tf;
		};
		nameField = row("&Stammname:", "dfs");
		pathField = row("&Ordner:", "/srv/dfs");
		commentField = row("&Kommentar:", "");
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		std::string n = trimStr(nameField->getText().text()), p = trimStr(pathField->getText().text());
		if (n.empty() || n.find_first_of(" \\/[]") != std::string::npos) {
			FXMessageBox::error(this, MBOX_OK, "Neuer DFS-Stamm", "Geben Sie einen Stammnamen ohne Leer- und Sonderzeichen an.");
			return 1;
		}
		if (p.empty() || p[0] != '/') {
			FXMessageBox::error(this, MBOX_OK, "Neuer DFS-Stamm", "Geben Sie einen absoluten Pfad für den Ordner an.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string name() const { return trimStr(nameField->getText().text()); }
	std::string path() const { return trimStr(pathField->getText().text()); }
	std::string comment() const { return trimStr(commentField->getText().text()); }
	virtual ~NewRootDialog() {}
};
FXDEFMAP(NewRootDialog) NewRootDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewRootDialog::ID_OK, NewRootDialog::onOk),
};
FXIMPLEMENT(NewRootDialog, FXDialogBox, NewRootDialogMap, ARRAYNUMBER(NewRootDialogMap))

// "Neue DFS-Verknüpfung" und "Neues Replikat" -- dasselbe Formular, nur
// ohne Namensfeld beim Replikat.
class LinkDialog : public FXDialogBox {
	FXDECLARE(LinkDialog)
private:
	FXTextField *nameField = nullptr, *targetField = nullptr;
protected:
	LinkDialog() {}
public:
	enum { ID_OK = FXDialogBox::ID_LAST };
	LinkDialog(FXWindow* owner, const FXString& title, bool withName, const FXString& intro)
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,460,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,4);
		new FXLabel(main, intro, NULL, JUSTIFY_LEFT);
		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		auto row = [&](const char* label, const char* value) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,170,0);
			FXTextField* tf = new FXTextField(r, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			tf->setText(value);
			return tf;
		};
		if (withName) nameField = row("&Verknüpfungsname:", "");
		targetField = row("&Verweisziel (UNC-Pfad):", "\\\\server\\freigabe");
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	long onOk(FXObject*, FXSelector, void*) {
		if (nameField) {
			std::string n = trimStr(nameField->getText().text());
			if (n.empty() || n.find_first_of(" \\/") != std::string::npos) {
				FXMessageBox::error(this, MBOX_OK, "DFS", "Geben Sie einen Verknüpfungsnamen ohne Leer- und Sonderzeichen an.");
				return 1;
			}
		}
		if (normalizeTarget(targetField->getText().text()).empty()) {
			FXMessageBox::error(this, MBOX_OK, "DFS", "Geben Sie das Verweisziel als UNC-Pfad an, z.B. \\\\server\\freigabe.");
			return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	std::string name() const { return nameField ? trimStr(nameField->getText().text()) : std::string(); }
	std::string target() const { return normalizeTarget(targetField->getText().text()); }
	virtual ~LinkDialog() {}
};
FXDEFMAP(LinkDialog) LinkDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, LinkDialog::ID_OK, LinkDialog::onOk),
};
FXIMPLEMENT(LinkDialog, FXDialogBox, LinkDialogMap, ARRAYNUMBER(LinkDialogMap))

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
class DfsWindow : public FXMainWindow {
	FXDECLARE(DfsWindow)
private:
	FXTreeList* tree = nullptr;
	FXIconList* list = nullptr;
	FXLabel* statusbar = nullptr;
	FXTreeItem* rootItem = nullptr;
	FXIcon *icoRoot = nullptr, *icoDfs = nullptr, *icoLink = nullptr, *icoTarget = nullptr;
	std::vector<DfsRoot> roots;
	std::map<FXTreeItem*, std::pair<int, int>> itemIndex;   // Baumknoten -> (Stamm, Verknüpfung oder -1)
	std::string host;
protected:
	DfsWindow() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_NEW_ROOT, ID_DELETE_ROOT, ID_NEW_LINK,
	       ID_DELETE_LINK, ID_NEW_REPLICA, ID_DELETE_REPLICA, ID_REFRESH, ID_ABOUT };

	DfsWindow(FXApp* a);
	virtual void create();
	long onTree(FXObject*, FXSelector, void*);
	long onTreeRight(FXObject*, FXSelector, void*);
	long onListRight(FXObject*, FXSelector, void*);
	long onNewRoot(FXObject*, FXSelector, void*);
	long onDeleteRoot(FXObject*, FXSelector, void*);
	long onNewLink(FXObject*, FXSelector, void*);
	long onDeleteLink(FXObject*, FXSelector, void*);
	long onNewReplica(FXObject*, FXSelector, void*);
	long onDeleteReplica(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	void reload();
	void showFor(FXTreeItem* item);
	int currentRoot() const;
	int currentLink() const;
	virtual ~DfsWindow() {}
};

FXDEFMAP(DfsWindow) DfsWindowMap[] = {
	FXMAPFUNC(SEL_CHANGED, DfsWindow::ID_TREE, DfsWindow::onTree),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, DfsWindow::ID_TREE, DfsWindow::onTreeRight),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, DfsWindow::ID_LIST, DfsWindow::onListRight),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_NEW_ROOT, DfsWindow::onNewRoot),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_DELETE_ROOT, DfsWindow::onDeleteRoot),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_NEW_LINK, DfsWindow::onNewLink),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_DELETE_LINK, DfsWindow::onDeleteLink),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_NEW_REPLICA, DfsWindow::onNewReplica),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_DELETE_REPLICA, DfsWindow::onDeleteReplica),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_REFRESH, DfsWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DfsWindow::ID_ABOUT, DfsWindow::onAbout),
};
FXIMPLEMENT(DfsWindow, FXMainWindow, DfsWindowMap, ARRAYNUMBER(DfsWindowMap))

DfsWindow::DfsWindow(FXApp* a)
	: FXMainWindow(a, "Verteiltes Dateisystem", NULL, NULL, DECOR_ALL, 0,0, 900,560) {
	host = netbiosName();
	icoRoot = new FXPNGIcon(a, resico_network, IMAGE_NEAREST);
	icoDfs = new FXPNGIcon(a, resico_server, IMAGE_NEAREST);
	icoLink = new FXPNGIcon(a, resico_folder, IMAGE_NEAREST);
	icoTarget = new FXPNGIcon(a, resico_network, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoDfs, icoLink, icoTarget }) i->create();

	FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	FXMenuPane* vorgang = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
	new FXMenuCommand(vorgang, "Neuen &DFS-Stamm...", NULL, this, ID_NEW_ROOT);
	new FXMenuCommand(vorgang, "Neue DFS-&Verknüpfung...", NULL, this, ID_NEW_LINK);
	new FXMenuCommand(vorgang, "Neues &Replikat...", NULL, this, ID_NEW_REPLICA);
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

void DfsWindow::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

void DfsWindow::reload() {
	// Auswahl merken, damit sie eine Änderung übersteht.
	std::string selRoot, selLink;
	{
		auto it = itemIndex.find(tree->getCurrentItem());
		if (it != itemIndex.end() && it->second.first < (int)roots.size()) {
			selRoot = roots[it->second.first].share;
			if (it->second.second >= 0 && it->second.second < (int)roots[it->second.first].links.size())
				selLink = roots[it->second.first].links[it->second.second].name;
		}
	}
	getApp()->beginWaitCursor();
	roots = listDfsRoots();
	getApp()->endWaitCursor();
	tree->clearItems();
	itemIndex.clear();
	rootItem = tree->appendItem(0, "Verteiltes Dateisystem", icoRoot, icoRoot);
	for (size_t i = 0; i < roots.size(); i++) {
		FXTreeItem* ri = tree->appendItem(rootItem, (FXString("\\\\") + host.c_str() + "\\" + roots[i].share.c_str()), icoDfs, icoDfs);
		itemIndex[ri] = { (int)i, -1 };
		for (size_t j = 0; j < roots[i].links.size(); j++) {
			FXTreeItem* li = tree->appendItem(ri, roots[i].links[j].name.c_str(), icoLink, icoLink);
			itemIndex[li] = { (int)i, (int)j };
		}
		tree->expandTree(ri);
	}
	tree->expandTree(rootItem);
	FXTreeItem* select = rootItem;
	for (auto& kv : itemIndex) {
		const DfsRoot& r = roots[kv.second.first];
		if (r.share != selRoot) continue;
		if (kv.second.second < 0 && selLink.empty()) select = kv.first;
		else if (kv.second.second >= 0 && r.links[kv.second.second].name == selLink) select = kv.first;
	}
	tree->setCurrentItem(select);
	tree->selectItem(select);
	tree->makeItemVisible(select);
	showFor(select);
}

int DfsWindow::currentRoot() const {
	auto it = itemIndex.find(tree->getCurrentItem());
	return it == itemIndex.end() ? -1 : it->second.first;
}

int DfsWindow::currentLink() const {
	auto it = itemIndex.find(tree->getCurrentItem());
	return it == itemIndex.end() ? -1 : it->second.second;
}

void DfsWindow::showFor(FXTreeItem* item) {
	while (list->getNumHeaders() > 0) list->removeHeader(0);
	list->clearItems();
	auto it = itemIndex.find(item);
	if (it == itemIndex.end()) {
		// Wurzel: die Stämme dieses Servers
		list->appendHeader("DFS-Stamm", NULL, 240);
		list->appendHeader("Ordner", NULL, 240);
		list->appendHeader("Verknüpfungen", NULL, 110);
		list->appendHeader("Kommentar", NULL, 200);
		for (auto& r : roots)
			list->appendItem(FXString("\\\\") + host.c_str() + "\\" + r.share.c_str() + "\t" + r.path.c_str() + "\t" +
			                 FXString(std::to_string(r.links.size()).c_str()) + "\t" + r.comment.c_str(), icoDfs, icoDfs);
		statusbar->setText(roots.empty()
			? " Kein DFS-Stamm eingerichtet. Rechtsklick: Neuen DFS-Stamm anlegen."
			: FXString(" ") + FXString(std::to_string(roots.size()).c_str()) + " DFS-Stamm/Stämme");
		return;
	}
	const DfsRoot& r = roots[it->second.first];
	if (it->second.second < 0) {
		// Stamm: seine Verknüpfungen
		list->appendHeader("DFS-Verknüpfung", NULL, 200);
		list->appendHeader("Verweisziel", NULL, 300);
		list->appendHeader("Replikate", NULL, 90);
		list->appendHeader("Status", NULL, 120);
		for (auto& l : r.links)
			list->appendItem(FXString(l.name.c_str()) + "\t" + (l.targets.empty() ? FXString("-") : displayTarget(l.targets[0])) + "\t" +
			                 FXString(std::to_string(l.targets.size()).c_str()) + "\tAktiviert", icoLink, icoLink);
		statusbar->setText(FXString(" ") + r.path.c_str() + "  --  Rechtsklick in die Liste: Verknüpfung anlegen oder löschen.");
		return;
	}
	// Verknüpfung: ihre Verweisziele (im Original die Replikate)
	const DfsLink& l = r.links[it->second.second];
	list->appendHeader("Verweisziel", NULL, 320);
	list->appendHeader("Status", NULL, 140);
	for (auto& t : l.targets) list->appendItem(displayTarget(t) + "\tAktiviert", icoTarget, icoTarget);
	statusbar->setText(FXString(" Verknüpfung ") + l.name.c_str() + "  --  Rechtsklick in die Liste: Replikat hinzufügen oder entfernen.");
}

long DfsWindow::onTree(FXObject*, FXSelector, void*) {
	showFor(tree->getCurrentItem());
	return 1;
}

long DfsWindow::onTreeRight(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);
	showFor(item);
	FXMenuPane menu(this);
	auto it = itemIndex.find(item);
	if (it == itemIndex.end()) {
		new FXMenuCommand(&menu, "Neuen &DFS-Stamm...", NULL, this, ID_NEW_ROOT);
	} else if (it->second.second < 0) {
		new FXMenuCommand(&menu, "Neue DFS-&Verknüpfung...", NULL, this, ID_NEW_LINK);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "Stamm &entfernen", NULL, this, ID_DELETE_ROOT);
	} else {
		new FXMenuCommand(&menu, "Neues &Replikat...", NULL, this, ID_NEW_REPLICA);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "Verknüpfung &löschen", NULL, this, ID_DELETE_LINK);
	}
	new FXMenuSeparator(&menu);
	new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DfsWindow::onListRight(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx >= 0) { list->setCurrentItem(idx); list->selectItem(idx); }
	auto it = itemIndex.find(tree->getCurrentItem());
	FXMenuPane menu(this);
	if (it == itemIndex.end()) {
		new FXMenuCommand(&menu, "Neuen &DFS-Stamm...", NULL, this, ID_NEW_ROOT);
	} else if (it->second.second < 0) {
		new FXMenuCommand(&menu, "Neue DFS-&Verknüpfung...", NULL, this, ID_NEW_LINK);
		if (idx >= 0) {
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "Verknüpfung &löschen", NULL, this, ID_DELETE_LINK);
		}
	} else {
		new FXMenuCommand(&menu, "Neues &Replikat...", NULL, this, ID_NEW_REPLICA);
		if (idx >= 0) {
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "Replikat &entfernen", NULL, this, ID_DELETE_REPLICA);
		}
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DfsWindow::onNewRoot(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "DFS", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	NewRootDialog dlg(this, host);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	FXString errorMsg;
	if (!createDfsRoot(dlg.name(), dlg.path(), dlg.comment(), errorMsg))
		FXMessageBox::error(this, MBOX_OK, "Neuer DFS-Stamm", "%s", errorMsg.text());
	reload();
	return 1;
}

long DfsWindow::onDeleteRoot(FXObject*, FXSelector, void*) {
	int ri = currentRoot();
	if (ri < 0 || currentLink() >= 0) return 1;
	if (FXMessageBox::question(this, MBOX_YES_NO, "DFS",
	        "Möchten Sie den DFS-Stamm \"%s\" wirklich entfernen?\n\n"
	        "Die Freigabe wird aus der Konfiguration genommen. Das Verzeichnis %s\n"
	        "und die darin liegenden Verknüpfungen bleiben erhalten.",
	        roots[ri].share.c_str(), roots[ri].path.c_str()) != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	if (!removeDfsRoot(roots[ri], errorMsg)) FXMessageBox::error(this, MBOX_OK, "DFS", "%s", errorMsg.text());
	reload();
	return 1;
}

long DfsWindow::onNewLink(FXObject*, FXSelector, void*) {
	int ri = currentRoot();
	if (ri < 0) return 1;
	if (!g_haveRoot) { FXMessageBox::error(this, MBOX_OK, "DFS", "Ohne Root-Rechte kann nichts geändert werden."); return 1; }
	LinkDialog dlg(this, "Neue DFS-Verknüpfung", true,
		FXString("Die Verknüpfung erscheint unter \\\\") + host.c_str() + "\\" + roots[ri].share.c_str() +
		"\\<Name>\nund verweist auf eine Freigabe eines anderen Servers.");
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	DfsLink link;
	link.name = dlg.name();
	link.targets = { dlg.target() };
	FXString errorMsg;
	if (!writeLink(roots[ri], link, errorMsg)) FXMessageBox::error(this, MBOX_OK, "DFS", "%s", errorMsg.text());
	reload();
	return 1;
}

long DfsWindow::onDeleteLink(FXObject*, FXSelector, void*) {
	int ri = currentRoot(), li = currentLink();
	if (ri < 0) return 1;
	if (li < 0) {
		int idx = list->getCurrentItem();
		if (idx < 0 || idx >= (int)roots[ri].links.size()) return 1;
		li = idx;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "DFS",
	        "Möchten Sie die Verknüpfung \"%s\" wirklich löschen?", roots[ri].links[li].name.c_str()) != MBOX_CLICKED_YES) return 1;
	FXString errorMsg;
	if (!removeLink(roots[ri], roots[ri].links[li], errorMsg)) FXMessageBox::error(this, MBOX_OK, "DFS", "%s", errorMsg.text());
	reload();
	return 1;
}

long DfsWindow::onNewReplica(FXObject*, FXSelector, void*) {
	int ri = currentRoot(), li = currentLink();
	if (ri < 0 || li < 0) {
		FXMessageBox::information(this, MBOX_OK, "DFS", "Wählen Sie zuerst die Verknüpfung, zu der ein Replikat gehören soll.");
		return 1;
	}
	LinkDialog dlg(this, "Neues Replikat", false,
		FXString("Zusätzliches Verweisziel für die Verknüpfung \"") + roots[ri].links[li].name.c_str() + "\".\n"
		"Clients wählen eines der Ziele aus; Samba hält die Inhalte nicht selbst gleich.");
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	DfsLink link = roots[ri].links[li];
	if (std::find(link.targets.begin(), link.targets.end(), dlg.target()) != link.targets.end()) {
		FXMessageBox::error(this, MBOX_OK, "DFS", "Dieses Verweisziel ist bereits eingetragen.");
		return 1;
	}
	link.targets.push_back(dlg.target());
	FXString errorMsg;
	if (!writeLink(roots[ri], link, errorMsg)) FXMessageBox::error(this, MBOX_OK, "DFS", "%s", errorMsg.text());
	reload();
	return 1;
}

long DfsWindow::onDeleteReplica(FXObject*, FXSelector, void*) {
	int ri = currentRoot(), li = currentLink();
	int idx = list->getCurrentItem();
	if (ri < 0 || li < 0 || idx < 0 || idx >= (int)roots[ri].links[li].targets.size()) return 1;
	DfsLink link = roots[ri].links[li];
	if (link.targets.size() <= 1) {
		FXMessageBox::information(this, MBOX_OK, "DFS",
			"Das letzte Verweisziel lässt sich nicht entfernen.\n\nLöschen Sie stattdessen die Verknüpfung.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "DFS", "Möchten Sie das Verweisziel %s wirklich entfernen?",
	        displayTarget(link.targets[idx]).text()) != MBOX_CLICKED_YES) return 1;
	link.targets.erase(link.targets.begin() + idx);
	FXString errorMsg;
	if (!writeLink(roots[ri], link, errorMsg)) FXMessageBox::error(this, MBOX_OK, "DFS", "%s", errorMsg.text());
	reload();
	return 1;
}

long DfsWindow::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }

long DfsWindow::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Info",
		"Verteiltes Dateisystem (ice2k)\n\n"
		"Ein DFS-Stamm ist eine Samba-Freigabe mit \"msdfs root = yes\",\n"
		"eine Verknüpfung ein Symlink mit dem Ziel \"msdfs:server\\freigabe\".\n"
		"Mehrere Ziele einer Verknüpfung entsprechen den Replikaten.");
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("Dfs", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	g_haveRoot = (runAsRoot({ "true" }) == 0);
	DfsWindow* win = new DfsWindow(&application);
	application.create();
	if (!g_haveRoot)
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\nDie Anzeige funktioniert, Änderungen sind nicht möglich.");
	return application.run();
}
