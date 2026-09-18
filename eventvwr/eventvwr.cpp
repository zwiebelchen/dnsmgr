// eventvwr.cpp
//
// "Ereignisanzeige" fuer ice2k -- Nachbau von eventvwr.msc aus Windows
// 2000. Links die drei Protokolle Anwendung, Sicherheit und System,
// rechts die Ereignisliste mit den Spalten des Originals, Doppelklick
// oeffnet die Ereigniseigenschaften mit Pfeiltasten zum Blaettern.
//
// Unterbau ist das systemd-Journal (`journalctl -o json`). Gibt es kein
// Journal, werden die klassischen Logdateien gelesen (/var/log/syslog,
// auth.log, kern.log, messages) -- so ist die Anzeige auch auf Systemen
// ohne dauerhaftes Journal brauchbar.
//
// Die Zuordnung zu den drei Protokollen folgt den Syslog-Facilities:
// auth/authpriv -> Sicherheit, kern und die Dienste des Systems ->
// System, alles Uebrige -> Anwendung.

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
#include <ctime>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

static FXApp* app = NULL;

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
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
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

// Root-Aufruf wie in den anderen ice2k-Programmen (Logdateien und Journal
// sind fuer normale Benutzer oft nicht lesbar).
static int runAsRootCaptured(const std::vector<std::string>& args, std::string& output) {
	std::vector<std::string> full = { "i2ksudo" };
	for (auto& a : args) full.push_back(a);
	return runCaptured(full, output);
}

// ---------------------------------------------------------------------
// Ereignisse
// ---------------------------------------------------------------------
enum EventType { EVT_INFO = 0, EVT_WARNING, EVT_ERROR };
enum LogKind { LOG_APPLICATION = 0, LOG_SECURITY, LOG_SYSTEM, LOG_COUNT };

struct EventEntry {
	EventType type = EVT_INFO;
	time_t when = 0;
	std::string source;     // Dienst bzw. Programm
	std::string user;
	std::string computer;
	std::string message;
	std::string eventId;    // Journal: Zeilennummer bzw. PID -- siehe README
	LogKind log = LOG_APPLICATION;
};

static const char* typeName(EventType t) {
	return t == EVT_ERROR ? "Fehler" : t == EVT_WARNING ? "Warnung" : "Informationen";
}

static FXString formatDate(time_t t) {
	struct tm lt;
	localtime_r(&t, &lt);
	char buf[32];
	strftime(buf, sizeof(buf), "%d.%m.%Y", &lt);
	return buf;
}

static FXString formatTime(time_t t) {
	struct tm lt;
	localtime_r(&t, &lt);
	char buf[32];
	strftime(buf, sizeof(buf), "%H:%M:%S", &lt);
	return buf;
}

// Ein Feld aus einer JSON-Zeile des Journals holen (die Ausgabe ist eine
// flache Struktur, ein vollstaendiger JSON-Leser waere hier Ballast).
static std::string jsonField(const std::string& line, const std::string& key) {
	std::string needle = "\"" + key + "\":";
	size_t p = line.find(needle);
	if (p == std::string::npos) return "";
	p += needle.size();
	while (p < line.size() && (line[p] == ' ')) p++;
	if (p >= line.size()) return "";
	if (line[p] == '"') {
		std::string out;
		for (size_t i = p + 1; i < line.size(); i++) {
			if (line[i] == '\\' && i + 1 < line.size()) {
				char c = line[++i];
				out += c == 'n' ? '\n' : c == 't' ? '\t' : c;
				continue;
			}
			if (line[i] == '"') break;
			out += line[i];
		}
		return out;
	}
	std::string out;
	while (p < line.size() && line[p] != ',' && line[p] != '}') out += line[p++];
	return trimStr(out);
}

static EventType typeFromPriority(int prio) {
	if (prio <= 3) return EVT_ERROR;
	if (prio == 4) return EVT_WARNING;
	return EVT_INFO;
}

// Facility 4 (auth) und 10 (authpriv) -> Sicherheit, 0 (kern) und 3
// (daemon) -> System, alles andere -> Anwendung.
static LogKind logFromFacility(int facility, const std::string& source) {
	if (facility == 4 || facility == 10) return LOG_SECURITY;
	if (facility == 0 || facility == 3) return LOG_SYSTEM;
	if (source == "kernel" || source == "systemd" || source == "systemd-journald") return LOG_SYSTEM;
	return LOG_APPLICATION;
}

static std::vector<EventEntry> readJournal(int maxEntries) {
	std::vector<EventEntry> out;
	std::string raw;
	if (runAsRootCaptured({ "journalctl", "-o", "json", "--no-pager", "-n", std::to_string(maxEntries) }, raw) != 0) return out;
	for (auto& line : splitLines(raw)) {
		if (line.size() < 2 || line[0] != '{') continue;
		EventEntry e;
		std::string ts = jsonField(line, "__REALTIME_TIMESTAMP");
		e.when = ts.empty() ? 0 : (time_t)(strtoull(ts.c_str(), NULL, 10) / 1000000ULL);
		std::string prio = jsonField(line, "PRIORITY");
		e.type = typeFromPriority(prio.empty() ? 6 : atoi(prio.c_str()));
		e.source = jsonField(line, "SYSLOG_IDENTIFIER");
		if (e.source.empty()) e.source = jsonField(line, "_COMM");
		if (e.source.empty()) e.source = jsonField(line, "_SYSTEMD_UNIT");
		e.message = jsonField(line, "MESSAGE");
		e.computer = jsonField(line, "_HOSTNAME");
		std::string uid = jsonField(line, "_UID");
		e.user = uid.empty() ? "" : (uid == "0" ? "root" : ("UID " + uid));
		e.eventId = jsonField(line, "_PID");
		std::string fac = jsonField(line, "SYSLOG_FACILITY");
		e.log = logFromFacility(fac.empty() ? 16 : atoi(fac.c_str()), e.source);
		if (jsonField(line, "_TRANSPORT") == "kernel") e.log = LOG_SYSTEM;
		out.push_back(e);
	}
	return out;
}

// Ruecksfallebene: klassische Logdateien im Syslog-Format
// ("Sep 18 12:00:00 host programm[123]: Text").
static std::vector<EventEntry> readSyslogFile(const std::string& path, LogKind log) {
	std::vector<EventEntry> out;
	std::string raw;
	if (runAsRootCaptured({ "cat", path }, raw) != 0) return out;
	time_t now = time(NULL);
	struct tm nowTm;
	localtime_r(&now, &nowTm);
	for (auto& line : splitLines(raw)) {
		if (line.size() < 20) continue;
		EventEntry e;
		e.log = log;
		struct tm tmv = {};
		tmv.tm_year = nowTm.tm_year;
		tmv.tm_isdst = -1;
		const char* rest = strptime(line.c_str(), "%b %d %H:%M:%S", &tmv);
		if (!rest) {
			// ISO-Format (rsyslog mit RSYSLOG_FileFormat)
			rest = strptime(line.c_str(), "%Y-%m-%dT%H:%M:%S", &tmv);
			if (!rest) continue;
			while (*rest && *rest != ' ') rest++;   // Zeitzone ueberspringen
		}
		e.when = mktime(&tmv);
		std::string tail = trimStr(rest);
		size_t sp = tail.find(' ');
		if (sp == std::string::npos) continue;
		e.computer = tail.substr(0, sp);
		tail = trimStr(tail.substr(sp + 1));
		size_t colon = tail.find(':');
		if (colon != std::string::npos && colon < 64) {
			std::string src = tail.substr(0, colon);
			size_t bracket = src.find('[');
			if (bracket != std::string::npos) {
				e.eventId = src.substr(bracket + 1, src.find(']') - bracket - 1);
				src = src.substr(0, bracket);
			}
			e.source = src;
			e.message = trimStr(tail.substr(colon + 1));
		} else {
			e.message = tail;
		}
		// In den Logdateien fehlt die Facility -- deshalb nach der Quelle
		// einsortieren.
		if (e.source == "kernel" || e.source.rfind("systemd", 0) == 0) e.log = LOG_SYSTEM;
		else if (e.source == "sshd" || e.source == "sudo" || e.source == "su" || e.source == "login" ||
		         e.source == "polkitd" || e.source == "pam_unix") e.log = LOG_SECURITY;
		std::string lower = e.message;
		std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
		if (lower.find("error") != std::string::npos || lower.find("fehler") != std::string::npos ||
		    lower.find("failed") != std::string::npos) e.type = EVT_ERROR;
		else if (lower.find("warn") != std::string::npos) e.type = EVT_WARNING;
		out.push_back(e);
	}
	return out;
}

static std::vector<EventEntry> readAllEvents(int maxEntries, bool& fromJournal) {
	std::vector<EventEntry> out = readJournal(maxEntries);
	fromJournal = !out.empty();
	if (fromJournal) return out;
	for (auto& p : { std::make_pair(std::string("/var/log/syslog"), LOG_APPLICATION),
	                 std::make_pair(std::string("/var/log/messages"), LOG_APPLICATION),
	                 std::make_pair(std::string("/var/log/auth.log"), LOG_SECURITY),
	                 std::make_pair(std::string("/var/log/secure"), LOG_SECURITY),
	                 std::make_pair(std::string("/var/log/kern.log"), LOG_SYSTEM) }) {
		auto part = readSyslogFile(p.first, p.second);
		out.insert(out.end(), part.begin(), part.end());
	}
	if ((int)out.size() > maxEntries) out.erase(out.begin(), out.end() - maxEntries);
	return out;
}

// ---------------------------------------------------------------------
// Dialog "Ereigniseigenschaften" -- Aufbau wie im Original, mit den
// Pfeiltasten zum Blaettern und "Kopieren".
// ---------------------------------------------------------------------
class EventPropertiesDialog : public FXDialogBox {
	FXDECLARE(EventPropertiesDialog)
private:
	const std::vector<EventEntry>* events = nullptr;
	int index = 0;
	FXLabel *dateL = nullptr, *timeL = nullptr, *typeL = nullptr, *userL = nullptr,
	        *computerL = nullptr, *sourceL = nullptr, *catL = nullptr, *idL = nullptr;
	FXText* description = nullptr;
protected:
	EventPropertiesDialog() {}
public:
	enum { ID_PREV = FXDialogBox::ID_LAST, ID_NEXT, ID_COPY };
	EventPropertiesDialog(FXWindow* owner, const std::vector<EventEntry>& events_, int index_)
		: FXDialogBox(owner, "Ereigniseigenschaften", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,520,420),
		  events(&events_), index(index_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		FXHorizontalFrame* top = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 20,0);
		FXMatrix* left = new FXMatrix(top, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,3);
		auto row = [&](FXComposite* p, const char* label) {
			new FXLabel(p, label, NULL, JUSTIFY_LEFT);
			return new FXLabel(p, "", NULL, JUSTIFY_LEFT);
		};
		dateL = row(left, "Datum:");
		timeL = row(left, "Zeit:");
		typeL = row(left, "Typ:");
		userL = row(left, "Benutzer:");
		computerL = row(left, "Computer:");
		FXMatrix* right = new FXMatrix(top, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,3);
		sourceL = row(right, "Quelle:");
		catL = row(right, "Kategorie:");
		idL = row(right, "Ereigniskennung:");

		// Rechts daneben die Pfeiltasten wie im Original.
		FXVerticalFrame* buttons = new FXVerticalFrame(top, LAYOUT_TOP, 0,0,0,0, 0,0,0,0, 0,2);
		new FXArrowButton(buttons, this, ID_PREV, ARROW_UP | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT, 0,0,26,22);
		new FXArrowButton(buttons, this, ID_NEXT, ARROW_DOWN | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT, 0,0,26,22);
		new FXButton(buttons, "&Kopieren", NULL, this, ID_COPY, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);

		new FXLabel(main, "&Beschreibung:", NULL, JUSTIFY_LEFT);
		FXPacker* df = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		description = new FXText(df, NULL, 0, TEXT_READONLY | TEXT_WORDWRAP | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		show();
	}
	void show() {
		if (index < 0 || index >= (int)events->size()) return;
		const EventEntry& e = (*events)[index];
		dateL->setText(formatDate(e.when));
		timeL->setText(formatTime(e.when));
		typeL->setText(typeName(e.type));
		userL->setText(e.user.empty() ? "Nicht zutreffend" : FXString(e.user.c_str()));
		computerL->setText(e.computer.c_str());
		sourceL->setText(e.source.empty() ? "Unbekannt" : FXString(e.source.c_str()));
		catL->setText("Keine");
		idL->setText(e.eventId.empty() ? "-" : FXString(e.eventId.c_str()));
		description->setText(e.message.c_str());
	}
	long onPrev(FXObject*, FXSelector, void*) { if (index > 0) { index--; show(); } return 1; }
	long onNext(FXObject*, FXSelector, void*) { if (index + 1 < (int)events->size()) { index++; show(); } return 1; }
	long onCopy(FXObject*, FXSelector, void*) {
		const EventEntry& e = (*events)[index];
		FXString text = FXString("Ereignistyp:\t") + typeName(e.type) + "\nEreignisquelle:\t" + e.source.c_str() +
		                "\nDatum:\t\t" + formatDate(e.when) + "\nZeit:\t\t" + formatTime(e.when) +
		                "\nBenutzer:\t" + (e.user.empty() ? "Nicht zutreffend" : FXString(e.user.c_str())) +
		                "\nComputer:\t" + e.computer.c_str() + "\nBeschreibung:\n" + e.message.c_str() + "\n";
		FXDragType types[1] = { FXWindow::stringType };
		if (acquireClipboard(types, 1)) clipped = text;
		return 1;
	}
	long onClipboardRequest(FXObject* sender, FXSelector sel, void* ptr) {
		FXEvent* event = (FXEvent*)ptr;
		if (event->target == FXWindow::stringType) {
			setDNDData(FROM_CLIPBOARD, FXWindow::stringType, clipped);
			return 1;
		}
		return FXDialogBox::onClipboardRequest(sender, sel, ptr);
	}
	FXString clipped;
	virtual ~EventPropertiesDialog() {}
};
FXDEFMAP(EventPropertiesDialog) EventPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, EventPropertiesDialog::ID_PREV, EventPropertiesDialog::onPrev),
	FXMAPFUNC(SEL_COMMAND, EventPropertiesDialog::ID_NEXT, EventPropertiesDialog::onNext),
	FXMAPFUNC(SEL_COMMAND, EventPropertiesDialog::ID_COPY, EventPropertiesDialog::onCopy),
	FXMAPFUNC(SEL_CLIPBOARD_REQUEST, 0, EventPropertiesDialog::onClipboardRequest),
};
FXIMPLEMENT(EventPropertiesDialog, FXDialogBox, EventPropertiesDialogMap, ARRAYNUMBER(EventPropertiesDialogMap))

// ---------------------------------------------------------------------
// Dialog "Filter" (im Original der Reiter "Filter" der
// Protokolleigenschaften).
// ---------------------------------------------------------------------
struct EventFilter {
	bool showInfo = true, showWarning = true, showError = true;
	std::string source;   // Teilstring der Quelle
	int maxEntries = 500;
};

class FilterDialog : public FXDialogBox {
	FXDECLARE(FilterDialog)
private:
	FXCheckButton *info = nullptr, *warning = nullptr, *error = nullptr;
	FXTextField *source = nullptr, *maxEntries = nullptr;
protected:
	FilterDialog() {}
public:
	FilterDialog(FXWindow* owner, const EventFilter& f)
		: FXDialogBox(owner, "Filter", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		FXGroupBox* types = new FXGroupBox(main, "Ereignistypen", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8, 0,2);
		info = new FXCheckButton(types, "&Informationen");
		warning = new FXCheckButton(types, "&Warnung");
		error = new FXCheckButton(types, "&Fehler");
		info->setCheck(f.showInfo);
		warning->setCheck(f.showWarning);
		error->setCheck(f.showError);
		auto row = [&](const char* label, const char* value) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,150,0);
			FXTextField* tf = new FXTextField(r, 16, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			tf->setText(value);
			return tf;
		};
		source = row("&Ereignisquelle:", f.source.c_str());
		maxEntries = row("&Anzahl der Ereignisse:", std::to_string(f.maxEntries).c_str());
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	EventFilter filter() const {
		EventFilter f;
		f.showInfo = info->getCheck();
		f.showWarning = warning->getCheck();
		f.showError = error->getCheck();
		f.source = trimStr(source->getText().text());
		f.maxEntries = std::max(10, atoi(maxEntries->getText().text()));
		return f;
	}
	virtual ~FilterDialog() {}
};
FXIMPLEMENT(FilterDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
class EventViewer : public FXMainWindow {
	FXDECLARE(EventViewer)
private:
	FXTreeList* tree = nullptr;
	FXIconList* list = nullptr;
	FXLabel* statusbar = nullptr;
	FXTreeItem* rootItem = nullptr;
	FXTreeItem* logItems[LOG_COUNT] = { nullptr };
	FXIcon *icoRoot = nullptr, *icoLog = nullptr, *icoInfo = nullptr, *icoWarning = nullptr, *icoError = nullptr;
	std::vector<EventEntry> allEvents, shown;
	EventFilter filter;
	LogKind current = LOG_APPLICATION;
	bool fromJournal = true;
protected:
	EventViewer() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_REFRESH, ID_PROPERTIES, ID_FILTER, ID_CLEAR, ID_ABOUT };

	EventViewer(FXApp* a);
	virtual void create();
	long onTree(FXObject*, FXSelector, void*);
	long onListDouble(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onFilter(FXObject*, FXSelector, void*);
	long onClear(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	void reload();
	void showLog(LogKind kind);
	virtual ~EventViewer() {}
};

FXDEFMAP(EventViewer) EventViewerMap[] = {
	FXMAPFUNC(SEL_CHANGED, EventViewer::ID_TREE, EventViewer::onTree),
	FXMAPFUNC(SEL_DOUBLECLICKED, EventViewer::ID_LIST, EventViewer::onListDouble),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_REFRESH, EventViewer::onRefresh),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_PROPERTIES, EventViewer::onProperties),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_FILTER, EventViewer::onFilter),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_CLEAR, EventViewer::onClear),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_ABOUT, EventViewer::onAbout),
};
FXIMPLEMENT(EventViewer, FXMainWindow, EventViewerMap, ARRAYNUMBER(EventViewerMap))

EventViewer::EventViewer(FXApp* a)
	: FXMainWindow(a, "Ereignisanzeige", NULL, NULL, DECOR_ALL, 0,0, 920,560) {
	icoRoot = new FXPNGIcon(a, resico_evt_log, IMAGE_NEAREST);
	icoLog = new FXPNGIcon(a, resico_evt_log, IMAGE_NEAREST);
	icoInfo = new FXPNGIcon(a, resico_evt_info, IMAGE_NEAREST);
	icoWarning = new FXPNGIcon(a, resico_evt_warning, IMAGE_NEAREST);
	icoError = new FXPNGIcon(a, resico_evt_error, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoLog, icoInfo, icoWarning, icoError }) i->create();

	FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	FXMenuPane* vorgang = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
	new FXMenuCommand(vorgang, "Alle Ereignisse &löschen", NULL, this, ID_CLEAR);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Eigenschaften", NULL, this, ID_PROPERTIES);
	FXMenuPane* ansicht = new FXMenuPane(this);
	new FXMenuTitle(menubar, "A&nsicht", NULL, ansicht);
	new FXMenuCommand(ansicht, "&Filter...", NULL, this, ID_FILTER);
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
	tb("\tListe exportieren", gif(resico_mmc_export), 0);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
	tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	new FXToolTip(getApp());

	statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);

	FXSplitter* splitter = new FXSplitter(this, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,260,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
	FXPacker* listframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(listframe, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	// Spalten wie im Original.
	list->appendHeader("Typ", NULL, 100);
	list->appendHeader("Datum", NULL, 90);
	list->appendHeader("Zeit", NULL, 80);
	list->appendHeader("Quelle", NULL, 150);
	list->appendHeader("Kategorie", NULL, 80);
	list->appendHeader("Ereignis", NULL, 70);
	list->appendHeader("Benutzer", NULL, 90);
	list->appendHeader("Computer", NULL, 110);

	char host[256] = { 0 };
	gethostname(host, sizeof(host) - 1);
	rootItem = tree->appendItem(0, FXString("Ereignisanzeige (Lokal: ") + host + ")", icoRoot, icoRoot);
	logItems[LOG_APPLICATION] = tree->appendItem(rootItem, "Anwendung", icoLog, icoLog);
	logItems[LOG_SECURITY] = tree->appendItem(rootItem, "Sicherheit", icoLog, icoLog);
	logItems[LOG_SYSTEM] = tree->appendItem(rootItem, "System", icoLog, icoLog);
	tree->expandTree(rootItem);
	tree->setCurrentItem(logItems[LOG_APPLICATION]);
	tree->selectItem(logItems[LOG_APPLICATION]);
}

void EventViewer::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

void EventViewer::reload() {
	getApp()->beginWaitCursor();
	allEvents = readAllEvents(filter.maxEntries, fromJournal);
	getApp()->endWaitCursor();
	// Neueste zuerst, wie im Original.
	std::sort(allEvents.begin(), allEvents.end(), [](const EventEntry& a, const EventEntry& b) { return a.when > b.when; });
	showLog(current);
}

void EventViewer::showLog(LogKind kind) {
	current = kind;
	shown.clear();
	list->clearItems();
	for (auto& e : allEvents) {
		if (e.log != kind) continue;
		if (e.type == EVT_INFO && !filter.showInfo) continue;
		if (e.type == EVT_WARNING && !filter.showWarning) continue;
		if (e.type == EVT_ERROR && !filter.showError) continue;
		if (!filter.source.empty() && e.source.find(filter.source) == std::string::npos) continue;
		shown.push_back(e);
	}
	for (auto& e : shown) {
		FXIcon* ic = e.type == EVT_ERROR ? icoError : e.type == EVT_WARNING ? icoWarning : icoInfo;
		list->appendItem(FXString(typeName(e.type)) + "\t" + formatDate(e.when) + "\t" + formatTime(e.when) + "\t" +
		                 e.source.c_str() + "\tKeine\t" + (e.eventId.empty() ? "-" : e.eventId.c_str()) + "\t" +
		                 (e.user.empty() ? "-" : e.user.c_str()) + "\t" + e.computer.c_str(), ic, ic);
	}
	char buf[160];
	snprintf(buf, sizeof(buf), " %d Ereignis(se)%s", (int)shown.size(),
	         fromJournal ? "" : "  --  Quelle: Logdateien unter /var/log (kein Journal gefunden)");
	statusbar->setText(buf);
}

long EventViewer::onTree(FXObject*, FXSelector, void*) {
	FXTreeItem* cur = tree->getCurrentItem();
	for (int i = 0; i < LOG_COUNT; i++)
		if (cur == logItems[i]) { showLog((LogKind)i); return 1; }
	return 1;
}

long EventViewer::onListDouble(FXObject*, FXSelector, void* ptr) {
	FXint idx = (FXint)(FXival)ptr;
	if (idx < 0 || idx >= (int)shown.size()) return 1;
	EventPropertiesDialog dlg(this, shown, idx);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long EventViewer::onProperties(FXObject*, FXSelector, void*) {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)shown.size()) return 1;
	EventPropertiesDialog dlg(this, shown, idx);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long EventViewer::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }

long EventViewer::onFilter(FXObject*, FXSelector, void*) {
	FilterDialog dlg(this, filter);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	int oldMax = filter.maxEntries;
	filter = dlg.filter();
	if (filter.maxEntries != oldMax) reload(); else showLog(current);
	return 1;
}

// Das Original leert genau ein Protokoll. Journald kennt diese Trennung
// nicht -- deshalb wird hier das ganze Journal geleert, und der Dialog
// sagt das auch.
long EventViewer::onClear(FXObject*, FXSelector, void*) {
	if (!fromJournal) {
		FXMessageBox::information(this, MBOX_OK, "Ereignisanzeige",
			"Die Ereignisse stammen aus den Logdateien unter /var/log.\n\n"
			"Diese werden von logrotate verwaltet und hier nicht gelöscht.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Ereignisanzeige",
	        "Möchten Sie wirklich alle Ereignisse löschen?\n\n"
	        "Das systemd-Journal kennt die Trennung in Anwendung, Sicherheit und System\n"
	        "nicht: Es wird vollständig geleert, nicht nur das gewählte Protokoll.") != MBOX_CLICKED_YES)
		return 1;
	std::string out;
	if (runAsRootCaptured({ "journalctl", "--rotate" }, out) != 0 ||
	    runAsRootCaptured({ "journalctl", "--vacuum-time=1s" }, out) != 0)
		FXMessageBox::error(this, MBOX_OK, "Ereignisanzeige", "Das Journal konnte nicht geleert werden:\n\n%s", trimStr(out).c_str());
	reload();
	return 1;
}

long EventViewer::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Info",
		"Ereignisanzeige (ice2k)\n\n"
		"Zeigt die Ereignisse dieses Servers aus dem systemd-Journal;\n"
		"ohne Journal aus den Logdateien unter /var/log.\n\n"
		"Die Zuordnung zu Anwendung, Sicherheit und System folgt den\n"
		"Syslog-Facilities.");
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("EventVwr", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	new EventViewer(&application);
	application.create();
	return application.run();
}
