// svccore.cpp -- siehe svccore.h

#include "svccore.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <sys/wait.h>

namespace svc {

// ---------------------------------------------------------------------
// Prozessaufrufe. Lesen braucht keine Rechte, Schreiben laeuft ueber
// i2ksudo -- dasselbe Muster wie in dnsmgr/dhcpmgr/compmgmt.
// ---------------------------------------------------------------------
static int runCaptured(const std::vector<std::string>& args, std::string& output) {
	int pipefd[2];
	if (pipe(pipefd) != 0) return -1;

	std::vector<char*> argv;
	for (auto& a : args) argv.push_back((char*)a.c_str());
	argv.push_back(NULL);

	pid_t pid = fork();
	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		execvp(argv[0], argv.data());
		_exit(127);
	} else if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

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

static int runAsRoot(std::vector<std::string> args, std::string& output) {
	args.insert(args.begin(), "i2ksudo");
	return runCaptured(args, output);
}

// Schreibt Text als root in eine Datei -- ueber "tee", damit die
// Umleitung selbst im privilegierten Prozess passiert und nicht in
// unserer unprivilegierten Shell.
static int writeAsRoot(const std::string& path, const std::string& content, std::string& output) {
	int pipefd[2];
	if (pipe(pipefd) != 0) return -1;

	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	argv.push_back((char*)"tee");
	argv.push_back((char*)path.c_str());
	argv.push_back(NULL);

	int outfd[2];
	if (pipe(outfd) != 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

	pid_t pid = fork();
	if (pid == 0) {
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]); close(pipefd[1]);
		dup2(outfd[1], STDOUT_FILENO);
		dup2(outfd[1], STDERR_FILENO);
		close(outfd[0]); close(outfd[1]);
		execvp("i2ksudo", argv.data());
		_exit(127);
	} else if (pid < 0) {
		close(pipefd[0]); close(pipefd[1]);
		close(outfd[0]); close(outfd[1]);
		return -1;
	}

	close(pipefd[0]);
	close(outfd[1]);
	ssize_t written = write(pipefd[1], content.data(), content.size());
	(void)written;
	close(pipefd[1]);

	char buf[1024];
	ssize_t n;
	while ((n = read(outfd[0], buf, sizeof(buf))) > 0) output.append(buf, n);
	close(outfd[0]);

	int status = 0;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) return WEXITSTATUS(status);
	return -1;
}

static std::string trim(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

// ---------------------------------------------------------------------
// ServiceInfo
// ---------------------------------------------------------------------
bool ServiceInfo::running() const {
	return activeState == "active" || activeState == "activating" || activeState == "reloading";
}

StartType ServiceInfo::startType() const {
	if (unitFileState == "masked" || unitFileState == "masked-runtime") return START_DISABLED;
	if (unitFileState == "enabled" || unitFileState == "enabled-runtime") return START_AUTO;
	if (unitFileState.empty()) return START_UNKNOWN;
	// disabled, static, indirect, generated, transient ... -- alles
	// startbar, aber nicht von allein: das ist Windows' "Manuell".
	return START_MANUAL;
}

std::string ServiceInfo::displayName() const {
	const std::string suffix = ".service";
	if (unit.size() > suffix.size() && unit.compare(unit.size() - suffix.size(), suffix.size(), suffix) == 0)
		return unit.substr(0, unit.size() - suffix.size());
	return unit;
}

std::string ServiceInfo::statusLabel() const {
	if (activeState == "active") return "Gestartet";
	if (activeState == "activating") return "Wird gestartet";
	if (activeState == "deactivating") return "Wird beendet";
	if (activeState == "failed") return "Fehlgeschlagen";
	return ""; // wie im Original: beendete Dienste zeigen nichts an
}

std::string ServiceInfo::startTypeLabel() const {
	switch (startType()) {
		case START_AUTO: return "Automatisch";
		case START_MANUAL: return "Manuell";
		case START_DISABLED: return "Deaktiviert";
		default: return "";
	}
}

std::string ServiceInfo::logonLabel() const {
	if (user.empty() || user == "root") return "LocalSystem";
	return user;
}

// ---------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------
std::vector<std::map<std::string, std::string> > parseShowRecords(const std::string& raw) {
	std::vector<std::map<std::string, std::string> > out;
	std::map<std::string, std::string> cur;
	std::istringstream in(raw);
	std::string line;
	while (std::getline(in, line)) {
		if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
		if (trim(line).empty()) {
			if (!cur.empty()) { out.push_back(cur); cur.clear(); }
			continue;
		}
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		cur[line.substr(0, eq)] = line.substr(eq + 1);
	}
	if (!cur.empty()) out.push_back(cur);
	return out;
}

static std::string get(const std::map<std::string, std::string>& rec, const char* key) {
	auto it = rec.find(key);
	return it == rec.end() ? std::string() : it->second;
}

ServiceInfo recordToInfo(const std::map<std::string, std::string>& rec) {
	ServiceInfo si;
	si.unit = get(rec, "Id");
	si.description = get(rec, "Description");
	si.activeState = get(rec, "ActiveState");
	si.subState = get(rec, "SubState");
	si.unitFileState = get(rec, "UnitFileState");
	si.user = get(rec, "User");
	si.fragmentPath = get(rec, "FragmentPath");

	// ExecStart kommt als Struktur: "{ path=/usr/sbin/sshd ; argv[]=... }".
	// Uns interessiert fuer "Pfad zur EXE-Datei" nur der Pfad samt
	// Argumenten, also nehmen wir argv[] wenn vorhanden, sonst path.
	std::string exec = get(rec, "ExecStart");
	size_t a = exec.find("argv[]=");
	if (a != std::string::npos) {
		size_t end = exec.find(" ;", a);
		si.execStart = trim(exec.substr(a + 7, end == std::string::npos ? std::string::npos : end - a - 7));
	} else {
		size_t p = exec.find("path=");
		if (p != std::string::npos) {
			size_t end = exec.find(" ;", p);
			si.execStart = trim(exec.substr(p + 5, end == std::string::npos ? std::string::npos : end - p - 5));
		} else {
			si.execStart = trim(exec);
		}
	}
	return si;
}

int parseTimeSpanSeconds(const std::string& value) {
	std::string v = trim(value);
	if (v.empty()) return 0;
	if (v == "infinity") return -1;

	// Reine Ziffern = Mikrosekunden (aeltere systemd-Versionen).
	if (v.find_first_not_of("0123456789") == std::string::npos) {
		long long us = atoll(v.c_str());
		return (int)(us / 1000000);
	}

	// Sonst eine Folge aus Zahl+Einheit, z.B. "1min 30s".
	long long total = 0;
	size_t i = 0;
	bool any = false;
	while (i < v.size()) {
		while (i < v.size() && isspace((unsigned char)v[i])) i++;
		size_t numStart = i;
		while (i < v.size() && isdigit((unsigned char)v[i])) i++;
		if (i == numStart) break;
		long long num = atoll(v.substr(numStart, i - numStart).c_str());
		size_t unitStart = i;
		while (i < v.size() && isalpha((unsigned char)v[i])) i++;
		std::string unit = v.substr(unitStart, i - unitStart);
		if (unit == "us") total += 0;
		else if (unit == "ms") total += 0;
		else if (unit == "s" || unit == "sec") total += num;
		else if (unit == "min" || unit == "m") total += num * 60;
		else if (unit == "h") total += num * 3600;
		else if (unit == "d") total += num * 86400;
		else if (unit == "w") total += num * 604800;
		else continue;
		any = true;
	}
	return any ? (int)total : 0;
}

RecoverySettings recordToRecovery(const std::map<std::string, std::string>& rec) {
	RecoverySettings r;
	std::string restart = get(rec, "Restart");
	r.action = (restart.empty() || restart == "no") ? REC_NONE : REC_RESTART;

	int sec = parseTimeSpanSeconds(get(rec, "RestartUSec"));
	if (sec > 0) r.restartSecs = sec;

	int interval = parseTimeSpanSeconds(get(rec, "StartLimitIntervalUSec"));
	r.resetDays = (interval > 0) ? interval / 86400 : 0;
	return r;
}

std::vector<std::string> splitUnitList(const std::string& value, bool servicesOnly) {
	std::vector<std::string> out;
	std::istringstream in(value);
	std::string tok;
	while (in >> tok) {
		if (servicesOnly) {
			const std::string suffix = ".service";
			if (tok.size() <= suffix.size() ||
			    tok.compare(tok.size() - suffix.size(), suffix.size(), suffix) != 0) continue;
		}
		if (std::find(out.begin(), out.end(), tok) == out.end()) out.push_back(tok);
	}
	std::sort(out.begin(), out.end());
	return out;
}

std::string dropInPath(const std::string& unit) {
	return "/etc/systemd/system/" + unit + ".d/ice2k.conf";
}

std::string buildDropIn(const std::string& account, const RecoverySettings& rec) {
	std::string out =
		"# Von ice2k erzeugt (Dienste-Verwaltung).\n"
		"# Diese Datei wird bei jeder Aenderung komplett neu geschrieben.\n"
		"# Die mitgelieferte Unit-Datei bleibt unangetastet.\n";

	if (rec.resetDays > 0) {
		char buf[128];
		snprintf(buf, sizeof(buf), "\n[Unit]\nStartLimitIntervalSec=%d\n", rec.resetDays * 86400);
		out += buf;
	}

	out += "\n[Service]\n";
	if (!account.empty()) out += "User=" + account + "\n";
	if (rec.action == REC_RESTART) {
		char buf[128];
		snprintf(buf, sizeof(buf), "Restart=on-failure\nRestartSec=%d\n", rec.restartSecs);
		out += buf;
	} else {
		out += "Restart=no\n";
	}
	return out;
}

// ---------------------------------------------------------------------
// Systemzugriffe
// ---------------------------------------------------------------------
static const char* SHOW_PROPS[] = {
	"Id", "Description", "ActiveState", "SubState", "UnitFileState",
	"User", "ExecStart", "FragmentPath", "Restart", "RestartUSec",
	"StartLimitIntervalUSec", "Requires", "Wants", "RequiredBy", "WantedBy"
};

static std::vector<std::string> showCommand(const std::string& pattern) {
	std::vector<std::string> args;
	args.push_back("systemctl");
	args.push_back("show");
	args.push_back(pattern);
	for (size_t i = 0; i < sizeof(SHOW_PROPS) / sizeof(SHOW_PROPS[0]); i++)
		args.push_back(std::string("--property=") + SHOW_PROPS[i]);
	return args;
}

bool systemdAvailable() {
	std::string out;
	return runCaptured({ "systemctl", "--version" }, out) == 0;
}

std::vector<ServiceInfo> listServices() {
	std::vector<ServiceInfo> out;
	std::string raw;
	// Ein einziger Aufruf fuer alle Dienste -- "systemctl show" trennt die
	// Bloecke durch Leerzeilen. Deutlich schneller als ein Aufruf je Unit.
	if (runCaptured(showCommand("*.service"), raw) != 0 && raw.empty()) return out;

	for (auto& rec : parseShowRecords(raw)) {
		ServiceInfo si = recordToInfo(rec);
		if (si.unit.empty()) continue;
		// Instanz-Vorlagen ("getty@.service") sind keine startbaren
		// Dienste, sondern Schablonen -- die zeigt das Original auch nicht.
		if (si.unit.find("@.service") != std::string::npos) continue;
		out.push_back(si);
	}
	std::sort(out.begin(), out.end(), [](const ServiceInfo& a, const ServiceInfo& b) {
		return a.displayName() < b.displayName();
	});
	return out;
}

bool loadService(const std::string& unit, ServiceInfo& info, RecoverySettings& rec, Dependencies& deps) {
	std::string raw;
	if (runCaptured(showCommand(unit), raw) != 0 && raw.empty()) return false;
	auto records = parseShowRecords(raw);
	if (records.empty()) return false;

	info = recordToInfo(records[0]);
	if (info.unit.empty()) info.unit = unit;
	rec = recordToRecovery(records[0]);

	deps.dependsOn.clear();
	deps.dependents.clear();
	for (auto& u : splitUnitList(get(records[0], "Requires"))) deps.dependsOn.push_back(u);
	for (auto& u : splitUnitList(get(records[0], "Wants")))
		if (std::find(deps.dependsOn.begin(), deps.dependsOn.end(), u) == deps.dependsOn.end())
			deps.dependsOn.push_back(u);
	for (auto& u : splitUnitList(get(records[0], "RequiredBy"))) deps.dependents.push_back(u);
	for (auto& u : splitUnitList(get(records[0], "WantedBy")))
		if (std::find(deps.dependents.begin(), deps.dependents.end(), u) == deps.dependents.end())
			deps.dependents.push_back(u);
	return true;
}

static bool simpleAction(const char* verb, const std::string& unit, std::string& errorMsg) {
	std::string out;
	int rc = runAsRoot({ "systemctl", verb, unit }, out);
	if (rc != 0) { errorMsg = out.empty() ? "systemctl meldete einen Fehler." : out; return false; }
	return true;
}

bool startService(const std::string& unit, std::string& errorMsg) { return simpleAction("start", unit, errorMsg); }
bool stopService(const std::string& unit, std::string& errorMsg) { return simpleAction("stop", unit, errorMsg); }
bool restartService(const std::string& unit, std::string& errorMsg) { return simpleAction("restart", unit, errorMsg); }

bool setStartType(const std::string& unit, StartType type, std::string& errorMsg) {
	std::string out;
	// Erst eine eventuelle Maskierung loesen, sonst laufen "enable"/
	// "disable" gegen einen maskierten Dienst ins Leere.
	if (type != START_DISABLED) runAsRoot({ "systemctl", "unmask", unit }, out);

	out.clear();
	int rc = 0;
	switch (type) {
		case START_AUTO: rc = runAsRoot({ "systemctl", "enable", unit }, out); break;
		case START_MANUAL: rc = runAsRoot({ "systemctl", "disable", unit }, out); break;
		case START_DISABLED: rc = runAsRoot({ "systemctl", "mask", unit }, out); break;
		default: return true;
	}
	if (rc != 0) { errorMsg = out.empty() ? "systemctl meldete einen Fehler." : out; return false; }
	return true;
}

bool applySettings(const std::string& unit, const std::string& account,
                   const RecoverySettings& rec, std::string& errorMsg) {
	std::string path = dropInPath(unit);
	std::string dir = path.substr(0, path.find_last_of('/'));

	std::string out;
	if (runAsRoot({ "mkdir", "-p", dir }, out) != 0) {
		errorMsg = "Konnte das Verzeichnis " + dir + " nicht anlegen.\n" + out;
		return false;
	}

	out.clear();
	if (writeAsRoot(path, buildDropIn(account, rec), out) != 0) {
		errorMsg = "Konnte " + path + " nicht schreiben.\n" + out;
		return false;
	}

	out.clear();
	if (runAsRoot({ "systemctl", "daemon-reload" }, out) != 0) {
		errorMsg = "daemon-reload fehlgeschlagen.\n" + out;
		return false;
	}
	return true;
}

} // namespace svc
