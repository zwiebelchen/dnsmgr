// evtcore.cpp -- siehe evtcore.h
#include "evtcore.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

namespace evt {

// ---------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------
std::string trimStr(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

std::vector<std::string> splitLines(const std::string& s) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : s) {
		if (c == '\n') { out.push_back(cur); cur.clear(); }
		else if (c != '\r') cur += c;
	}
	if (!cur.empty()) out.push_back(cur);
	return out;
}

int runCaptured(const std::vector<std::string>& args, std::string& output) {
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
int runAsRootCaptured(const std::vector<std::string>& args, std::string& output) {
	std::vector<std::string> full = { "i2ksudo" };
	for (auto& a : args) full.push_back(a);
	return runCaptured(full, output);
}

// ---------------------------------------------------------------------
// Ereignisse
// ---------------------------------------------------------------------




// Ein Feld aus einer JSON-Zeile des Journals holen (die Ausgabe ist eine
// flache Struktur, ein vollstaendiger JSON-Leser waere hier Ballast).
std::string jsonField(const std::string& line, const std::string& key) {
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

EventType typeFromPriority(int prio) {
	if (prio <= 3) return EVT_ERROR;
	if (prio == 4) return EVT_WARNING;
	return EVT_INFO;
}

// Facility 4 (auth) und 10 (authpriv) -> Sicherheit, 0 (kern) und 3
// (daemon) -> System, alles andere -> Anwendung.
LogKind logFromFacility(int facility, const std::string& source) {
	if (facility == 4 || facility == 10) return LOG_SECURITY;
	if (facility == 0 || facility == 3) return LOG_SYSTEM;
	if (source == "kernel" || source == "systemd" || source == "systemd-journald") return LOG_SYSTEM;
	return LOG_APPLICATION;
}

std::vector<EventEntry> readJournal(int maxEntries) {
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
std::vector<EventEntry> readSyslogFile(const std::string& path, LogKind log) {
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

std::vector<EventEntry> readAllEvents(int maxEntries, bool& fromJournal) {
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


const char* typeName(EventType t) {
	return t == EVT_ERROR ? "Fehler" : t == EVT_WARNING ? "Warnung" : "Informationen";
}

std::string formatDate(time_t t) {
	struct tm lt;
	localtime_r(&t, &lt);
	char buf[32];
	strftime(buf, sizeof(buf), "%d.%m.%Y", &lt);
	return buf;
}

std::string formatTime(time_t t) {
	struct tm lt;
	localtime_r(&t, &lt);
	char buf[32];
	strftime(buf, sizeof(buf), "%H:%M:%S", &lt);
	return buf;
}

bool clearJournal(std::string& output) {
	if (runAsRootCaptured({ "journalctl", "--rotate" }, output) != 0) return false;
	return runAsRootCaptured({ "journalctl", "--vacuum-time=1s" }, output) == 0;
}

} // namespace evt
