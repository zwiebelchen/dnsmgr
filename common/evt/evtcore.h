// evtcore.h -- Ereignisse dieses Servers einsammeln.
//
// Quelle ist das systemd-Journal (`journalctl -o json`); ohne Journal die
// klassischen Logdateien unter /var/log. Die Zuordnung zu den drei
// Protokollen Anwendung, Sicherheit und System folgt den
// Syslog-Facilities. Ohne FOX-Abhaengigkeit, damit der Kern auch ohne
// Oberflaeche nutzbar bleibt (wie bei common/svc).
#pragma once

#include <string>
#include <vector>
#include <ctime>

namespace evt {

enum EventType { EVT_INFO = 0, EVT_WARNING, EVT_ERROR };
enum LogKind { LOG_APPLICATION = 0, LOG_SECURITY, LOG_SYSTEM, LOG_COUNT };

struct EventEntry {
	EventType type = EVT_INFO;
	time_t when = 0;
	std::string source;     // Dienst bzw. Programm
	std::string user;
	std::string computer;
	std::string message;
	std::string eventId;    // Journal: Prozesskennung -- siehe README
	LogKind log = LOG_APPLICATION;
};

const char* typeName(EventType t);
std::string formatDate(time_t t);
std::string formatTime(time_t t);

// Liest bis zu maxEntries Ereignisse. fromJournal sagt, ob sie aus dem
// Journal stammen oder aus den Logdateien.
std::vector<EventEntry> readAllEvents(int maxEntries, bool& fromJournal);

// Leert das Journal (rotate + vacuum). Liefert false samt Ausgabe, wenn
// es nicht geklappt hat.
bool clearJournal(std::string& output);

} // namespace evt
