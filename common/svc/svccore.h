// svccore.h
//
// Gemeinsamer Kern der Dienstverwaltung -- Backend ist systemd.
// Bewusst OHNE jede FOX-/GUI-Abhaengigkeit, damit dieselbe Logik im
// eigenstaendigen "Dienste"-Programm und im Zweig "Dienste und
// Anwendungen" der Computerverwaltung steckt und sich die reinen
// Parser ohne laufendes systemd testen lassen (siehe test_svccore.cpp).

#ifndef SVCCORE_H
#define SVCCORE_H

#include <string>
#include <vector>
#include <map>

namespace svc {

// Windows-2000-Starttyp. Abbildung auf systemd:
//   Automatisch  = enabled        (startet beim Systemstart)
//   Manuell      = disabled/static(startbar, aber nicht automatisch)
//   Deaktiviert  = masked         (laesst sich gar nicht starten)
enum StartType { START_AUTO, START_MANUAL, START_DISABLED, START_UNKNOWN };

// Was bei einem Dienstausfall passieren soll. systemd kennt nur eine
// einzige Regel, nicht "erster/zweiter/weiterer Fehlschlag" getrennt.
enum RecoveryAction { REC_NONE, REC_RESTART };

struct ServiceInfo {
	std::string unit;           // "ssh.service"
	std::string description;    // Description=
	std::string activeState;    // active/inactive/failed/...
	std::string subState;
	std::string unitFileState;  // enabled/disabled/masked/static/...
	std::string user;           // User= (leer = root)
	std::string execStart;      // erster ExecStart-Pfad
	std::string fragmentPath;

	bool running() const;
	StartType startType() const;
	// Anzeigename ohne ".service" -- entspricht der Spalte "Name".
	std::string displayName() const;
	std::string statusLabel() const;     // "Gestartet" / "" / "Wird gestartet"
	std::string startTypeLabel() const;  // "Automatisch"/"Manuell"/"Deaktiviert"
	std::string logonLabel() const;      // "LocalSystem" oder Kontoname
};

struct RecoverySettings {
	RecoveryAction action = REC_NONE;
	int restartSecs = 100;   // RestartSec=
	int resetDays = 0;       // StartLimitIntervalSec= in Tagen (0 = aus)
};

struct Dependencies {
	std::vector<std::string> dependsOn;   // "X ist von diesen Diensten abhaengig"
	std::vector<std::string> dependents;  // "Diese Dienste sind von X abhaengig"
};

// ---------------------------------------------------------------------
// Reine Parser -- kein systemd noetig, direkt testbar.
// ---------------------------------------------------------------------

// "systemctl show" liefert KEY=VALUE-Zeilen; bei mehreren Units sind die
// Bloecke durch Leerzeilen getrennt.
std::vector<std::map<std::string, std::string> > parseShowRecords(const std::string& raw);

ServiceInfo recordToInfo(const std::map<std::string, std::string>& rec);
RecoverySettings recordToRecovery(const std::map<std::string, std::string>& rec);

// systemd trennt Listenwerte (Requires=, WantedBy= ...) mit Leerzeichen.
// Wir zeigen wie das Original nur Dienste an, keine Targets/Sockets.
std::vector<std::string> splitUnitList(const std::string& value, bool servicesOnly = true);

// Unit-Namen aus "systemctl list-unit-files" bzw. "list-units --plain"
// (erste Spalte). Nur Dienste, ohne Instanz-Vorlagen ("getty@.service"),
// ohne Doppelte, in Eingabereihenfolge.
std::vector<std::string> parseUnitNames(const std::string& raw);

// Zeitangaben aus "systemctl show": je nach Version "30s", "1min 30s",
// "infinity" oder blanke Mikrosekunden. Rueckgabe in Sekunden, -1 bei
// "infinity"/unlesbar.
int parseTimeSpanSeconds(const std::string& value);

// Baut den Inhalt von /etc/systemd/system/<unit>.d/ice2k.conf. Ein
// leeres Konto bedeutet "Lokales Systemkonto" -- dann schreiben wir
// keine User=-Zeile und die Vorgabe der Unit gilt wieder.
std::string buildDropIn(const std::string& account, const RecoverySettings& rec);

std::string dropInPath(const std::string& unit);

// Prueft einen Kontonamen, bevor er als User= in die Drop-in-Datei
// wandert. Ohne das koennte ein Zeilenumbruch im Eingabefeld beliebige
// weitere systemd-Direktiven einschleusen -- keine Rechteausweitung
// (wer hier bedient, hat ueber i2ksudo ohnehin root), aber es wuerde
// die Unit unbemerkt verbiegen.
bool isValidAccountName(const std::string& account);

// ---------------------------------------------------------------------
// Zugriffe auf das laufende System.
// Lesen laeuft unprivilegiert, Schreiben ueber i2ksudo.
// ---------------------------------------------------------------------
bool systemdAvailable();

std::vector<ServiceInfo> listServices();
bool loadService(const std::string& unit, ServiceInfo& info, RecoverySettings& rec, Dependencies& deps);

bool startService(const std::string& unit, std::string& errorMsg);
bool stopService(const std::string& unit, std::string& errorMsg);
bool restartService(const std::string& unit, std::string& errorMsg);
bool setStartType(const std::string& unit, StartType type, std::string& errorMsg);
bool applySettings(const std::string& unit, const std::string& account,
                   const RecoverySettings& rec, std::string& errorMsg);

} // namespace svc

#endif
