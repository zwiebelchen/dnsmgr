// test_svccore.cpp -- prueft die reinen Parser ohne laufendes systemd.
//   g++ -Wall -std=c++17 -o test_svccore test_svccore.cpp svccore.cpp && ./test_svccore

#include "svccore.h"
#include <cassert>
#include <cstdio>
#include <string>

using namespace svc;

static void testShowRecords() {
	// Zwei Bloecke, durch eine Leerzeile getrennt -- so gibt
	// "systemctl show '*.service'" mehrere Units aus.
	std::string raw =
		"Id=ssh.service\n"
		"Description=OpenBSD Secure Shell server\n"
		"ActiveState=active\n"
		"UnitFileState=enabled\n"
		"User=\n"
		"ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no }\n"
		"\n"
		"Id=cups.service\n"
		"Description=CUPS Scheduler\n"
		"ActiveState=inactive\n"
		"UnitFileState=masked\n"
		"User=lp\n";

	auto recs = parseShowRecords(raw);
	assert(recs.size() == 2);

	ServiceInfo a = recordToInfo(recs[0]);
	assert(a.unit == "ssh.service");
	assert(a.displayName() == "ssh");
	assert(a.running());
	assert(a.statusLabel() == "Gestartet");
	assert(a.startType() == START_AUTO);
	assert(a.startTypeLabel() == "Automatisch");
	assert(a.logonLabel() == "LocalSystem");
	// Aus der ExecStart-Struktur wird die reine Befehlszeile.
	assert(a.execStart == "/usr/sbin/sshd -D");

	ServiceInfo b = recordToInfo(recs[1]);
	assert(b.displayName() == "cups");
	assert(!b.running());
	assert(b.statusLabel() == "");           // beendet = leere Spalte
	assert(b.startTypeLabel() == "Deaktiviert");
	assert(b.logonLabel() == "lp");
}

static void testStartTypeMapping() {
	ServiceInfo si;
	si.unitFileState = "enabled-runtime"; assert(si.startType() == START_AUTO);
	si.unitFileState = "disabled";        assert(si.startType() == START_MANUAL);
	si.unitFileState = "static";          assert(si.startType() == START_MANUAL);
	si.unitFileState = "indirect";        assert(si.startType() == START_MANUAL);
	si.unitFileState = "masked-runtime";  assert(si.startType() == START_DISABLED);
	si.unitFileState = "";                assert(si.startType() == START_UNKNOWN);

	// root ist das lokale Systemkonto -- nicht als Sonderkonto anzeigen.
	si.user = "root"; assert(si.logonLabel() == "LocalSystem");
}

static void testTimeSpans() {
	assert(parseTimeSpanSeconds("30s") == 30);
	assert(parseTimeSpanSeconds("1min 30s") == 90);
	assert(parseTimeSpanSeconds("2h") == 7200);
	assert(parseTimeSpanSeconds("7d") == 604800);
	assert(parseTimeSpanSeconds("infinity") == -1);
	assert(parseTimeSpanSeconds("") == 0);
	assert(parseTimeSpanSeconds("100ms") == 0);
	// Blanke Zahlen sind Mikrosekunden (aeltere systemd-Versionen).
	assert(parseTimeSpanSeconds("5000000") == 5);
}

static void testRecovery() {
	std::string raw =
		"Id=x.service\n"
		"Restart=on-failure\n"
		"RestartUSec=30s\n"
		"StartLimitIntervalUSec=2d\n";
	auto recs = parseShowRecords(raw);
	RecoverySettings r = recordToRecovery(recs[0]);
	assert(r.action == REC_RESTART);
	assert(r.restartSecs == 30);
	assert(r.resetDays == 2);

	auto recs2 = parseShowRecords("Id=y.service\nRestart=no\n");
	RecoverySettings r2 = recordToRecovery(recs2[0]);
	assert(r2.action == REC_NONE);
	assert(r2.resetDays == 0);
}

static void testUnitLists() {
	// Nur Dienste anzeigen, Targets/Sockets ausblenden, Duplikate weg.
	auto l = splitUnitList("a.service basic.target b.service a.service dbus.socket");
	assert(l.size() == 2);
	assert(l[0] == "a.service" && l[1] == "b.service");
	assert(splitUnitList("").empty());
	assert(splitUnitList("only.target").empty());
	assert(splitUnitList("only.target", false).size() == 1);
}

static void testDropIn() {
	RecoverySettings r;
	r.action = REC_RESTART;
	r.restartSecs = 60;
	r.resetDays = 1;

	std::string s = buildDropIn("apache", r);
	assert(s.find("[Service]") != std::string::npos);
	assert(s.find("User=apache") != std::string::npos);
	assert(s.find("Restart=on-failure") != std::string::npos);
	assert(s.find("RestartSec=60") != std::string::npos);
	// Tage -> Sekunden, und StartLimitIntervalSec gehoert nach [Unit].
	assert(s.find("[Unit]") != std::string::npos);
	assert(s.find("StartLimitIntervalSec=86400") != std::string::npos);

	// Lokales Systemkonto: keine User=-Zeile, damit die Vorgabe der
	// mitgelieferten Unit wieder greift.
	RecoverySettings none;
	std::string s2 = buildDropIn("", none);
	assert(s2.find("User=") == std::string::npos);
	assert(s2.find("Restart=no") != std::string::npos);
	assert(s2.find("[Unit]") == std::string::npos);

	assert(dropInPath("ssh.service") == "/etc/systemd/system/ssh.service.d/ice2k.conf");
}

int main() {
	testShowRecords();
	testStartTypeMapping();
	testTimeSpans();
	testRecovery();
	testUnitLists();
	testDropIn();
	printf("svccore: alle Tests bestanden\n");
	return 0;
}
