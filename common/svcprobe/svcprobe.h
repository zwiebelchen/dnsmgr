// ---------------------------------------------------------------------
// Gemeinsame Pruefung "laeuft der Dienst, den dieses Programm verwaltet?"
//
// Alle ice2k-Programme arbeiten ueber Dateien und Kommandozeilenwerkzeuge.
// Faellt der zugehoerige Dienst aus, liefern viele dieser Werkzeuge
// trotzdem Daten (aus den Dateien auf der Platte) -- die Oberflaeche sieht
// dann gefuellt aus, zeigt aber einen Zustand, den der Dienst gar nicht
// kennt. Deshalb pruefen die Programme den Dienst aktiv und sagen es,
// statt stillschweigend Unvollstaendiges anzuzeigen.
//
// Header-only, damit jedes Programm seinen eigenen root-Aufruf
// (i2ksudo-Wrapper) mitgeben kann.
// ---------------------------------------------------------------------
#pragma once
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
#include <cctype>

namespace svcprobe {

// runner: fuehrt das Kommando als root aus und liefert Ausgabe + Rueckgabewert.
typedef std::function<int(const std::vector<std::string>&, std::string&)> Runner;

struct Result {
	bool ok = true;
	std::string detail;    // Ausgabe des fehlgeschlagenen Befehls
};

inline std::string trimmed(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

// Erfolg, wenn der Befehl 0 liefert und (falls angegeben) "needle" in der
// Ausgabe steht -- Gross-/Kleinschreibung egal.
inline Result probe(const Runner& run, const std::vector<std::string>& args, const std::string& needle = "") {
	Result r;
	std::string out;
	int rc = run(args, out);
	std::string lower = out;
	std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
	std::string needleLower = needle;
	std::transform(needleLower.begin(), needleLower.end(), needleLower.begin(), [](unsigned char c) { return std::tolower(c); });
	r.ok = (rc == 0) && (needle.empty() || lower.find(needleLower) != std::string::npos);
	if (!r.ok) r.detail = trimmed(out);
	return r;
}

// Läuft die systemd-Unit? (Ohne systemd gilt der Dienst als erreichbar --
// dann sagt die fachliche Probe, was Sache ist.)
inline Result unitActive(const Runner& run, const std::string& unit) {
	return probe(run, { "systemctl", "is-active", unit });
}

// Meldungstext im einheitlichen Wortlaut.
inline std::string message(const std::string& what, const std::string& unit, const std::string& detail) {
	std::string m = what + " ist nicht erreichbar. Die angezeigten Daten stammen aus den\n"
	                "Konfigurationsdateien und geben nicht wieder, was der Dienst tatsächlich verwendet.\n\n"
	                "Prüfen Sie, ob der Dienst läuft:\n    systemctl status " + unit + "\n";
	if (!detail.empty()) m += "\n" + detail;
	return m;
}

} // namespace svcprobe
