// dhcpmgr.cpp
//
// DHCP-Manager fuer ice2k -- Nachbau des Windows 2000 "DHCP"-MMC-Snapins.
// Liest/schreibt die Kea-DHCPv4-Konfiguration (/etc/kea/kea-dhcp4.conf)
// ueber Boost.JSON.
//
// Baut auf demselben Muster wie dnsmgr.cpp auf: FXTreeList links,
// Detailansicht rechts, MMC-Toolbar-Icons, Root-Rechte via i2ksudo.

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"

#include <boost/json.hpp>

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

namespace json = boost::json;

FXApp* app;
static bool g_haveRoot = false;
static const char* KEA_CONF = "/etc/kea/kea-dhcp4.conf";

// ---------------------------------------------------------------------
// Root-Rechte ueber i2ksudo -- identisches Muster wie in dnsmgr.cpp.
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

static bool writeFileAsRoot(const FXString& path, const std::string& content) {
	char tmpname[] = "/tmp/dhcpmgr_XXXXXX";
	int fd = mkstemp(tmpname);
	if (fd < 0) return false;
	FILE* f = fdopen(fd, "w");
	if (!f) { close(fd); unlink(tmpname); return false; }
	fwrite(content.data(), 1, content.size(), f);
	fclose(f);

	int rc = runAsRoot({ FXString("cp"), FXString(tmpname), path });
	unlink(tmpname);
	if (rc != 0) return false;
	runAsRoot({ FXString("chmod"), FXString("644"), path });
	return true;
}

// ---------------------------------------------------------------------
// Kea-Konfiguration lesen/schreiben ueber Boost.JSON.
// Keas Standard-Beispielkonfiguration enthaelt "//"-Kommentare, die
// striktes JSON (und damit Boost.JSON) nicht akzeptiert -- deshalb
// entfernen wir Zeilenkommentare vor dem Parsen (grob: alles nach
// einem "//" ausserhalb von Anfuehrungszeichen).
// ---------------------------------------------------------------------
static std::string stripJsonComments(const std::string& in) {
	std::string out;
	out.reserve(in.size());
	bool inString = false;
	for (size_t i = 0; i < in.size(); ++i) {
		if (!inString && i + 1 < in.size() && in[i] == '/' && in[i+1] == '/') {
			while (i < in.size() && in[i] != '\n') ++i;
			out += '\n';
			continue;
		}
		if (in[i] == '"' && (i == 0 || in[i-1] != '\\')) inString = !inString;
		out += in[i];
	}
	return out;
}

// Laedt die Kea-Konfiguration. Gibt bei Parse-Fehlern/leerer Config ein
// leeres json::object zurueck (Aufrufer prueft ueber isValidConfig()).
static json::value loadKeaConfig() {
	std::ifstream in(KEA_CONF);
	if (!in.is_open()) return json::object();
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();
	content = stripJsonComments(content);
	try {
		return json::parse(content);
	} catch (...) {
		return json::object();
	}
}

// Eine Kea-Config gilt fuer uns als "vorhanden", wenn sie mindestens
// eine subnet4-Zone (einen Bereich) definiert.
static bool isValidConfig(const json::value& v) {
	if (!v.is_object()) return false;
	auto* dhcp4 = v.as_object().if_contains("Dhcp4");
	if (!dhcp4 || !dhcp4->is_object()) return false;
	auto* subnets = dhcp4->as_object().if_contains("subnet4");
	return subnets && subnets->is_array() && !subnets->as_array().empty();
}

static bool saveKeaConfig(const json::value& v) {
	std::string content = json::serialize(v);
	return writeFileAsRoot(KEA_CONF, content);
}

// Startet kea-dhcp4-server neu, damit gespeicherte Aenderungen wirksam
// werden (Kea hat -- anders als BINDs "rndc reload" -- ohne den
// separaten Control-Agent keinen Live-Reload-Mechanismus). Gibt true
// zurueck, wenn der Neustart erfolgreich war; sonst false, damit der
// Aufrufer das dem Benutzer sichtbar zurueckmelden kann statt es
// stillschweigend zu verschlucken.
static bool restartKeaService() {
	return runAsRoot({ FXString("systemctl"), FXString("restart"), FXString("kea-dhcp4-server") }) == 0;
}

// ---------------------------------------------------------------------
// IP-Hilfsfunktionen
// ---------------------------------------------------------------------
static uint32_t ipToUint(const FXString& ip) {
	unsigned a=0,b=0,c=0,d=0;
	sscanf(ip.text(), "%u.%u.%u.%u", &a, &b, &c, &d);
	return (a << 24) | (b << 16) | (c << 8) | d;
}
static FXString uintToIp(uint32_t v) {
	char buf[32];
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF);
	return FXString(buf);
}
static int maskToPrefixLen(const FXString& mask) {
	uint32_t m = ipToUint(mask);
	int len = 0;
	for (int i = 31; i >= 0; --i) { if (m & (1u << i)) len++; else break; }
	return len;
}
static FXString computeSubnetCidr(const FXString& startIp, const FXString& mask) {
	uint32_t ip = ipToUint(startIp);
	int prefix = maskToPrefixLen(mask);
	uint32_t maskBits = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
	uint32_t network = ip & maskBits;
	return uintToIp(network) + "/" + FXString(std::to_string(prefix).c_str());
}

// ---------------------------------------------------------------------
// Datenmodell fuer einen Bereich (Scope), aus dem geparsten Kea-JSON
// ---------------------------------------------------------------------
struct PoolRange { FXString start, end; };
struct Reservation { FXString ip, mac, hostname; };
struct ScopeOption { FXString label, value; };

struct ScopeInfo {
	int id = 0;
	FXString subnetCidr;
	FXString name;         // aus "user-context"."name" (Kea kennt selbst keinen Bereichsnamen)
	FXString description;  // aus "user-context"."description"
	long validLifetime = 86400;
	std::vector<PoolRange> pools;       // tatsaechlich vergebbare Bloecke (nach Abzug der Ausschluesse)
	std::vector<PoolRange> exclusions;  // aus "user-context"."exclusions" -- Kea kennt den Begriff selbst nicht
	std::vector<Reservation> reservations;
	std::vector<ScopeOption> options;
};

static FXString jsonStr(const json::object& o, const char* key, const FXString& def = "") {
	auto* v = o.if_contains(key);
	if (!v || !v->is_string()) return def;
	return FXString(v->as_string().c_str());
}

// Wandelt Keas "pools"-Array ([{"pool":"a - b"}, ...]) in unser
// PoolRange-Vektor-Modell um -- und zurueck. Wird sowohl beim Parsen
// als auch beim Neuberechnen nach einem Ausschluss gebraucht.
static std::vector<PoolRange> jsonPoolsToVector(const json::array& poolsArr) {
	std::vector<PoolRange> out;
	for (auto& pv : poolsArr) {
		if (!pv.is_object()) continue;
		FXString poolStr = jsonStr(pv.as_object(), "pool");
		int dash = poolStr.find('-');
		PoolRange pr;
		if (dash >= 0) {
			pr.start = poolStr.left(dash).trim();
			pr.end = poolStr.mid(dash+1, poolStr.length()-dash-1).trim();
		} else {
			pr.start = pr.end = poolStr.trim();
		}
		out.push_back(pr);
	}
	return out;
}
static json::array poolsVectorToJson(const std::vector<PoolRange>& pools) {
	json::array arr;
	for (auto& p : pools) arr.push_back(json::object{ {"pool", (p.start + " - " + p.end).text()} });
	return arr;
}

// Zieht einen Ausschlussbereich von einer Liste von Pool-Bloecken ab --
// splittet einen Block in zwei, wenn der Ausschluss mittendrin liegt,
// kappt ihn an einem Rand, oder entfernt ihn ganz, wenn er den
// Ausschluss komplett umfasst (auch fuer den Sonderfall "eine einzelne
// Adresse ausschliessen", bei dem start == ende ist).
static std::vector<PoolRange> subtractExclusion(const std::vector<PoolRange>& pools, const PoolRange& excl) {
	std::vector<PoolRange> out;
	uint32_t exS = ipToUint(excl.start), exE = ipToUint(excl.end);
	for (auto& p : pools) {
		uint32_t pS = ipToUint(p.start), pE = ipToUint(p.end);
		if (exE < pS || exS > pE) { out.push_back(p); continue; } // keine Ueberschneidung
		if (exS > pS) out.push_back(PoolRange{ p.start, uintToIp(exS - 1) });
		if (exE < pE) out.push_back(PoolRange{ uintToIp(exE + 1), p.end });
		// liegt der Ausschluss genau ueber dem ganzen Block (exS<=pS && exE>=pE),
		// wird hier nichts angehaengt -- der Block faellt komplett weg.
	}
	return out;
}

// Fuegt einen zuvor ausgeschlossenen Bereich wieder in die Pool-Liste
// ein und verschmilzt angrenzende/ueberlappende Bloecke zu einem
// zusammenhaengenden Block -- das Gegenstueck zu subtractExclusion(),
// gebraucht beim Loeschen eines Ausschlussbereichs.
static std::vector<PoolRange> mergeBackRange(std::vector<PoolRange> pools, const PoolRange& toAdd) {
	pools.push_back(toAdd);
	std::sort(pools.begin(), pools.end(), [](const PoolRange& a, const PoolRange& b) {
		return ipToUint(a.start) < ipToUint(b.start);
	});
	std::vector<PoolRange> out;
	for (auto& p : pools) {
		if (!out.empty()) {
			uint32_t prevEnd = ipToUint(out.back().end);
			uint32_t curStart = ipToUint(p.start);
			if (curStart <= prevEnd + 1) {
				if (ipToUint(p.end) > prevEnd) out.back().end = p.end;
				continue;
			}
		}
		out.push_back(p);
	}
	return out;
}

static std::vector<ScopeInfo> parseScopes(const json::value& conf) {
	std::vector<ScopeInfo> scopes;
	if (!isValidConfig(conf)) return scopes;
	const auto& subnets = conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array();

	for (auto& sv : subnets) {
		if (!sv.is_object()) continue;
		const auto& so = sv.as_object();
		ScopeInfo sc;
		if (auto* id = so.if_contains("id")) sc.id = (int)id->to_number<int64_t>();
		sc.subnetCidr = jsonStr(so, "subnet");
		if (auto* uc = so.if_contains("user-context")) {
			if (uc->is_object()) {
				sc.name = jsonStr(uc->as_object(), "name", sc.subnetCidr);
				sc.description = jsonStr(uc->as_object(), "description");
				if (auto* excl = uc->as_object().if_contains("exclusions")) {
					if (excl->is_array()) {
						for (auto& ev : excl->as_array()) {
							if (!ev.is_object()) continue;
							PoolRange pr;
							pr.start = jsonStr(ev.as_object(), "start");
							pr.end = jsonStr(ev.as_object(), "end");
							sc.exclusions.push_back(pr);
						}
					}
				}
			}
		}
		if (sc.name.empty()) sc.name = sc.subnetCidr;
		if (auto* vl = so.if_contains("valid-lifetime")) sc.validLifetime = vl->to_number<int64_t>();

		if (auto* pools = so.if_contains("pools")) {
			if (pools->is_array()) sc.pools = jsonPoolsToVector(pools->as_array());
		}
		if (auto* res = so.if_contains("reservations")) {
			if (res->is_array()) {
				for (auto& rv : res->as_array()) {
					if (!rv.is_object()) continue;
					Reservation r;
					r.ip = jsonStr(rv.as_object(), "ip-address");
					r.mac = jsonStr(rv.as_object(), "hw-address");
					r.hostname = jsonStr(rv.as_object(), "hostname");
					sc.reservations.push_back(r);
				}
			}
		}

		ScopeOption lease;
		lease.label = "051 Verbindungsdauer";
		lease.value = FXString(std::to_string(sc.validLifetime).c_str()) + " s";
		sc.options.push_back(lease);

		if (auto* opts = so.if_contains("option-data")) {
			if (opts->is_array()) {
				for (auto& ov : opts->as_array()) {
					if (!ov.is_object()) continue;
					FXString oname = jsonStr(ov.as_object(), "name");
					FXString oval = jsonStr(ov.as_object(), "data");
					ScopeOption opt;
					if (oname == "routers") opt.label = "003 Router";
					else if (oname == "domain-name-servers") opt.label = "006 DNS-Server";
					else if (oname == "domain-name") opt.label = "015 Domänenname";
					else opt.label = oname;
					opt.value = oval;
					sc.options.push_back(opt);
				}
			}
		}
		scopes.push_back(sc);
	}
	return scopes;
}

// Parst /var/lib/kea/kea-leases4.csv (Memfile-Backend) fuer die Anzeige
// in "Adressleases". Reines Lesen, kein Schreibzugriff notwendig.
struct LeaseEntry { FXString ip, mac, hostname, expire; int subnetId = 0; };
static std::vector<LeaseEntry> parseLeases() {
	std::vector<LeaseEntry> leases;
	std::ifstream in("/var/lib/kea/kea-leases4.csv");
	if (!in.is_open()) return leases;
	std::string line;
	bool first = true;
	while (std::getline(in, line)) {
		if (first) { first = false; continue; } // Kopfzeile ueberspringen
		std::vector<std::string> cols;
		std::string cur;
		for (char c : line) {
			if (c == ',') { cols.push_back(cur); cur.clear(); }
			else cur += c;
		}
		cols.push_back(cur);
		// Spalten (Memfile v2): address,hwaddr,client_id,valid_lifetime,expire,
		// subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
		if (cols.size() < 9) continue;
		LeaseEntry le;
		le.ip = cols[0].c_str();
		le.mac = cols[1].c_str();
		le.expire = cols[4].c_str();
		le.subnetId = atoi(cols[5].c_str());
		le.hostname = cols[8].c_str();
		leases.push_back(le);
	}
	return leases;
}

// ---------------------------------------------------------------------
// Baut eine gueltige Kea-Grundkonfiguration (Skeleton) mit leerem
// subnet4-Array -- fuer den Fall, dass /etc/kea/kea-dhcp4.conf fehlt
// oder nur die unveraenderte, auskommentierte Beispieldatei ist.
// ---------------------------------------------------------------------
static json::value buildSkeletonConfig() {
	json::object dhcp4;
	dhcp4["interfaces-config"] = json::object{ {"interfaces", json::array{"*"}} };
	dhcp4["control-socket"] = json::object{
		{"socket-type", "unix"}, {"socket-name", "/run/kea/kea4-ctrl-socket"}
	};
	dhcp4["lease-database"] = json::object{
		{"type", "memfile"}, {"lfc-interval", 3600}
	};
	dhcp4["valid-lifetime"] = 86400;
	dhcp4["renew-timer"] = 43200;
	dhcp4["rebind-timer"] = 75600;
	dhcp4["subnet4"] = json::array{};

	json::object root;
	root["Dhcp4"] = dhcp4;
	return root;
}

static int nextFreeSubnetId(const json::value& conf) {
	int maxId = 0;
	if (isValidConfig(conf)) {
		for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
			if (sv.is_object()) {
				if (auto* id = sv.as_object().if_contains("id")) {
					int v = (int)id->to_number<int64_t>();
					if (v > maxId) maxId = v;
				}
			}
		}
	}
	return maxId + 1;
}

// Legt bei fehlender/ungueltiger Konfiguration automatisch einen
// Demo-Bereich an -- Netz basierend auf der aktuellen Maschine
// (analog zur Demo-Zone im DNS-Manager).
static bool seedDemoScopeOnDisk() {
	json::value conf = buildSkeletonConfig();

	json::object subnet;
	subnet["id"] = 1;
	subnet["subnet"] = "10.10.10.0/24";
	subnet["pools"] = json::array{ json::object{ {"pool", "10.10.10.100 - 10.10.10.200"} } };
	subnet["valid-lifetime"] = 86400;
	subnet["option-data"] = json::array{
		json::object{ {"name", "routers"}, {"data", "10.10.10.1"} },
		json::object{ {"name", "domain-name-servers"}, {"data", "10.10.10.91"} }
	};
	subnet["user-context"] = json::object{
		{"name", "Standardbereich"}, {"description", "Automatisch angelegter Demo-Bereich"}
	};
	subnet["reservations"] = json::array{};

	conf.as_object()["Dhcp4"].as_object()["subnet4"].as_array().push_back(subnet);

	bool ok = saveKeaConfig(conf);
	if (ok) restartKeaService();
	return ok;
}

// ---------------------------------------------------------------------
// Kleiner wiederverwendbarer 4-Oktett-IP-Eingabewidget-Helfer
// ---------------------------------------------------------------------
// Nachbau des klassischen Windows-IP-Adressfelds: springt automatisch
// zum naechsten Oktett weiter, sobald 3 Ziffern eingegeben wurden --
// genau wie im Original (z.B. beim Ausschluss-Dialog).
class IpQuad : public FXObject {
	FXDECLARE(IpQuad)
public:
	FXTextField *o1, *o2, *o3, *o4;
	enum { ID_O1 = 1, ID_O2, ID_O3 };

	long onOctetChanged(FXObject* sender, FXSelector, void*) {
		FXTextField* tf = (FXTextField*)sender;
		FXTextField* next = (tf == o1) ? o2 : (tf == o2) ? o3 : (tf == o3) ? o4 : NULL;
		if (next && tf->getText().length() >= 3) {
			next->setFocus();
			next->selectAll();
		}
		return 1;
	}

	void build(FXComposite* parent) {
		FXHorizontalFrame* f = new FXHorizontalFrame(parent, 0,0,0,0,0, 0,0,0,0, 1,1);
		o1 = new FXTextField(f, 3, this, ID_O1, FRAME_SUNKEN | JUSTIFY_CENTER_X); o1->setText("0");
		new FXLabel(f, ".");
		o2 = new FXTextField(f, 3, this, ID_O2, FRAME_SUNKEN | JUSTIFY_CENTER_X); o2->setText("0");
		new FXLabel(f, ".");
		o3 = new FXTextField(f, 3, this, ID_O3, FRAME_SUNKEN | JUSTIFY_CENTER_X); o3->setText("0");
		new FXLabel(f, ".");
		o4 = new FXTextField(f, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); o4->setText("0");
	}
	void set(const FXString& ip) {
		FXString c = ip;
		int d1 = c.find('.'), d2 = c.find('.', d1+1), d3 = c.find('.', d2+1);
		if (d1 > 0 && d2 > 0 && d3 > 0) {
			o1->setText(c.mid(0, d1));
			o2->setText(c.mid(d1+1, d2-d1-1));
			o3->setText(c.mid(d2+1, d3-d2-1));
			o4->setText(c.mid(d3+1, c.length()-d3-1));
		}
	}
	// Leert alle vier Felder -- fuer optionale Adressen (z.B. "Letzte
	// IP-Adresse" beim Ausschluss-Dialog, die im Original leer bleiben darf).
	void clear() { o1->setText(""); o2->setText(""); o3->setText(""); o4->setText(""); }
	FXbool isEmpty() const {
		return o1->getText().empty() && o2->getText().empty() && o3->getText().empty() && o4->getText().empty();
	}
	FXString get() const {
		return o1->getText() + "." + o2->getText() + "." + o3->getText() + "." + o4->getText();
	}
};
FXDEFMAP(IpQuad) IpQuadMap[] = {
	FXMAPFUNC(SEL_CHANGED, IpQuad::ID_O1, IpQuad::onOctetChanged),
	FXMAPFUNC(SEL_CHANGED, IpQuad::ID_O2, IpQuad::onOctetChanged),
	FXMAPFUNC(SEL_CHANGED, IpQuad::ID_O3, IpQuad::onOctetChanged),
};
FXIMPLEMENT(IpQuad, FXObject, IpQuadMap, ARRAYNUMBER(IpQuadMap))

// ---------------------------------------------------------------------
// Assistent "Neuer Bereich" -- Name/Beschreibung, Start-/End-IP,
// Subnetzmaske. Entspricht den Kernfeldern des Original-Assistenten
// (Aktivierung/DHCP-Optionen-Seite werden in diesem Prototyp beim
// Anlegen ausgelassen -- Optionen lassen sich danach ueber
// "Bereichsoptionen konfigurieren..." setzen).
// ---------------------------------------------------------------------
class NewScopeWizardDialog : public FXDialogBox {
	FXDECLARE(NewScopeWizardDialog)
private:
	FXTextField *nameField, *descField;
	IpQuad startIp, endIp, mask;
protected:
	NewScopeWizardDialog() {}
public:
	NewScopeWizardDialog(FXWindow* owner)
		: FXDialogBox(owner, "Assistent für neuen Bereich", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		new FXLabel(main, "Bereichsname:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Beschreibung:");
		descField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Start-IP-Adresse:");
		startIp.build(main);
		new FXLabel(main, "End-IP-Adresse:");
		endIp.build(main);
		new FXLabel(main, "Subnetzmaske:");
		mask.build(main);
		mask.set("255.255.255.0");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Fertig stellen", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getName() const { return nameField->getText(); }
	FXString getDescription() const { return descField->getText(); }
	FXString getStartIp() const { return startIp.get(); }
	FXString getEndIp() const { return endIp.get(); }
	FXString getMask() const { return mask.get(); }
	virtual ~NewScopeWizardDialog() {}
};
FXIMPLEMENT(NewScopeWizardDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" eines Bereichs -- reine Anzeige, angelehnt an
// den "Allgemein"-Tab der Original-Bereichseigenschaften.
// ---------------------------------------------------------------------
class ScopePropertiesDialog : public FXDialogBox {
	FXDECLARE(ScopePropertiesDialog)
protected:
	ScopePropertiesDialog() {}
public:
	ScopePropertiesDialog(FXWindow* owner, const ScopeInfo& sc)
		: FXDialogBox(owner, "Eigenschaften von " + sc.name, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,380,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		FXMatrix* grid = new FXMatrix(main, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 4,2);
		auto addRow = [&](const char* label, const FXString& value) {
			new FXLabel(grid, label);
			FXTextField* tf = new FXTextField(grid, 24, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
			tf->setText(value);
			tf->disable();
		};
		addRow("Bereichsname:", sc.name);
		addRow("Beschreibung:", sc.description);
		addRow("Netz:", sc.subnetCidr);
		if (!sc.pools.empty()) {
			addRow("Startadresse:", sc.pools[0].start);
			addRow("Endadresse:", sc.pools[0].end);
		}
		addRow("Verbindungsdauer:", FXString(std::to_string(sc.validLifetime).c_str()) + " s");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	virtual ~ScopePropertiesDialog() {}
};
FXIMPLEMENT(ScopePropertiesDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Bereichsoptionen konfigurieren" -- Router (003), DNS-Server
// (006), Domänenname (015), Verbindungsdauer. Klassisches OK/Abbrechen
// wie im Original (keine Add-Schleife -- das ist eine Eigenschaftenseite,
// kein Assistent).
// ---------------------------------------------------------------------
class ConfigureOptionsDialog : public FXDialogBox {
	FXDECLARE(ConfigureOptionsDialog)
private:
	FXTextField *routerField, *dnsField, *domainField, *leaseField;
protected:
	ConfigureOptionsDialog() {}
public:
	ConfigureOptionsDialog(FXWindow* owner, const FXString& scopeName, const FXString& router,
	                        const FXString& dns, const FXString& domain, long leaseSeconds)
		: FXDialogBox(owner, "Bereichsoptionen konfigurieren", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Bereichsoptionen für: " + scopeName);

		new FXLabel(main, "003 Router:");
		routerField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		routerField->setText(router);

		new FXLabel(main, "006 DNS-Server:");
		dnsField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		dnsField->setText(dns);

		new FXLabel(main, "015 Domänenname:");
		domainField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		domainField->setText(domain);

		new FXLabel(main, "051 Verbindungsdauer (Sekunden):");
		leaseField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		leaseField->setText(FXString(std::to_string(leaseSeconds).c_str()));

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getRouter() const { return routerField->getText().trim(); }
	FXString getDns() const { return dnsField->getText().trim(); }
	FXString getDomain() const { return domainField->getText().trim(); }
	long getLease() const { return atol(leaseField->getText().text()); }
	virtual ~ConfigureOptionsDialog() {}
};
FXIMPLEMENT(ConfigureOptionsDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Neue Reservierung" -- wie im Original: "Hinzufügen" legt die
// Reservierung sofort an und der Dialog bleibt fuer weitere offen,
// "Schließen" beendet.
// ---------------------------------------------------------------------
class DhcpManager; // vorwaertsdeklariert

class NewReservationDialog : public FXDialogBox {
	FXDECLARE(NewReservationDialog)
private:
	IpQuad ip;
	FXTextField *macField, *nameField;
	DhcpManager* mgr;
	int scopeIdx;
protected:
	NewReservationDialog() {}
public:
	enum { ID_ADDRES = FXDialogBox::ID_LAST };
	long onAddReservation(FXObject*, FXSelector, void*);

	NewReservationDialog(FXWindow* owner, DhcpManager* m, int sIdx, const FXString& scopeName)
		: FXDialogBox(owner, "Neue Reservierung", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,380,0, 0,0,0,0),
		  mgr(m), scopeIdx(sIdx) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Neue Reservierung in Bereich: " + scopeName);

		new FXLabel(main, "IP-Adresse:");
		ip.build(main);

		new FXLabel(main, "MAC-Adresse (z.B. aa:bb:cc:dd:ee:ff):");
		macField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Name:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Hinzufügen", NULL, this, ID_ADDRES,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Schließen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	void resetFields() { ip.set("0.0.0.0"); macField->setText(""); nameField->setText(""); macField->setFocus(); }
	virtual ~NewReservationDialog() {}
};
FXDEFMAP(NewReservationDialog) NewReservationDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewReservationDialog::ID_ADDRES, NewReservationDialog::onAddReservation),
};
FXIMPLEMENT(NewReservationDialog, FXDialogBox, NewReservationDialogMap, ARRAYNUMBER(NewReservationDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer bestehenden Reservierung -- klassisches
// OK/Abbrechen (kein Add-Schleifenmuster, das gibt es im Original nur
// beim Anlegen), vorbelegt mit den aktuellen Werten.
// ---------------------------------------------------------------------
class ReservationPropertiesDialog : public FXDialogBox {
	FXDECLARE(ReservationPropertiesDialog)
private:
	IpQuad ip;
	FXTextField *macField, *nameField;
protected:
	ReservationPropertiesDialog() {}
public:
	ReservationPropertiesDialog(FXWindow* owner, const FXString& scopeName, const Reservation& r)
		: FXDialogBox(owner, "Eigenschaften von " + r.ip, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,380,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Reservierung in Bereich: " + scopeName);

		new FXLabel(main, "IP-Adresse:");
		ip.build(main);
		ip.set(r.ip);

		new FXLabel(main, "MAC-Adresse:");
		macField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		macField->setText(r.mac);

		new FXLabel(main, "Name:");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		nameField->setText(r.hostname);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	FXString getIp() const { return ip.get(); }
	FXString getMac() const { return macField->getText().trim(); }
	FXString getName() const { return nameField->getText().trim(); }
	virtual ~ReservationPropertiesDialog() {}
};
FXIMPLEMENT(ReservationPropertiesDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Neuer Ausschlussbereich" -- entspricht dem Original: schliesst
// eine Teilspanne (auch eine einzelne Adresse, wenn Start == Ende) aus
// dem Adresspool aus. "Hinzufügen" wendet den Ausschluss sofort an und
// haelt den Dialog fuer weitere Ausschluesse offen, "Schließen" beendet.
// ---------------------------------------------------------------------
class NewExclusionDialog : public FXDialogBox {
	FXDECLARE(NewExclusionDialog)
private:
	IpQuad startIp, endIp;
	DhcpManager* mgr;
	int scopeIdx;
protected:
	NewExclusionDialog() {}
public:
	enum { ID_ADDEXCL = FXDialogBox::ID_LAST };
	long onAddExclusion(FXObject*, FXSelector, void*);

	NewExclusionDialog(FXWindow* owner, DhcpManager* m, int sIdx, const FXString& scopeName)
		: FXDialogBox(owner, "Ausschluss hinzufügen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0, 0,0,0,0),
		  mgr(m), scopeIdx(sIdx) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main,
			"Geben Sie den IP-Adressbereich an, den Sie ausschließen möchten.\n"
			"Wenn Sie eine einzelne IP-Adresse ausschließen möchten, geben Sie\n"
			"nur die Adresse in \"Erste IP-Adresse\" an.",
			NULL, JUSTIFY_LEFT);

		new FXLabel(main, "Erste IP-Adresse:");
		startIp.build(main);
		new FXLabel(main, "Letzte IP-Adresse:");
		endIp.build(main);
		endIp.clear(); // bleibt leer, bis der Benutzer eine echte Bereichsobergrenze eingibt

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Hinzufügen", NULL, this, ID_ADDEXCL,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Schließen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	void resetFields() { startIp.set("0.0.0.0"); endIp.clear(); }
	virtual ~NewExclusionDialog() {}
};
FXDEFMAP(NewExclusionDialog) NewExclusionDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewExclusionDialog::ID_ADDEXCL, NewExclusionDialog::onAddExclusion),
};
FXIMPLEMENT(NewExclusionDialog, FXDialogBox, NewExclusionDialogMap, ARRAYNUMBER(NewExclusionDialogMap))

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------

enum NodeKind { NK_NONE, NK_SCOPE, NK_POOL, NK_LEASES, NK_RESERVATIONS, NK_OPTIONS, NK_SERVEROPTIONS };

class DhcpManager : public FXMainWindow {
	FXDECLARE(DhcpManager)
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

	FXTreeItem *rootItem, *serverItem, *serverOptionsItem;
	std::vector<FXTreeItem*> scopeItems, poolItems, leaseItems, resItems, optItems;
	std::vector<ScopeOption> serverOptions; // globale Optionen, unabhaengig von einem Bereich
	std::vector<ScopeInfo> scopes;

	FXIcon *icoRoot, *icoServer, *icoFolder, *icoClock, *icoKey, *icoComputer;
	FXIcon *icoBack, *icoForward, *icoUp, *icoContree, *icoProperties, *icoRefresh, *icoHelp, *icoDelete;

	int contextScopeIdx;      // Bereich, auf dem das Kontextmenue geoeffnet wurde
	NodeKind currentNodeKind; // Art des aktuell in der Liste angezeigten Knotens
	int currentScopeForList;  // zugehoeriger Bereichs-Index fuer die Liste
	FXString contextExclStart, contextExclEnd; // fuer "Ausschlussbereich loeschen" gemerkt
	FXString contextResIp, contextResMac;      // fuer Reservierung Eigenschaften/Loeschen gemerkt

protected:
	DhcpManager() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_REFRESH, ID_ABOUT, ID_NEWSCOPE,
	       ID_NEWRESERVATION, ID_CONFIGOPTIONS, ID_DELETESCOPE, ID_SCOPEPROPS, ID_NEWEXCLUSION,
	       ID_DELETEEXCLUSION, ID_RESPROPS, ID_DELETERESERVATION, ID_SERVEROPTIONS };

	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	long onNewScope(FXObject*, FXSelector, void*);
	long onNewReservation(FXObject*, FXSelector, void*);
	long onNewExclusion(FXObject*, FXSelector, void*);
	long onDeleteExclusion(FXObject*, FXSelector, void*);
	long onReservationProperties(FXObject*, FXSelector, void*);
	long onDeleteReservation(FXObject*, FXSelector, void*);
	long onConfigureOptions(FXObject*, FXSelector, void*);
	long onServerOptions(FXObject*, FXSelector, void*);
	long onDeleteScope(FXObject*, FXSelector, void*);
	long onScopeProperties(FXObject*, FXSelector, void*);

	DhcpManager(FXApp* a);
	void loadScopes();
	void showListFor(NodeKind kind, int scopeIdx);
	bool createReservation(int scopeIdx, const FXString& ip, const FXString& mac, const FXString& hostname, FXString& errorMsg);
	bool updateReservation(int scopeIdx, const FXString& oldIp, const FXString& oldMac, const FXString& newIp, const FXString& newMac, const FXString& newName, FXString& errorMsg);
	bool deleteReservationEntry(int scopeIdx, const FXString& ip, const FXString& mac, FXString& errorMsg);
	bool createExclusion(int scopeIdx, const FXString& start, const FXString& end, FXString& errorMsg);
	bool deleteExclusion(int scopeIdx, const FXString& start, const FXString& end, FXString& errorMsg);
	virtual void create();
	virtual ~DhcpManager() {}
};

FXDEFMAP(DhcpManager) DhcpManagerMap[] = {
	FXMAPFUNC(SEL_CHANGED, DhcpManager::ID_TREE, DhcpManager::onTreeChanged),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, DhcpManager::ID_TREE, DhcpManager::onTreeRightClick),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, DhcpManager::ID_LIST, DhcpManager::onListRightClick),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_REFRESH, DhcpManager::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_ABOUT, DhcpManager::onAbout),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_NEWSCOPE, DhcpManager::onNewScope),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_NEWRESERVATION, DhcpManager::onNewReservation),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_NEWEXCLUSION, DhcpManager::onNewExclusion),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_DELETEEXCLUSION, DhcpManager::onDeleteExclusion),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_RESPROPS, DhcpManager::onReservationProperties),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_DELETERESERVATION, DhcpManager::onDeleteReservation),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_CONFIGOPTIONS, DhcpManager::onConfigureOptions),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_SERVEROPTIONS, DhcpManager::onServerOptions),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_DELETESCOPE, DhcpManager::onDeleteScope),
	FXMAPFUNC(SEL_COMMAND, DhcpManager::ID_SCOPEPROPS, DhcpManager::onScopeProperties),
};
FXIMPLEMENT(DhcpManager, FXMainWindow, DhcpManagerMap, ARRAYNUMBER(DhcpManagerMap))

static void setListColumns(FXIconList* list, std::vector<std::pair<FXString,int>> cols) {
	while (list->getNumHeaders() > 0) list->removeHeader(0);
	for (auto& c : cols) list->appendHeader(c.first, NULL, c.second);
}

DhcpManager::DhcpManager(FXApp* a)
	: FXMainWindow(a, "DHCP", NULL, NULL, DECOR_ALL, 0, 0, 800, 480, 0,0,0,0,0,0),
	  contextScopeIdx(-1), currentNodeKind(NK_NONE), currentScopeForList(-1) {

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

	splitter = new FXSplitter(this, LAYOUT_FILL_X|LAYOUT_FILL_Y|SPLITTER_TRACKING);

	FXPacker* treeframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y, 0,0,270,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                       SCROLLERS_DONT_TRACK|FRAME_NORMAL|LAYOUT_FILL_X|LAYOUT_FILL_Y|
	                       TREELIST_SHOWS_BOXES|TREELIST_SHOWS_LINES|TREELIST_BROWSESELECT|TREELIST_ROOT_BOXES);

	FXPacker* listframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y|LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(listframe, this, ID_LIST,
	                       ICONLIST_DETAILED|ICONLIST_BROWSESELECT|LAYOUT_FILL_X|LAYOUT_FILL_Y|FRAME_NORMAL);

	icoRoot = new FXPNGIcon(getApp(), resico_network, IMAGE_NEAREST); icoRoot->create();
	icoServer = new FXPNGIcon(getApp(), resico_server, IMAGE_NEAREST); icoServer->create();
	icoFolder = new FXPNGIcon(getApp(), resico_folder, IMAGE_NEAREST); icoFolder->create();
	icoClock = new FXPNGIcon(getApp(), resico_clock, IMAGE_NEAREST); icoClock->create();
	icoKey = new FXPNGIcon(getApp(), resico_key, IMAGE_NEAREST); icoKey->create();
	icoComputer = new FXPNGIcon(getApp(), resico_computer, IMAGE_NEAREST); icoComputer->create();

	char hostname[256];
	gethostname(hostname, sizeof(hostname));

	rootItem = tree->appendItem(0, "DHCP", icoRoot, icoRoot);
	serverItem = tree->appendItem(rootItem, hostname, icoServer, icoServer);
	tree->expandTree(rootItem);
	tree->expandTree(serverItem);

	loadScopes();
}

void DhcpManager::loadScopes() {
	FXTreeItem* loop = serverItem->getFirst();
	while (loop) { FXTreeItem* n = loop->getNext(); tree->removeItem(loop); loop = n; }

	json::value conf = loadKeaConfig();
	if (g_haveRoot && !isValidConfig(conf)) {
		if (seedDemoScopeOnDisk()) {
			statuslbl->setText("Keine Konfiguration gefunden -- Demo-Bereich nach /etc/kea/ geschrieben.");
			conf = loadKeaConfig();
		} else {
			statuslbl->setText("Demo-Bereich konnte nicht nach /etc/kea/ geschrieben werden.");
		}
	}

	scopes = parseScopes(conf);
	scopeItems.clear(); poolItems.clear(); leaseItems.clear(); resItems.clear(); optItems.clear();

	if (scopes.empty() && !g_haveRoot) {
		statuslbl->setText("Keine Root-Rechte -- keine Bereiche geladen (nichts wird geschrieben).");
	}

	std::vector<LeaseEntry> allLeases = parseLeases();

	for (auto& sc : scopes) {
		FXString label = "Bereich [" + sc.subnetCidr + "] " + sc.name;
		FXTreeItem* scopeItem = tree->appendItem(serverItem, label, icoFolder, icoFolder);
		FXTreeItem* poolItem = tree->appendItem(scopeItem, "Adresspool", icoFolder, icoFolder);
		FXTreeItem* leaseItem = tree->appendItem(scopeItem, "Adressleases", icoClock, icoClock);
		FXTreeItem* resItem = tree->appendItem(scopeItem, "Reservierungen", icoKey, icoKey);
		FXTreeItem* optItem = tree->appendItem(scopeItem, "Bereichsoptionen", icoFolder, icoFolder);
		scopeItems.push_back(scopeItem);
		poolItems.push_back(poolItem);
		leaseItems.push_back(leaseItem);
		resItems.push_back(resItem);
		optItems.push_back(optItem);
	}

	// "Serveroptionen" -- gleichrangig neben den Bereichen, fuer globale
	// Optionen (Dhcp4-Ebene, oberhalb aller Bereiche), genau wie im Original.
	serverOptions.clear();
	long globalLease = 86400;
	if (isValidConfig(conf)) {
		auto& dhcp4 = conf.as_object().at("Dhcp4").as_object();
		if (auto* vl = dhcp4.if_contains("valid-lifetime")) globalLease = vl->to_number<int64_t>();
		ScopeOption lease;
		lease.label = "051 Verbindungsdauer";
		lease.value = FXString(std::to_string(globalLease).c_str()) + " s";
		serverOptions.push_back(lease);
		if (auto* opts = dhcp4.if_contains("option-data")) {
			if (opts->is_array()) {
				for (auto& ov : opts->as_array()) {
					if (!ov.is_object()) continue;
					FXString oname = jsonStr(ov.as_object(), "name");
					FXString oval = jsonStr(ov.as_object(), "data");
					ScopeOption opt;
					if (oname == "routers") opt.label = "003 Router";
					else if (oname == "domain-name-servers") opt.label = "006 DNS-Server";
					else if (oname == "domain-name") opt.label = "015 Domänenname";
					else opt.label = oname;
					opt.value = oval;
					serverOptions.push_back(opt);
				}
			}
		}
	}
	serverOptionsItem = tree->appendItem(serverItem, "Serveroptionen", icoFolder, icoFolder);

	tree->expandTree(serverItem);

	// Leases den jeweiligen Bereichen zuordnen (fuer showListFor)
	// -- wir speichern sie einfach in einer statischen Kopie pro Aufruf,
	// da sich die Zuordnung ueber subnetId in showListFor ergibt.
	(void)allLeases;
}

void DhcpManager::showListFor(NodeKind kind, int scopeIdx) {
	list->clearItems();
	currentNodeKind = kind;
	currentScopeForList = scopeIdx;

	if (kind == NK_SERVEROPTIONS) {
		setListColumns(list, { {"Option", 200}, {"Wert", 260} });
		for (auto& o : serverOptions) {
			FXString txt = o.label + "\t" + o.value;
			list->appendItem(txt, icoFolder, icoFolder);
		}
		return;
	}

	if (scopeIdx < 0 || scopeIdx >= (int)scopes.size()) { setListColumns(list, {}); return; }
	ScopeInfo& sc = scopes[scopeIdx];

	if (kind == NK_POOL) {
		setListColumns(list, { {"Startadresse", 160}, {"Endadresse", 160}, {"Beschreibung", 220} });
		for (auto& p : sc.pools) {
			FXString txt = p.start + "\t" + p.end + "\tAdressbereich für Verteilung";
			list->appendItem(txt, icoComputer, icoComputer);
		}
		for (auto& e : sc.exclusions) {
			FXString txt = e.start + "\t" + e.end + "\tAdressbereich für Ausschluss";
			list->appendItem(txt, icoDelete, icoDelete);
		}
	} else if (kind == NK_LEASES) {
		setListColumns(list, { {"IP-Adresse", 140}, {"MAC-Adresse", 140}, {"Hostname", 140}, {"Ablauf (Unixzeit)", 140} });
		for (auto& le : parseLeases()) {
			if (le.subnetId != sc.id) continue;
			FXString txt = le.ip + "\t" + le.mac + "\t" + le.hostname + "\t" + le.expire;
			list->appendItem(txt, icoClock, icoClock);
		}
	} else if (kind == NK_RESERVATIONS) {
		setListColumns(list, { {"IP-Adresse", 140}, {"MAC-Adresse", 140}, {"Name", 180} });
		for (auto& r : sc.reservations) {
			FXString txt = r.ip + "\t" + r.mac + "\t" + r.hostname;
			list->appendItem(txt, icoKey, icoKey);
		}
	} else if (kind == NK_OPTIONS) {
		setListColumns(list, { {"Option", 200}, {"Wert", 260} });
		for (auto& o : sc.options) {
			FXString txt = o.label + "\t" + o.value;
			list->appendItem(txt, icoFolder, icoFolder);
		}
	} else {
		setListColumns(list, {});
	}
}

long DhcpManager::onTreeChanged(FXObject*, FXSelector, void*) {
	FXTreeItem* cur = tree->getCurrentItem();
	if (!cur) return 1;
	if (cur == serverOptionsItem) { showListFor(NK_SERVEROPTIONS, -1); return 1; }
	for (size_t i = 0; i < scopeItems.size(); ++i) {
		if (poolItems[i] == cur) { showListFor(NK_POOL, (int)i); return 1; }
		if (leaseItems[i] == cur) { showListFor(NK_LEASES, (int)i); return 1; }
		if (resItems[i] == cur) { showListFor(NK_RESERVATIONS, (int)i); return 1; }
		if (optItems[i] == cur) { showListFor(NK_OPTIONS, (int)i); return 1; }
		if (scopeItems[i] == cur) { list->clearItems(); setListColumns(list, {}); currentNodeKind = NK_SCOPE; currentScopeForList = (int)i; return 1; }
	}
	list->clearItems();
	setListColumns(list, {});
	currentNodeKind = NK_NONE;
	return 1;
}

long DhcpManager::onTreeRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);

	contextScopeIdx = -1;
	for (size_t i = 0; i < scopeItems.size(); ++i) if (scopeItems[i] == item) contextScopeIdx = (int)i;

	FXMenuPane menu(this);
	if (item == serverItem) {
		new FXMenuCommand(&menu, "&Neuer Bereich...", NULL, this, ID_NEWSCOPE);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	} else if (item == serverOptionsItem) {
		new FXMenuCommand(&menu, "&Serveroptionen konfigurieren...", NULL, this, ID_SERVEROPTIONS);
	} else if (contextScopeIdx >= 0) {
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
		new FXMenuCommand(&menu, "E&igenschaften", NULL, this, ID_SCOPEPROPS);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETESCOPE);
	} else {
		// Unter-Knoten eines Bereichs (Adresspool/Reservierungen/Bereichsoptionen) finden
		int scopeIdx = -1; NodeKind kind = NK_NONE;
		for (size_t i = 0; i < scopeItems.size(); ++i) {
			if (poolItems[i] == item) { scopeIdx = (int)i; kind = NK_POOL; }
			else if (resItems[i] == item) { scopeIdx = (int)i; kind = NK_RESERVATIONS; }
			else if (optItems[i] == item) { scopeIdx = (int)i; kind = NK_OPTIONS; }
		}
		if (scopeIdx < 0) return 1;
		contextScopeIdx = scopeIdx;
		if (kind == NK_POOL) new FXMenuCommand(&menu, "&Neuer Ausschlussbereich...", NULL, this, ID_NEWEXCLUSION);
		else if (kind == NK_RESERVATIONS) new FXMenuCommand(&menu, "&Neue Reservierung...", NULL, this, ID_NEWRESERVATION);
		else if (kind == NK_OPTIONS) new FXMenuCommand(&menu, "&Bereichsoptionen konfigurieren...", NULL, this, ID_CONFIGOPTIONS);
		else return 1;
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DhcpManager::onListRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	if (currentScopeForList < 0) return 1;
	if (currentNodeKind != NK_POOL && currentNodeKind != NK_RESERVATIONS) return 1;

	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx < 0) return 1;
	list->setCurrentItem(idx);
	list->selectItem(idx);

	FXString txt = list->getItemText(idx);
	int t1 = txt.find('\t');
	int t2 = txt.find('\t', t1 + 1);
	if (t1 < 0 || t2 < 0) return 1;
	FXString col1 = txt.left(t1);
	FXString col2 = txt.mid(t1 + 1, t2 - t1 - 1);
	FXString col3 = txt.mid(t2 + 1, txt.length() - t2 - 1);

	FXMenuPane menu(this);
	contextScopeIdx = currentScopeForList;

	if (currentNodeKind == NK_POOL) {
		if (col3 != "Adressbereich für Ausschluss") return 1; // Adresspool-Bloecke selbst sind nicht direkt loeschbar
		contextExclStart = col1;
		contextExclEnd = col2;
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETEEXCLUSION);
	} else { // NK_RESERVATIONS: Spalten sind IP-Adresse, MAC-Adresse, Name
		contextResIp = col1;
		contextResMac = col2;
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_RESPROPS);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETERESERVATION);
	}

	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DhcpManager::onRefresh(FXObject*, FXSelector, void*) {
	list->clearItems();
	setListColumns(list, {});
	loadScopes();
	statuslbl->setText("Aktualisiert.");
	return 1;
}

long DhcpManager::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Über DHCP",
		"DHCP-Manager für ice2k\n\n"
		"Ein Nachbau des Windows 2000 DHCP-Manager-Snapins.\n"
		"Liest/schreibt die Kea-DHCPv4-Konfiguration unter /etc/kea/.");
	return 1;
}

long DhcpManager::onNewScope(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte",
			"Ohne Root-Rechte kann kein neuer Bereich angelegt werden.\n"
			"Starte den DHCP-Manager neu und gib dein Passwort ein.");
		return 1;
	}

	NewScopeWizardDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	FXString name = dlg.getName().trim();
	if (name.empty()) name = "Neuer Bereich";
	FXString desc = dlg.getDescription();
	FXString startIp = dlg.getStartIp();
	FXString endIp = dlg.getEndIp();
	FXString mask = dlg.getMask();

	// Absicherung gegen das leere/unausgefuellte Formular (alle Oktett-Felder
	// stehen standardmaessig auf 0): ohne diese Pruefung entsteht sonst
	// unbemerkt ein sinnloser Bereich "0.0.0.0/24".
	if (ipToUint(startIp) == 0 || ipToUint(endIp) == 0) {
		FXMessageBox::error(this, MBOX_OK, "Ungültige Adressen",
			"Bitte eine echte Start- und End-IP-Adresse angeben (nicht 0.0.0.0).");
		return 1;
	}
	if (ipToUint(startIp) > ipToUint(endIp)) {
		FXMessageBox::error(this, MBOX_OK, "Ungültiger Bereich",
			"Die Start-IP-Adresse muss vor (oder gleich) der End-IP-Adresse liegen.");
		return 1;
	}
	{
		uint32_t maskBits = (maskToPrefixLen(mask) == 0) ? 0 : (0xFFFFFFFFu << (32 - maskToPrefixLen(mask)));
		if ((ipToUint(startIp) & maskBits) != (ipToUint(endIp) & maskBits)) {
			FXMessageBox::error(this, MBOX_OK, "Ungültiger Bereich",
				"Start- und End-IP-Adresse müssen im selben Subnetz liegen (passend zur Subnetzmaske).");
			return 1;
		}
	}

	FXString cidr = computeSubnetCidr(startIp, mask);

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) conf = buildSkeletonConfig();

	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (sv.is_object() && jsonStr(sv.as_object(), "subnet") == cidr) {
			FXMessageBox::error(this, MBOX_OK, "Bereich existiert bereits",
				"Ein Bereich für das Netz \"%s\" ist schon vorhanden.", cidr.text());
			return 1;
		}
	}

	json::object subnet;
	subnet["id"] = nextFreeSubnetId(conf);
	subnet["subnet"] = cidr.text();
	subnet["pools"] = json::array{ json::object{ {"pool", (startIp + " - " + endIp).text()} } };
	subnet["valid-lifetime"] = 86400;
	subnet["option-data"] = json::array{};
	subnet["reservations"] = json::array{};
	subnet["user-context"] = json::object{ {"name", name.text()}, {"description", desc.text()} };

	conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array().push_back(subnet);

	if (saveKeaConfig(conf)) {
		bool restarted = restartKeaService();
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Bereich " + name + " (" + cidr + ") angelegt."
			+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	} else {
		statuslbl->setText("Fehler beim Anlegen des Bereichs " + name + ".");
	}
	return 1;
}

long DhcpManager::onScopeProperties(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	ScopePropertiesDialog dlg(this, scopes[contextScopeIdx]);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DhcpManager::onDeleteScope(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	ScopeInfo sc = scopes[contextScopeIdx];

	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Bereich gelöscht werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Bereich löschen",
	        "Bereich \"%s\" (%s) wirklich löschen?", sc.name.text(), sc.subnetCidr.text())
	        != MBOX_CLICKED_YES) {
		return 1;
	}

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) return 1;
	auto& arr = conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array();
	for (size_t i = 0; i < arr.size(); ++i) {
		if (arr[i].is_object() && jsonStr(arr[i].as_object(), "subnet") == sc.subnetCidr) {
			arr.erase(arr.begin() + i);
			break;
		}
	}

	if (saveKeaConfig(conf)) {
		bool restarted = restartKeaService();
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Bereich " + sc.name + " gelöscht."
			+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	} else {
		statuslbl->setText("Fehler beim Löschen des Bereichs " + sc.name + ".");
	}
	return 1;
}

long DhcpManager::onNewReservation(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann keine Reservierung angelegt werden.");
		return 1;
	}
	NewReservationDialog dlg(this, this, contextScopeIdx, scopes[contextScopeIdx].name);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DhcpManager::onReservationProperties(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	Reservation* found = NULL;
	for (auto& r : scopes[contextScopeIdx].reservations) {
		if (r.ip == contextResIp && r.mac == contextResMac) { found = &r; break; }
	}
	if (!found) return 1;
	FXString scopeName = scopes[contextScopeIdx].name;

	ReservationPropertiesDialog dlg(this, scopeName, *found);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts geändert werden.");
		return 1;
	}

	FXString errorMsg;
	if (!updateReservation(contextScopeIdx, contextResIp, contextResMac, dlg.getIp(), dlg.getMac(), dlg.getName(), errorMsg)) {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long DhcpManager::onDeleteReservation(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts gelöscht werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen",
	        "Reservierung \"%s\" wirklich löschen?", contextResIp.text()) != MBOX_CLICKED_YES) {
		return 1;
	}
	FXString errorMsg;
	if (!deleteReservationEntry(contextScopeIdx, contextResIp, contextResMac, errorMsg)) {
		statuslbl->setText(errorMsg);
	}
	return 1;
}

long DhcpManager::onNewExclusion(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Ausschlussbereich angelegt werden.");
		return 1;
	}
	NewExclusionDialog dlg(this, this, contextScopeIdx, scopes[contextScopeIdx].name);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DhcpManager::onDeleteExclusion(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts gelöscht werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen",
	        "Ausschlussbereich \"%s - %s\" wirklich löschen?", contextExclStart.text(), contextExclEnd.text())
	        != MBOX_CLICKED_YES) {
		return 1;
	}
	FXString errorMsg;
	if (!deleteExclusion(contextScopeIdx, contextExclStart, contextExclEnd, errorMsg)) {
		statuslbl->setText(errorMsg);
	}
	return 1;
}

long DhcpManager::onConfigureOptions(FXObject*, FXSelector, void*) {
	if (contextScopeIdx < 0 || contextScopeIdx >= (int)scopes.size()) return 1;
	ScopeInfo& sc = scopes[contextScopeIdx];
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können keine Optionen gesetzt werden.");
		return 1;
	}

	FXString router, dns, domain;
	for (auto& o : sc.options) {
		if (o.label == "003 Router") router = o.value;
		else if (o.label == "006 DNS-Server") dns = o.value;
		else if (o.label == "015 Domänenname") domain = o.value;
	}
	// Vor dem Speichern in lokale Kopien sichern: onRefresh() unten baut
	// den "scopes"-Vektor neu auf, danach waere die Referenz "sc" ungueltig.
	FXString scopeName = sc.name;
	FXString scopeCidr = sc.subnetCidr;

	ConfigureOptionsDialog dlg(this, scopeName, router, dns, domain, sc.validLifetime);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) return 1;
	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (!sv.is_object() || jsonStr(sv.as_object(), "subnet") != scopeCidr) continue;

		json::array opts;
		FXString newRouter = dlg.getRouter();
		FXString newDns = dlg.getDns();
		FXString newDomain = dlg.getDomain();
		if (!newRouter.empty()) opts.push_back(json::object{ {"name","routers"}, {"data", newRouter.text()} });
		if (!newDns.empty()) opts.push_back(json::object{ {"name","domain-name-servers"}, {"data", newDns.text()} });
		if (!newDomain.empty()) opts.push_back(json::object{ {"name","domain-name"}, {"data", newDomain.text()} });
		sv.as_object()["option-data"] = opts;
		sv.as_object()["valid-lifetime"] = dlg.getLease();
		break;
	}

	if (saveKeaConfig(conf)) {
		bool restarted = restartKeaService();
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Bereichsoptionen für " + scopeName + " aktualisiert."
			+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	} else {
		statuslbl->setText("Fehler beim Speichern der Bereichsoptionen.");
	}
	return 1;
}

long DhcpManager::onServerOptions(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte können keine Optionen gesetzt werden.");
		return 1;
	}

	FXString router, dns, domain;
	long lease = 86400;
	for (auto& o : serverOptions) {
		if (o.label == "003 Router") router = o.value;
		else if (o.label == "006 DNS-Server") dns = o.value;
		else if (o.label == "015 Domänenname") domain = o.value;
		else if (o.label == "051 Verbindungsdauer") lease = atol(o.value.text());
	}

	ConfigureOptionsDialog dlg(this, "Server (alle Bereiche)", router, dns, domain, lease);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) conf = buildSkeletonConfig();
	auto& dhcp4 = conf.as_object().at("Dhcp4").as_object();

	json::array opts;
	FXString newRouter = dlg.getRouter();
	FXString newDns = dlg.getDns();
	FXString newDomain = dlg.getDomain();
	if (!newRouter.empty()) opts.push_back(json::object{ {"name","routers"}, {"data", newRouter.text()} });
	if (!newDns.empty()) opts.push_back(json::object{ {"name","domain-name-servers"}, {"data", newDns.text()} });
	if (!newDomain.empty()) opts.push_back(json::object{ {"name","domain-name"}, {"data", newDomain.text()} });
	dhcp4["option-data"] = opts;
	dhcp4["valid-lifetime"] = dlg.getLease();

	if (saveKeaConfig(conf)) {
		bool restarted = restartKeaService();
		onRefresh(NULL, 0, NULL);
		statuslbl->setText(FXString("Serveroptionen aktualisiert.")
			+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	} else {
		statuslbl->setText("Fehler beim Speichern der Serveroptionen.");
	}
	return 1;
}

// Fuegt eine Reservierung zu scopes[scopeIdx] hinzu. Aufgerufen von
// NewReservationDialog::onAddReservation.
bool DhcpManager::createReservation(int scopeIdx, const FXString& ip, const FXString& mac, const FXString& hostname, FXString& errorMsg) {
	if (scopeIdx < 0 || scopeIdx >= (int)scopes.size()) { errorMsg = "Ungültiger Bereich."; return false; }
	FXString cidr = scopes[scopeIdx].subnetCidr;

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) { errorMsg = "Konfiguration nicht gefunden."; return false; }

	bool found = false;
	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (!sv.is_object() || jsonStr(sv.as_object(), "subnet") != cidr) continue;
		found = true;
		json::array* resArr;
		if (!sv.as_object().if_contains("reservations") || !sv.as_object().at("reservations").is_array()) {
			sv.as_object()["reservations"] = json::array{};
		}
		resArr = &sv.as_object().at("reservations").as_array();
		resArr->push_back(json::object{
			{"hw-address", mac.text()}, {"ip-address", ip.text()}, {"hostname", hostname.text()}
		});
		break;
	}
	if (!found) { errorMsg = "Bereich nicht gefunden."; return false; }

	if (!saveKeaConfig(conf)) { errorMsg = "Fehler beim Schreiben der Konfiguration."; return false; }
	bool restarted = restartKeaService();
	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Reservierung " + ip + " (" + hostname + ") angelegt."
		+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	return true;
}

// Legt einen Ausschlussbereich zu scopes[scopeIdx] an: berechnet die
// verbleibenden Adresspool-Bloecke neu (subtractExclusion) und merkt
// den Ausschluss zusaetzlich in user-context.exclusions vor, damit er
// beim naechsten Laden wieder als eigene Zeile ("Ausschlussbereich")
// angezeigt werden kann. Aufgerufen von NewExclusionDialog::onAddExclusion.
bool DhcpManager::createExclusion(int scopeIdx, const FXString& startIn, const FXString& endIn, FXString& errorMsg) {
	if (scopeIdx < 0 || scopeIdx >= (int)scopes.size()) { errorMsg = "Ungültiger Bereich."; return false; }
	FXString cidr = scopes[scopeIdx].subnetCidr;

	FXString start = startIn, end = endIn;
	if (ipToUint(start) > ipToUint(end)) std::swap(start, end); // Start/Ende ggf. tauschen

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) { errorMsg = "Konfiguration nicht gefunden."; return false; }

	bool found = false;
	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (!sv.is_object() || jsonStr(sv.as_object(), "subnet") != cidr) continue;
		found = true;

		std::vector<PoolRange> curPools;
		if (auto* p = sv.as_object().if_contains("pools")) {
			if (p->is_array()) curPools = jsonPoolsToVector(p->as_array());
		}

		// Pruefen, ob der Ausschluss ueberhaupt innerhalb eines vorhandenen
		// Adresspool-Blocks liegt -- sonst waere er wirkungslos.
		uint32_t exS = ipToUint(start), exE = ipToUint(end);
		bool overlaps = false;
		for (auto& p : curPools) {
			if (exE >= ipToUint(p.start) && exS <= ipToUint(p.end)) { overlaps = true; break; }
		}
		if (!overlaps) {
			errorMsg = "Der Ausschlussbereich liegt außerhalb des Adresspools.";
			return false;
		}

		std::vector<PoolRange> newPools = subtractExclusion(curPools, PoolRange{ start, end });
		sv.as_object()["pools"] = poolsVectorToJson(newPools);

		if (!sv.as_object().if_contains("user-context") || !sv.as_object().at("user-context").is_object()) {
			sv.as_object()["user-context"] = json::object{};
		}
		auto& uc = sv.as_object().at("user-context").as_object();
		if (!uc.if_contains("exclusions") || !uc.at("exclusions").is_array()) {
			uc["exclusions"] = json::array{};
		}
		uc.at("exclusions").as_array().push_back(json::object{ {"start", start.text()}, {"end", end.text()} });
		break;
	}
	if (!found) { errorMsg = "Bereich nicht gefunden."; return false; }

	if (!saveKeaConfig(conf)) { errorMsg = "Fehler beim Schreiben der Konfiguration."; return false; }
	bool restarted = restartKeaService();
	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Ausschlussbereich " + start + " - " + end + " angelegt."
		+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	return true;
}

// Entfernt einen zuvor angelegten Ausschlussbereich wieder: fuegt die
// Spanne per mergeBackRange() in die Pool-Liste zurueck (verschmilzt
// sie mit angrenzenden Bloecken) und entfernt den passenden Eintrag
// aus user-context.exclusions.
bool DhcpManager::deleteExclusion(int scopeIdx, const FXString& start, const FXString& end, FXString& errorMsg) {
	if (scopeIdx < 0 || scopeIdx >= (int)scopes.size()) { errorMsg = "Ungültiger Bereich."; return false; }
	FXString cidr = scopes[scopeIdx].subnetCidr;

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) { errorMsg = "Konfiguration nicht gefunden."; return false; }

	bool found = false;
	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (!sv.is_object() || jsonStr(sv.as_object(), "subnet") != cidr) continue;
		found = true;

		std::vector<PoolRange> curPools;
		if (auto* p = sv.as_object().if_contains("pools")) {
			if (p->is_array()) curPools = jsonPoolsToVector(p->as_array());
		}
		std::vector<PoolRange> newPools = mergeBackRange(curPools, PoolRange{ start, end });
		sv.as_object()["pools"] = poolsVectorToJson(newPools);

		if (sv.as_object().if_contains("user-context") && sv.as_object().at("user-context").is_object()) {
			auto& uc = sv.as_object().at("user-context").as_object();
			if (uc.if_contains("exclusions") && uc.at("exclusions").is_array()) {
				auto& exclArr = uc.at("exclusions").as_array();
				for (size_t i = 0; i < exclArr.size(); ++i) {
					if (!exclArr[i].is_object()) continue;
					if (jsonStr(exclArr[i].as_object(), "start") == start && jsonStr(exclArr[i].as_object(), "end") == end) {
						exclArr.erase(exclArr.begin() + i);
						break;
					}
				}
			}
		}
		break;
	}
	if (!found) { errorMsg = "Bereich nicht gefunden."; return false; }

	if (!saveKeaConfig(conf)) { errorMsg = "Fehler beim Schreiben der Konfiguration."; return false; }
	bool restarted = restartKeaService();
	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Ausschlussbereich " + start + " - " + end + " gelöscht."
		+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	return true;
}

// Findet innerhalb von scopes[scopeIdx] die Reservierung mit
// oldIp+oldMac (eindeutiger Schluessel) und ersetzt sie durch die
// neuen Werte. Aufgerufen von onReservationProperties.
bool DhcpManager::updateReservation(int scopeIdx, const FXString& oldIp, const FXString& oldMac,
                                     const FXString& newIp, const FXString& newMac, const FXString& newName,
                                     FXString& errorMsg) {
	if (scopeIdx < 0 || scopeIdx >= (int)scopes.size()) { errorMsg = "Ungültiger Bereich."; return false; }
	FXString cidr = scopes[scopeIdx].subnetCidr;

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) { errorMsg = "Konfiguration nicht gefunden."; return false; }

	bool found = false;
	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (!sv.is_object() || jsonStr(sv.as_object(), "subnet") != cidr) continue;
		if (!sv.as_object().if_contains("reservations") || !sv.as_object().at("reservations").is_array()) break;
		auto& resArr = sv.as_object().at("reservations").as_array();
		for (auto& rv : resArr) {
			if (!rv.is_object()) continue;
			if (jsonStr(rv.as_object(), "ip-address") == oldIp && jsonStr(rv.as_object(), "hw-address") == oldMac) {
				rv.as_object()["ip-address"] = newIp.text();
				rv.as_object()["hw-address"] = newMac.text();
				rv.as_object()["hostname"] = newName.text();
				found = true;
				break;
			}
		}
		break;
	}
	if (!found) { errorMsg = "Reservierung nicht gefunden."; return false; }

	if (!saveKeaConfig(conf)) { errorMsg = "Fehler beim Schreiben der Konfiguration."; return false; }
	bool restarted = restartKeaService();
	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Reservierung " + newIp + " (" + newName + ") aktualisiert."
		+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	return true;
}

// Entfernt die Reservierung mit ip+mac aus scopes[scopeIdx].
// Aufgerufen von onDeleteReservation.
bool DhcpManager::deleteReservationEntry(int scopeIdx, const FXString& ip, const FXString& mac, FXString& errorMsg) {
	if (scopeIdx < 0 || scopeIdx >= (int)scopes.size()) { errorMsg = "Ungültiger Bereich."; return false; }
	FXString cidr = scopes[scopeIdx].subnetCidr;

	json::value conf = loadKeaConfig();
	if (!isValidConfig(conf)) { errorMsg = "Konfiguration nicht gefunden."; return false; }

	bool found = false;
	for (auto& sv : conf.as_object().at("Dhcp4").as_object().at("subnet4").as_array()) {
		if (!sv.is_object() || jsonStr(sv.as_object(), "subnet") != cidr) continue;
		if (!sv.as_object().if_contains("reservations") || !sv.as_object().at("reservations").is_array()) break;
		auto& resArr = sv.as_object().at("reservations").as_array();
		for (size_t i = 0; i < resArr.size(); ++i) {
			if (!resArr[i].is_object()) continue;
			if (jsonStr(resArr[i].as_object(), "ip-address") == ip && jsonStr(resArr[i].as_object(), "hw-address") == mac) {
				resArr.erase(resArr.begin() + i);
				found = true;
				break;
			}
		}
		break;
	}
	if (!found) { errorMsg = "Reservierung nicht gefunden."; return false; }

	if (!saveKeaConfig(conf)) { errorMsg = "Fehler beim Schreiben der Konfiguration."; return false; }
	bool restarted = restartKeaService();
	onRefresh(NULL, 0, NULL);
	statuslbl->setText("Reservierung " + ip + " gelöscht."
		+ (restarted ? FXString("") : FXString(" Achtung: kea-dhcp4-server konnte nicht neu gestartet werden -- bitte manuell prüfen.")));
	return true;
}

// Muss nach der vollstaendigen DhcpManager-Definition stehen.
long NewReservationDialog::onAddReservation(FXObject*, FXSelector, void*) {
	FXString ipVal = ip.get();
	FXString macVal = macField->getText().trim();
	FXString nameVal = nameField->getText().trim();
	if (macVal.empty()) {
		FXMessageBox::error(this, MBOX_OK, "MAC-Adresse fehlt", "Bitte eine MAC-Adresse eingeben.");
		return 1;
	}
	FXString errorMsg;
	if (mgr->createReservation(scopeIdx, ipVal, macVal, nameVal, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neue Reservierung",
			"Die Reservierung für \"%s\" wurde erfolgreich erstellt.", ipVal.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long NewExclusionDialog::onAddExclusion(FXObject*, FXSelector, void*) {
	FXString startVal = startIp.get();
	// "Letzte IP-Adresse" ist optional -- bleibt sie leer, wird wie im
	// Original nur die eine Adresse aus "Erste IP-Adresse" ausgeschlossen.
	FXString endVal = endIp.isEmpty() ? startVal : endIp.get();
	FXString errorMsg;
	if (mgr->createExclusion(scopeIdx, startVal, endVal, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neuer Ausschlussbereich",
			"Der Ausschlussbereich \"%s - %s\" wurde erfolgreich erstellt.", startVal.text(), endVal.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

void DhcpManager::create() {
	FXMainWindow::create();
	show(PLACEMENT_SCREEN);
}

int main(int argc, char* argv[]) {
	FXApp application("DhcpMgr", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	// Root-Rechte anfragen, BEVOR das Hauptfenster aufgebaut wird -- wie
	// bei dnsmgr: i2ksudo zeigt die GUI-Passwortabfrage im Win2k-Stil.
	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	// Debian/Kea legt /etc/kea standardmaessig mit Modus 750 an (nur root
	// + Gruppe duerfen das Verzeichnis betreten) -- anders als /etc/bind
	// beim DNS-Manager, das i.d.R. 755 ist. Ohne diese Korrektur kann der
	// normale Benutzer die Konfigurationsdatei nie lesen (selbst wenn sie
	// selbst 644 ist), das Programm haelt die Config bei jedem Neuladen
	// faelschlich fuer ungueltig und schreibt den Demo-Bereich erneut --
	// und ueberschreibt damit alles, was der Benutzer gerade erst angelegt
	// hat. Einmalig beim Start beheben, dann funktioniert das ganz normale
	// unprivilegierte Lesen in loadKeaConfig().
	if (g_haveRoot) {
		runAsRoot({ FXString("mkdir"), FXString("-p"), FXString("/etc/kea") });
		runAsRoot({ FXString("chmod"), FXString("755"), FXString("/etc/kea") });
	}

	DhcpManager* win = new DhcpManager(&application);
	application.create();
	win->show(PLACEMENT_SCREEN);

	if (!g_haveRoot) {
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\n"
			"Der DHCP-Manager kann bestehende Bereiche weiterhin anzeigen, aber keine\n"
			"neuen Bereiche/Reservierungen anlegen und keine Demo-Konfiguration\n"
			"nach /etc/kea/ schreiben.");
	}

	return application.run();
}
