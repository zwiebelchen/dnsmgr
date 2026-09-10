// dnsmgr.cpp
//
// DNS-Manager fuer ice2k -- Nachbau des Windows 2000 "DNS"-MMC-Snapins.
// Liest/schreibt echte BIND9-Zonen (named.conf.local + Zonendateien).
//
// Baut auf demselben Muster wie mmc/devmgmt aus dem ice2k-Repo auf:
// FXTreeList links, Detailansicht rechts, MMC-Toolbar-Icons.

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <sys/wait.h>
#include <ctype.h>

FXApp* app;

// Ob wir beim Start erfolgreich Root-Rechte erlangt haben (siehe main()).
static bool g_haveRoot = false;

// ---------------------------------------------------------------------
// Root-Rechte ueber i2ksudo -- exakt dasselbe Muster wie in
// control/sysdm/sysdm.cpp und control/timedate/timedate.cpp im ice2k-Repo:
// i2ksudo ruft "sudo -A" mit einer GUI-Passwortabfrage (i2ksudo-askpass)
// im Win2k-Stil auf. Der erste Aufruf fragt nach dem Passwort, dank
// sudo-Timestamp-Caching fragen nachfolgende Aufrufe i.d.R. nicht erneut.
// ---------------------------------------------------------------------
static int runAsRoot(const std::vector<FXString>& args) {
	std::vector<char*> argv;
	argv.push_back((char*)"i2ksudo");
	for (auto& a : args) argv.push_back((char*)a.text());
	argv.push_back(NULL);

	pid_t pid = fork();
	if (pid == 0) {
		execvp("i2ksudo", argv.data());
		_exit(127); // i2ksudo nicht gefunden/ausfuehrbar
	} else if (pid > 0) {
		int status = 0;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) return WEXITSTATUS(status);
		return -1;
	}
	return -1;
}

// Schreibt "content" als root nach "path": erst unprivilegiert in eine
// Temp-Datei, dann per i2ksudo/"cp" an den eigentlichen Zielort kopieren.
// So braucht keine root-Instanz des Programms selbst zu laufen -- nur die
// einzelnen privilegierten Schreibzugriffe.
static bool writeFileAsRoot(const FXString& path, const FXString& content) {
	char tmpname[] = "/tmp/dnsmgr_XXXXXX";
	int fd = mkstemp(tmpname);
	if (fd < 0) return false;
	FILE* f = fdopen(fd, "w");
	if (!f) { close(fd); unlink(tmpname); return false; }
	fwrite(content.text(), 1, content.length(), f);
	fclose(f);

	int rc = runAsRoot({ FXString("cp"), FXString(tmpname), path });
	unlink(tmpname);
	if (rc != 0) return false;
	runAsRoot({ FXString("chmod"), FXString("644"), path });
	return true;
}

// ---------------------------------------------------------------------
// Sehr einfacher BIND9-Parser: liest /etc/bind/named.conf.local nach
// "zone "NAME" { ... file "PFAD"; ... };" Bloecken.
// Kein vollstaendiger Parser -- reicht fuer master-Zonen im ueblichen Format.
// ---------------------------------------------------------------------

struct ZoneInfo {
	FXString name;
	FXString file;
	bool isReverse;
};

struct ResourceRecord {
	FXString name;    // Anzeigename, z.B. "(identisch mit übergeordnetem...)" oder "www"
	FXString rawName; // Rohname wie in der Zonendatei ("@" oder "www") -- fuer Bearbeiten/Loeschen
	FXString type;   // SOA / NS / A / CNAME / MX ...
	FXString data;   // Anzeigetext fuer die Datenspalte
	FXString rawIp;  // bei A-Records: reine IP, fuer den Eigenschaften-Dialog
};

static const char* NAMED_CONF_LOCAL = "/etc/bind/named.conf.local";

static std::vector<ZoneInfo> parseNamedConfLocal() {
	std::vector<ZoneInfo> zones;
	std::ifstream in(NAMED_CONF_LOCAL);
	if (!in.is_open()) return zones;

	std::string line, block;
	bool inZone = false;
	FXString curName;

	while (std::getline(in, line)) {
		// Kommentare grob entfernen
		size_t c = line.find("//");
		if (c != std::string::npos) line = line.substr(0, c);

		if (!inZone) {
			size_t p = line.find("zone");
			if (p != std::string::npos) {
				size_t q1 = line.find('"', p);
				size_t q2 = (q1 != std::string::npos) ? line.find('"', q1 + 1) : std::string::npos;
				if (q1 != std::string::npos && q2 != std::string::npos) {
					curName = line.substr(q1 + 1, q2 - q1 - 1).c_str();
					inZone = true;
					block.clear();
				}
			}
		} else {
			block += line + "\n";
			if (line.find("};") != std::string::npos) {
				// file "..." suchen
				size_t fp = block.find("file");
				FXString file;
				if (fp != std::string::npos) {
					size_t q1 = block.find('"', fp);
					size_t q2 = (q1 != std::string::npos) ? block.find('"', q1 + 1) : std::string::npos;
					if (q1 != std::string::npos && q2 != std::string::npos)
						file = block.substr(q1 + 1, q2 - q1 - 1).c_str();
				}
				ZoneInfo zi;
				zi.name = curName;
				zi.file = file;
				zi.isReverse = curName.find("in-addr.arpa") >= 0;
				zones.push_back(zi);
				inZone = false;
			}
		}
	}
	return zones;
}

// Sehr einfacher Zonendatei-Parser fuer SOA/NS/A-Records.
static std::vector<ResourceRecord> parseZoneFile(const FXString& path, const FXString& origin) {
	std::vector<ResourceRecord> recs;
	std::ifstream in(path.text());
	if (!in.is_open()) return recs;

	std::string line;
	FXString lastName = "@";
	std::string soaBuf;
	bool inSoa = false;

	while (std::getline(in, line)) {
		size_t c = line.find(';');
		if (c != std::string::npos) line = line.substr(0, c);
		if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
		if (line[0] == '$') continue; // $TTL, $ORIGIN

		if (inSoa) {
			soaBuf += " " + line;
			if (line.find(')') != std::string::npos) {
				inSoa = false;
				// grober Serial-Extract: erste Zahl nach der Klammer
				std::istringstream iss(soaBuf);
				std::string tok; std::string serial;
				while (iss >> tok) {
					bool allDigit = !tok.empty();
					for (char ch : tok) if (!isdigit((unsigned char)ch)) { allDigit = false; break; }
					if (allDigit) { serial = tok; break; }
				}
				ResourceRecord rr;
				rr.name = "(identisch mit übergeordnetem Ordnerobjekt)";
				rr.rawName = "@";
				rr.type = "Autoritätsursprung";
				rr.data = "[" + FXString(serial.c_str()) + "], " + origin + ".";
				recs.push_back(rr);
			}
			continue;
		}

		std::istringstream iss(line);
		std::vector<std::string> tok;
		std::string t;
		while (iss >> t) tok.push_back(t);
		if (tok.empty()) continue;

		size_t idx = 0;
		FXString name = lastName;
		if (tok[0] != "IN" && tok[0] != "in") {
			name = tok[0].c_str();
			lastName = name;
			idx = 1;
		}
		if (idx < tok.size() && (tok[idx] == "IN" || tok[idx] == "in")) idx++;
		if (idx >= tok.size()) continue;

		std::string type = tok[idx]; idx++;
		std::transform(type.begin(), type.end(), type.begin(), ::toupper);

		FXString dispName = (name == "@") ? "(identisch mit übergeordnetem Ordnerobjekt)" : name;

		if (type == "SOA") {
			inSoa = (line.find(')') == std::string::npos);
			soaBuf = line;
			if (!inSoa) {
				ResourceRecord rr;
				rr.name = dispName; rr.rawName = name;
				rr.type = "Autoritätsursprung";
				rr.data = origin + ".";
				recs.push_back(rr);
			}
		} else if (type == "NS") {
			ResourceRecord rr;
			rr.name = dispName; rr.rawName = name;
			rr.type = "Namenserver";
			rr.data = (idx < tok.size()) ? tok[idx].c_str() : "";
			recs.push_back(rr);
		} else if (type == "A") {
			ResourceRecord rr;
			rr.name = (name == "@") ? origin : name; rr.rawName = name;
			rr.type = "Host";
			rr.data = (idx < tok.size()) ? tok[idx].c_str() : "";
			rr.rawIp = rr.data;
			recs.push_back(rr);
		} else if (type == "AAAA") {
			ResourceRecord rr;
			rr.name = (name == "@") ? origin : name; rr.rawName = name;
			rr.type = "IPv6-Host";
			rr.data = (idx < tok.size()) ? tok[idx].c_str() : "";
			recs.push_back(rr);
		} else if (type == "CNAME") {
			ResourceRecord rr;
			rr.name = dispName; rr.rawName = name;
			rr.type = "Alias";
			rr.data = (idx < tok.size()) ? tok[idx].c_str() : "";
			recs.push_back(rr);
		} else if (type == "MX") {
			ResourceRecord rr;
			rr.name = dispName; rr.rawName = name;
			rr.type = "Mailaustausch";
			if (idx + 1 < tok.size()) rr.data = FXString("[") + tok[idx].c_str() + "] " + tok[idx+1].c_str();
			recs.push_back(rr);
		} else if (type == "PTR") {
			ResourceRecord rr;
			rr.name = dispName; rr.rawName = name;
			rr.type = "Zeiger";
			rr.data = (idx < tok.size()) ? tok[idx].c_str() : "";
			recs.push_back(rr);
		} else if (type == "SRV") {
			ResourceRecord rr;
			rr.name = dispName; rr.rawName = name;
			rr.type = "Dienst";
			if (idx + 3 < tok.size())
				rr.data = FXString("[") + tok[idx].c_str() + "][" + tok[idx+1].c_str() + "][" + tok[idx+2].c_str() + "] " + tok[idx+3].c_str();
			recs.push_back(rr);
		} else if (type == "TXT") {
			// Text-Inhalt kann Leerzeichen enthalten -- direkt aus der
			// Originalzeile nach dem Schluesselwort TXT herausschneiden,
			// statt sich auf die whitespace-getrennten Tokens zu verlassen.
			size_t tpos = line.find("TXT");
			std::string raw = (tpos != std::string::npos) ? line.substr(tpos + 3) : "";
			size_t b = raw.find_first_not_of(" \t");
			std::string display = (b != std::string::npos) ? raw.substr(b) : raw;
			if (!display.empty() && display.front() == '"') {
				display.erase(0, 1);
				size_t endq = display.find('"');
				if (endq != std::string::npos) display = display.substr(0, endq);
			}
			ResourceRecord rr;
			rr.name = dispName; rr.rawName = name;
			rr.type = "Text";
			rr.data = display.c_str();
			recs.push_back(rr);
		}
	}
	return recs;
}

// Liest die 5 SOA-Zahlenwerte (Serial, Refresh, Retry, Expire, Minimum)
// roh aus einer Zonendatei -- fuer den Eigenschaften-Dialog einer Zone.
// Bildet unsere deutschen Anzeige-Typnamen auf die BIND-Schluesselwoerter
// in der Zonendatei ab -- fuer generisches Bearbeiten/Loeschen.
static FXString typeKeywordFor(const FXString& displayType) {
	if (displayType == "Host") return "A";
	if (displayType == "IPv6-Host") return "AAAA";
	if (displayType == "Alias") return "CNAME";
	if (displayType == "Mailaustausch") return "MX";
	if (displayType == "Zeiger") return "PTR";
	if (displayType == "Namenserver") return "NS";
	if (displayType == "Text") return "TXT";
	if (displayType == "Dienst") return "SRV";
	return "";
}

static bool parseSoaFields(const FXString& path, long& serial, long& refresh, long& retry, long& expire, long& minimum) {
	std::ifstream in(path.text());
	if (!in.is_open()) return false;

	std::string line;
	bool inSoa = false;
	std::vector<long> nums;
	while (std::getline(in, line)) {
		size_t c = line.find(';');
		if (c != std::string::npos) line = line.substr(0, c);

		if (!inSoa) {
			if (line.find("SOA") == std::string::npos) continue;
			inSoa = true;
		}

		std::string digits;
		for (size_t i = 0; i <= line.size(); ++i) {
			if (i < line.size() && isdigit((unsigned char)line[i])) {
				digits += line[i];
			} else if (!digits.empty()) {
				nums.push_back(atol(digits.c_str()));
				digits.clear();
			}
		}
		if (line.find(')') != std::string::npos) break;
	}
	if (nums.size() < 5) return false;
	size_t n = nums.size();
	serial = nums[n-5]; refresh = nums[n-4]; retry = nums[n-3]; expire = nums[n-2]; minimum = nums[n-1];
	return true;
}

// Schreibt eine geaenderte IP fuer einen A-Record best-effort in die Zonendatei
// (als root via writeFileAsRoot) und stoesst danach "rndc reload <zone>" an.
static bool updateARecord(const FXString& zoneFile, const FXString& hostName,
                           const FXString& oldIp, const FXString& newIp, const FXString& zoneName) {
	std::ifstream in(zoneFile.text());
	if (!in.is_open()) return false;
	std::vector<std::string> lines;
	std::string line;
	bool changed = false;
	while (std::getline(in, line)) {
		if (!changed && line.find(hostName.text()) != std::string::npos &&
		    line.find(" A ") != std::string::npos &&
		    line.find(oldIp.text()) != std::string::npos) {
			size_t p = line.find(oldIp.text());
			line.replace(p, strlen(oldIp.text()), newIp.text());
			changed = true;
		}
		lines.push_back(line);
	}
	in.close();
	if (!changed) return false;

	std::string newContent;
	for (auto& l : lines) newContent += l + "\n";
	if (!writeFileAsRoot(zoneFile, newContent.c_str())) return false;

	runAsRoot({ FXString("rndc"), FXString("reload"), zoneName });
	return true;
}

// Prueft, ob named.conf.local fehlt oder eine "Dummy"-Datei ohne jede
// Zonendefinition ist (z.B. eine frisch von BIND9 mitgelieferte Leerdatei).
static bool namedConfLocalIsMissingOrDummy() {
	std::ifstream in(NAMED_CONF_LOCAL);
	if (!in.is_open()) return true;
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	return content.find("zone") == std::string::npos;
}

// Legt eine Demo-Zone (analog zum Original-Screenshot) direkt auf der
// Platte an, wenn named.conf.local fehlt oder nur eine Dummy-Datei ist.
// Braucht Root-Rechte (siehe g_haveRoot / runAsRoot).
static bool seedDemoZoneOnDisk() {
	char hn[256] = {0};
	gethostname(hn, sizeof(hn));
	FXString hostnameStr = (hn[0] != '\0') ? FXString(hn) : FXString("win2k-server");

	FXString confContent =
		"// Von DNS-Manager (ice2k) automatisch angelegt, da unter\n"
		"// /etc/bind/named.conf.local keine echte Zonenkonfiguration\n"
		"// gefunden wurde.\n\n"
		"zone \"zwiebelchen.org\" {\n"
		"\ttype master;\n"
		"\tfile \"/etc/bind/db.zwiebelchen.org\";\n"
		"};\n";

	FXString zoneContent =
		FXString("$TTL\t604800\n") +
		"@\tIN\tSOA\t" + hostnameStr + ". admin.zwiebelchen.org. (\n" +
		"\t\t\t      1\t\t; Serial\n" +
		"\t\t\t 604800\t\t; Refresh\n" +
		"\t\t\t  86400\t\t; Retry\n" +
		"\t\t\t2419200\t\t; Expire\n" +
		"\t\t\t 604800 )\t; Negative Cache TTL\n" +
		"@\tIN\tNS\t" + hostnameStr + ".\n" +
		hostnameStr + "\tIN\tA\t10.10.10.91\n";

	runAsRoot({ FXString("mkdir"), FXString("-p"), FXString("/etc/bind") });
	bool ok = writeFileAsRoot(NAMED_CONF_LOCAL, confContent) &&
	          writeFileAsRoot("/etc/bind/db.zwiebelchen.org", zoneContent);
	if (ok) runAsRoot({ FXString("rndc"), FXString("reconfig") });
	return ok;
}

// ---------------------------------------------------------------------
// Eigenschaften-Dialog fuer einen Host (A)-Eintrag, wie im Original-Screenshot
// ---------------------------------------------------------------------

class HostPropertiesDialog : public FXDialogBox {
	FXDECLARE(HostPropertiesDialog)
private:
	FXTextField *domainField, *hostField;
	FXTextField *ip1, *ip2, *ip3, *ip4;
	FXCheckButton *ptrCheck;
	FXString zoneFile, zoneName, hostName, oldIp;
protected:
	HostPropertiesDialog() {}
public:
	HostPropertiesDialog(FXWindow* owner, const FXString& zone, const FXString& file,
	                      const FXString& host, const FXString& ip)
		: FXDialogBox(owner, "Eigenschaften von " + host, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE,
		              0, 0, 400, 0, 0, 0, 0, 0),
		  zoneFile(file), zoneName(zone), hostName(host), oldIp(ip) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 8,8,8,8);

		FXTabBook* tabs = new FXTabBook(main, NULL, 0, LAYOUT_FILL_X);
		new FXTabItem(tabs, "Host (A)", NULL);
		FXVerticalFrame* tabframe = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED, 0,0,0,0, 10,10,10,10);

		new FXLabel(tabframe, "Übergeordnete Domäne:");
		domainField = new FXTextField(tabframe, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		domainField->setText(zone);
		domainField->disable();

		new FXLabel(tabframe, "Host (bei Nichtangabe wird übergeordneter Domänenname verwendet):");
		hostField = new FXTextField(tabframe, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		hostField->setText(host);

		new FXLabel(tabframe, "IP-Adresse:");
		FXHorizontalFrame* ipf = new FXHorizontalFrame(tabframe, 0,0,0,0,0, 0,0,0,0, 1,1);

		FXString o1="0",o2="0",o3="0",o4="0";
		FXString ipcopy = ip;
		int dot1 = ipcopy.find('.');
		int dot2 = ipcopy.find('.', dot1+1);
		int dot3 = ipcopy.find('.', dot2+1);
		if (dot1>0 && dot2>0 && dot3>0) {
			o1 = ipcopy.mid(0, dot1);
			o2 = ipcopy.mid(dot1+1, dot2-dot1-1);
			o3 = ipcopy.mid(dot2+1, dot3-dot2-1);
			o4 = ipcopy.mid(dot3+1, ipcopy.length()-dot3-1);
		}
		ip1 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip1->setText(o1);
		new FXLabel(ipf, ".");
		ip2 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip2->setText(o2);
		new FXLabel(ipf, ".");
		ip3 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip3->setText(o3);
		new FXLabel(ipf, ".");
		ip4 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip4->setText(o4);

		ptrCheck = new FXCheckButton(tabframe, "Entsprechenden PTR-Eintrag aktualisieren");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	FXString getNewIp() const {
		return ip1->getText() + "." + ip2->getText() + "." + ip3->getText() + "." + ip4->getText();
	}
	FXString getZoneFile() const { return zoneFile; }
	FXString getZoneName() const { return zoneName; }
	FXString getHostName() const { return hostField->getText(); }
	FXString getOldIp() const { return oldIp; }

	virtual ~HostPropertiesDialog() {}
};
FXIMPLEMENT(HostPropertiesDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Assistent fuer "Neue Zone" -- angelehnt an den Original-Zonen-Assistenten:
// Zonentyp (nur Primär/Standard wird unterstuetzt), dann Auswahl
// Forward-/Reverse-Lookupzone, je nachdem Domänenname oder Netzwerk-ID.
// ---------------------------------------------------------------------

class NewZoneWizardDialog : public FXDialogBox {
	FXDECLARE(NewZoneWizardDialog)
private:
	FXRadioButton *rbForward, *rbReverse;
	FXSwitcher *switcher;
	FXTextField *domainField;
	FXTextField *net1, *net2, *net3;
	FXLabel *reverseNamePreview;
protected:
	NewZoneWizardDialog() {}
public:
	enum { ID_FWD = FXDialogBox::ID_LAST, ID_REV, ID_NETOCT };

	long onScope(FXObject* sender, FXSelector, void*) {
		bool rev = (sender == rbReverse);
		rbForward->setCheck(!rev);
		rbReverse->setCheck(rev);
		switcher->setCurrent(rev ? 1 : 0);
		return 1;
	}
	long onNetOct(FXObject*, FXSelector, void*) {
		reverseNamePreview->setText("Zonenname: " + getReverseZoneName() + ".in-addr.arpa");
		return 1;
	}

	NewZoneWizardDialog(FXWindow* owner)
		: FXDialogBox(owner, "Assistent für neue Zone", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,440,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		new FXLabel(main,
			"Dieser Assistent legt eine neue DNS-Zone an.\n"
			"Zonentyp: Primäre Zone (Standard) -- Active-Directory-Integration\n"
			"wird von diesem Prototyp nicht unterstützt.",
			NULL, JUSTIFY_LEFT);

		FXGroupBox* scopeBox = new FXGroupBox(main, "Zone", FRAME_GROOVE | LAYOUT_FILL_X);
		FXVerticalFrame* scopeFrame = new FXVerticalFrame(scopeBox, LAYOUT_FILL_X, 0,0,0,0, 6,6,6,6);
		rbForward = new FXRadioButton(scopeFrame, "&Forward-Lookupzone", this, ID_FWD);
		rbReverse = new FXRadioButton(scopeFrame, "&Reverse-Lookupzone", this, ID_REV);
		rbForward->setCheck(TRUE);

		switcher = new FXSwitcher(main, LAYOUT_FILL_X);

		FXVerticalFrame* fwdPage = new FXVerticalFrame(switcher, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXLabel(fwdPage, "Zonenname (z.B. beispiel.org):");
		domainField = new FXTextField(fwdPage, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		FXVerticalFrame* revPage = new FXVerticalFrame(switcher, LAYOUT_FILL_X, 0,0,0,0, 0,0,4,4);
		new FXLabel(revPage, "Netzwerk-ID (die ersten drei Oktette, z.B. 10.10.10):");
		FXHorizontalFrame* netf = new FXHorizontalFrame(revPage, 0,0,0,0,0, 0,0,0,0, 1,1);
		net1 = new FXTextField(netf, 3, this, ID_NETOCT, FRAME_SUNKEN | JUSTIFY_CENTER_X); net1->setText("10");
		new FXLabel(netf, ".");
		net2 = new FXTextField(netf, 3, this, ID_NETOCT, FRAME_SUNKEN | JUSTIFY_CENTER_X); net2->setText("10");
		new FXLabel(netf, ".");
		net3 = new FXTextField(netf, 3, this, ID_NETOCT, FRAME_SUNKEN | JUSTIFY_CENTER_X); net3->setText("10");
		new FXLabel(netf, ".x");
		reverseNamePreview = new FXLabel(revPage, "Zonenname: 10.10.10.in-addr.arpa");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Fertig stellen", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	FXbool isReverse() const { return rbReverse->getCheck(); }
	FXString getDomainName() const { return domainField->getText().trim(); }
	FXString getReverseZoneName() const {
		return net3->getText() + "." + net2->getText() + "." + net1->getText() + ".in-addr.arpa";
	}

	virtual ~NewZoneWizardDialog() {}
};
FXDEFMAP(NewZoneWizardDialog) NewZoneWizardDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewZoneWizardDialog::ID_FWD, NewZoneWizardDialog::onScope),
	FXMAPFUNC(SEL_COMMAND, NewZoneWizardDialog::ID_REV, NewZoneWizardDialog::onScope),
	FXMAPFUNC(SEL_CHANGED, NewZoneWizardDialog::ID_NETOCT, NewZoneWizardDialog::onNetOct),
};
FXIMPLEMENT(NewZoneWizardDialog, FXDialogBox, NewZoneWizardDialogMap, ARRAYNUMBER(NewZoneWizardDialogMap))

// ---------------------------------------------------------------------
// Dialog "Neuer Host" -- Kontextmenue auf einer Zone.
// Wie im Original: "Host hinzufügen" legt den Host sofort an und laesst
// den Dialog fuer weitere Hosts offen; "Fertig stellen" schliesst ihn.
// ---------------------------------------------------------------------

class DnsManager; // vorwaertsdeklariert, echte Definition folgt weiter unten

class NewHostDialog : public FXDialogBox {
	FXDECLARE(NewHostDialog)
private:
	FXTextField *hostField;
	FXTextField *ip1, *ip2, *ip3, *ip4;
	FXCheckButton *ptrCheck;
	DnsManager* mgr;
	int zoneIdx;
protected:
	NewHostDialog() {}
public:
	enum { ID_ADDHOST = FXDialogBox::ID_LAST };

	long onAddHost(FXObject*, FXSelector, void*); // Implementierung folgt nach DnsManager

	NewHostDialog(FXWindow* owner, DnsManager* m, int zIdx, const FXString& zone)
		: FXDialogBox(owner, "Neuer Host", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0, 0, 380, 0, 0,0,0,0),
		  mgr(m), zoneIdx(zIdx) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		new FXLabel(main, "Neuer Host in Zone: " + zone);

		new FXLabel(main, "Name (bei Nichtangabe wird der übergeordnete Domänenname verwendet):");
		hostField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "IP-Adresse:");
		FXHorizontalFrame* ipf = new FXHorizontalFrame(main, 0,0,0,0,0, 0,0,0,0, 1,1);
		ip1 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip1->setText("0");
		new FXLabel(ipf, ".");
		ip2 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip2->setText("0");
		new FXLabel(ipf, ".");
		ip3 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip3->setText("0");
		new FXLabel(ipf, ".");
		ip4 = new FXTextField(ipf, 3, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X); ip4->setText("0");

		ptrCheck = new FXCheckButton(main, "Entsprechenden PTR-Eintrag erstellen (falls Reverse-Zone vorhanden)");
		ptrCheck->setCheck(TRUE);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Host hinzufügen", NULL, this, ID_ADDHOST,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Fertig stellen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	void resetFields() {
		hostField->setText("");
		ip1->setText("0"); ip2->setText("0"); ip3->setText("0"); ip4->setText("0");
		hostField->setFocus();
	}

	virtual ~NewHostDialog() {}
};
FXDEFMAP(NewHostDialog) NewHostDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewHostDialog::ID_ADDHOST, NewHostDialog::onAddHost),
};
FXIMPLEMENT(NewHostDialog, FXDialogBox, NewHostDialogMap, ARRAYNUMBER(NewHostDialogMap))

// ---------------------------------------------------------------------
// Dialog "Neuer Alias (CNAME)" -- gleiches Add/Fertig-Muster wie beim Host
// ---------------------------------------------------------------------

class NewAliasDialog : public FXDialogBox {
	FXDECLARE(NewAliasDialog)
private:
	FXTextField *aliasField, *targetField;
	DnsManager* mgr;
	int zoneIdx;
protected:
	NewAliasDialog() {}
public:
	enum { ID_ADDALIAS = FXDialogBox::ID_LAST };
	long onAddAlias(FXObject*, FXSelector, void*);

	NewAliasDialog(FXWindow* owner, DnsManager* m, int zIdx, const FXString& zone)
		: FXDialogBox(owner, "Neuer Alias", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0, 0, 400, 0, 0,0,0,0),
		  mgr(m), zoneIdx(zIdx) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Neuer Alias in Zone: " + zone);

		new FXLabel(main, "Aliasname (bei Nichtangabe wird der übergeordnete Domänenname verwendet):");
		aliasField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Voll qualifizierter Domänenname (FQDN) für Zielhost:");
		targetField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Alias hinzufügen", NULL, this, ID_ADDALIAS,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Fertig stellen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	void resetFields() { aliasField->setText(""); targetField->setText(""); aliasField->setFocus(); }
	virtual ~NewAliasDialog() {}
};
FXDEFMAP(NewAliasDialog) NewAliasDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewAliasDialog::ID_ADDALIAS, NewAliasDialog::onAddAlias),
};
FXIMPLEMENT(NewAliasDialog, FXDialogBox, NewAliasDialogMap, ARRAYNUMBER(NewAliasDialogMap))

// ---------------------------------------------------------------------
// Dialog "Neuer Mailserver (MX)" -- gleiches Add/Fertig-Muster
// ---------------------------------------------------------------------

class NewMxDialog : public FXDialogBox {
	FXDECLARE(NewMxDialog)
private:
	FXTextField *nameField, *targetField, *prioField;
	DnsManager* mgr;
	int zoneIdx;
protected:
	NewMxDialog() {}
public:
	enum { ID_ADDMX = FXDialogBox::ID_LAST };
	long onAddMx(FXObject*, FXSelector, void*);

	NewMxDialog(FXWindow* owner, DnsManager* m, int zIdx, const FXString& zone)
		: FXDialogBox(owner, "Neuer Mailserver", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0, 0, 420, 0, 0,0,0,0),
		  mgr(m), zoneIdx(zIdx) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Neuer Mailserver in Zone: " + zone);

		new FXLabel(main, "Host- oder untergeordneter Domänenname (bei Nichtangabe wird die übergeordnete Domäne verwendet):");
		nameField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Voll qualifizierter Domänenname (FQDN) des Mailservers:");
		targetField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		new FXLabel(main, "Mailserverpriorität:");
		prioField = new FXTextField(main, 5, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X);
		prioField->setText("10");

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Mailserver hinzufügen", NULL, this, ID_ADDMX,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Fertig stellen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	void resetFields() { nameField->setText(""); targetField->setText(""); prioField->setText("10"); nameField->setFocus(); }
	virtual ~NewMxDialog() {}
};
FXDEFMAP(NewMxDialog) NewMxDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewMxDialog::ID_ADDMX, NewMxDialog::onAddMx),
};
FXIMPLEMENT(NewMxDialog, FXDialogBox, NewMxDialogMap, ARRAYNUMBER(NewMxDialogMap))

// ---------------------------------------------------------------------
// Dialog "Neuer Zeiger (PTR)" -- Kontextmenue auf einer Reverse-Lookupzone.
// Wie im Original: "Host-IP-Nummer" ist die IP im Netz der Zone (bei uns
// vereinfacht: nur das letzte Oktett, der Rest ergibt sich aus der Zone),
// "Hostname" ist der voll qualifizierte Name, auf den gezeigt wird.
// ---------------------------------------------------------------------

class NewPtrDialog : public FXDialogBox {
	FXDECLARE(NewPtrDialog)
private:
	FXLabel *ipPrefixLabel;
	FXTextField *lastOctetField, *hostField;
	DnsManager* mgr;
	int zoneIdx;
protected:
	NewPtrDialog() {}
public:
	enum { ID_ADDPTR = FXDialogBox::ID_LAST };
	long onAddPtr(FXObject*, FXSelector, void*);

	NewPtrDialog(FXWindow* owner, DnsManager* m, int zIdx, const FXString& zone, const FXString& networkPrefix)
		: FXDialogBox(owner, "Neuer Zeiger", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0, 0, 400, 0, 0,0,0,0),
		  mgr(m), zoneIdx(zIdx) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Neuer Zeiger in Zone: " + zone);

		new FXLabel(main, "Host-IP-Nummer:");
		FXHorizontalFrame* ipf = new FXHorizontalFrame(main, 0,0,0,0,0, 0,0,0,0, 1,1);
		ipPrefixLabel = new FXLabel(ipf, networkPrefix + ".");
		lastOctetField = new FXTextField(ipf, 4, NULL, 0, FRAME_SUNKEN | JUSTIFY_CENTER_X);

		new FXLabel(main, "Hostname (voll qualifizierter Domänenname, FQDN):");
		hostField = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Zeiger hinzufügen", NULL, this, ID_ADDPTR,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Fertig stellen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	void resetFields() { lastOctetField->setText(""); hostField->setText(""); lastOctetField->setFocus(); }
	virtual ~NewPtrDialog() {}
};
FXDEFMAP(NewPtrDialog) NewPtrDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, NewPtrDialog::ID_ADDPTR, NewPtrDialog::onAddPtr),
};
FXIMPLEMENT(NewPtrDialog, FXDialogBox, NewPtrDialogMap, ARRAYNUMBER(NewPtrDialogMap))

// ---------------------------------------------------------------------
// Dialog "Eigenschaften" einer Zone -- angelehnt an den "Allgemein"-Tab
// der Original-Zoneneigenschaften (reine Anzeige in diesem Prototyp).
// ---------------------------------------------------------------------

class ZonePropertiesDialog : public FXDialogBox {
	FXDECLARE(ZonePropertiesDialog)
protected:
	ZonePropertiesDialog() {}
public:
	ZonePropertiesDialog(FXWindow* owner, const FXString& zoneName, const FXString& zoneFile,
	                      long serial, long refresh, long retry, long expire, long minimum, bool soaOk,
	                      bool isReverse, const FXString& networkId)
		: FXDialogBox(owner, "Eigenschaften von " + zoneName, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,380,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);

		FXMatrix* grid = new FXMatrix(main, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 4,2);
		auto addRow = [&](const char* label, const FXString& value) {
			new FXLabel(grid, label);
			FXTextField* tf = new FXTextField(grid, 24, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
			tf->setText(value);
			tf->disable();
		};
		addRow("Zonenname:", zoneName);
		addRow("Zonentyp:", isReverse ? "Primär (Standard) -- Reverse-Lookupzone"
		                              : "Primär (Standard) -- Forward-Lookupzone");
		if (isReverse) addRow("Netzwerk-ID:", networkId);
		addRow("Zonendatei:", zoneFile.empty() ? FXString("(keine -- Demo-Modus)") : zoneFile);
		if (soaOk) {
			addRow("Seriennummer:", FXString(std::to_string(serial).c_str()));
			addRow("Aktualisierungsintervall:", FXString(std::to_string(refresh).c_str()) + " s");
			addRow("Wiederholungsintervall:", FXString(std::to_string(retry).c_str()) + " s");
			addRow("Ablaufintervall:", FXString(std::to_string(expire).c_str()) + " s");
			addRow("Minimum (Negative-Cache-TTL):", FXString(std::to_string(minimum).c_str()) + " s");
		}

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}
	virtual ~ZonePropertiesDialog() {}
};
FXIMPLEMENT(ZonePropertiesDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Generischer Dialog mit 1-4 Textfeldern -- fuer die Eigenschaften
// bestehender Records (Alias/MX/PTR/NS/Text/Dienst/IPv6-Host) UND fuer
// das Anlegen "anderer" neuer Datensaetze (NS/TXT/SRV/AAAA). Anders als
// bei Host/Zone gibt es hier kein "Hinzufuegen"-Schleifenmuster -- das
// entspricht dem Original: nur der New-Host-Assistent legt mehrere an,
// alle anderen "New Resource Record"-Dialoge sind klassisches OK/Abbrechen.
// ---------------------------------------------------------------------

class GenericPropsDialog : public FXDialogBox {
	FXDECLARE(GenericPropsDialog)
private:
	std::vector<FXTextField*> fields;
protected:
	GenericPropsDialog() {}
public:
	GenericPropsDialog(FXWindow* owner, const FXString& title, const FXString& infoLine,
	                    const std::vector<FXString>& labels, const std::vector<FXString>& initial)
		: FXDialogBox(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0, 0, 420, 0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		if (!infoLine.empty()) new FXLabel(main, infoLine);

		for (size_t i = 0; i < labels.size(); ++i) {
			new FXLabel(main, labels[i]);
			FXTextField* tf = new FXTextField(main, 30, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
			if (i < initial.size()) tf->setText(initial[i]);
			fields.push_back(tf);
		}

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	FXString getValue(size_t i) const { return (i < fields.size()) ? fields[i]->getText() : FXString(""); }
	virtual ~GenericPropsDialog() {}
};
FXIMPLEMENT(GenericPropsDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Dialog "Ressourcendatensatztyp auswählen" -- entspricht dem Original
// "Andere neue Datensätze..."; hier auf die haeufigsten, fuer BIND9
// sinnvollen Typen beschraenkt: NS, TXT, SRV, AAAA.
// ---------------------------------------------------------------------

class OtherRecordTypeDialog : public FXDialogBox {
	FXDECLARE(OtherRecordTypeDialog)
private:
	FXListBox* typeList;
protected:
	OtherRecordTypeDialog() {}
public:
	OtherRecordTypeDialog(FXWindow* owner)
		: FXDialogBox(owner, "Ressourcendatensatztyp auswählen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,360,0, 0,0,0,0) {

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
		new FXLabel(main, "Wählen Sie einen Ressourcendatensatztyp:");

		typeList = new FXListBox(main, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);
		typeList->appendItem("Namenserver (NS)");
		typeList->appendItem("Text (TXT)");
		typeList->appendItem("Dienst (SRV)");
		typeList->appendItem("IPv6-Host (AAAA)");
		typeList->setCurrentItem(0);
		typeList->setNumVisible(4);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
		new FXFrame(btnf, LAYOUT_FILL_X);
		new FXButton(btnf, "&Erstellen...", NULL, this, FXDialogBox::ID_ACCEPT,
		             BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
		new FXButton(btnf, "&Abbrechen", NULL, this, FXDialogBox::ID_CANCEL,
		             BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	}

	FXint getSelected() const { return typeList->getCurrentItem(); }
	virtual ~OtherRecordTypeDialog() {}
};
FXIMPLEMENT(OtherRecordTypeDialog, FXDialogBox, NULL, 0)

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------

class DnsManager : public FXMainWindow {
	FXDECLARE(DnsManager)
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

	FXTreeItem *rootItem, *serverItem, *fwdItem, *revItem;
	std::vector<FXTreeItem*> zoneItems;
	std::vector<ZoneInfo> zones;
	std::vector<std::vector<ResourceRecord> > zoneRecords;

	FXIcon *icoRoot, *icoServer, *icoFolder;
	FXIcon *icoBack, *icoForward, *icoUp, *icoContree, *icoProperties, *icoRefresh, *icoHelp, *icoDelete;

	// Fuer die Kontextmenues "Neue Zone" / "Neuer Host" gemerkt:
	// welche Zone war unter dem Rechtsklick, der das Menue geoeffnet hat.
	int contextZoneIdx;

protected:
	DnsManager() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_REFRESH, ID_ABOUT, ID_NEWZONE, ID_NEWHOST,
	       ID_DELETEZONE, ID_DELETERECORD, ID_PROPERTIES, ID_NEWCNAME, ID_NEWMX, ID_ZONEPROPS, ID_NEWPTR,
	       ID_NEWOTHER };

	long onTreeChanged(FXObject*, FXSelector, void*);
	long onTreeRightClick(FXObject*, FXSelector, void*);
	long onListDouble(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	long onNewZone(FXObject*, FXSelector, void*);
	long onNewHost(FXObject*, FXSelector, void*);
	long onNewCname(FXObject*, FXSelector, void*);
	long onNewMx(FXObject*, FXSelector, void*);
	long onNewPtr(FXObject*, FXSelector, void*);
	long onNewOther(FXObject*, FXSelector, void*);
	long onZoneProperties(FXObject*, FXSelector, void*);
	long onDeleteZone(FXObject*, FXSelector, void*);
	long onDeleteRecord(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);

	DnsManager(FXApp* a);
	void loadZones();
	void showZoneRecords(int idx);
	void openHostProperties(int zoneIdx, int recIdx);
	int currentZoneIdxFromTree();
	bool appendZoneRecord(int zoneIdx, const FXString& fullLine, FXString& errorMsg);
	bool createHostRecord(int zoneIdx, const FXString& host, const FXString& ip, bool wantPtr, FXString& errorMsg);
	bool createCnameRecord(int zoneIdx, const FXString& alias, const FXString& target, FXString& errorMsg);
	bool createMxRecord(int zoneIdx, const FXString& name, const FXString& target, int priority, FXString& errorMsg);
	bool createPtrRecord(int zoneIdx, const FXString& lastOctet, const FXString& hostFqdn, FXString& errorMsg);
	bool modifyRecordLine(int zoneIdx, const FXString& rawName, const FXString& typeKeyword,
	                       const FXString& newFullLine, FXString& errorMsg);
	virtual void create();
	virtual ~DnsManager() {}
};

FXDEFMAP(DnsManager) DnsManagerMap[] = {
	FXMAPFUNC(SEL_CHANGED, DnsManager::ID_TREE, DnsManager::onTreeChanged),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, DnsManager::ID_TREE, DnsManager::onTreeRightClick),
	FXMAPFUNC(SEL_DOUBLECLICKED, DnsManager::ID_LIST, DnsManager::onListDouble),
	FXMAPFUNC(SEL_RIGHTBUTTONPRESS, DnsManager::ID_LIST, DnsManager::onListRightClick),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_REFRESH, DnsManager::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_ABOUT, DnsManager::onAbout),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_NEWZONE, DnsManager::onNewZone),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_NEWHOST, DnsManager::onNewHost),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_NEWCNAME, DnsManager::onNewCname),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_NEWMX, DnsManager::onNewMx),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_NEWPTR, DnsManager::onNewPtr),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_NEWOTHER, DnsManager::onNewOther),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_ZONEPROPS, DnsManager::onZoneProperties),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_DELETEZONE, DnsManager::onDeleteZone),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_DELETERECORD, DnsManager::onDeleteRecord),
	FXMAPFUNC(SEL_COMMAND, DnsManager::ID_PROPERTIES, DnsManager::onProperties),
};
FXIMPLEMENT(DnsManager, FXMainWindow, DnsManagerMap, ARRAYNUMBER(DnsManagerMap))

DnsManager::DnsManager(FXApp* a)
	: FXMainWindow(a, "DNS", NULL, NULL, DECOR_ALL, 0, 0, 780, 480, 0,0,0,0,0,0) {

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
	FXMenuCommand* mc = new FXMenuCommand(vorgangmenu, "&Eigenschaften"); mc->disable();

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
	btn = new FXButton(toolbar, "\tLöschen", icoDelete, this, ID_DELETERECORD, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	btn = new FXButton(toolbar, "\tEigenschaften", icoProperties, this, ID_PROPERTIES, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
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
	list->appendHeader("Name", NULL, 260);
	list->appendHeader("Typ", NULL, 140);
	list->appendHeader("Daten", NULL, 260);

	icoRoot = new FXPNGIcon(getApp(), resico_network, IMAGE_NEAREST); icoRoot->create();
	icoServer = new FXPNGIcon(getApp(), resico_server, IMAGE_NEAREST); icoServer->create();
	icoFolder = new FXPNGIcon(getApp(), resico_folder, IMAGE_NEAREST); icoFolder->create();

	char hostname[256];
	gethostname(hostname, sizeof(hostname));

	rootItem = tree->appendItem(0, "DNS", icoRoot, icoRoot);
	serverItem = tree->appendItem(rootItem, hostname, icoServer, icoServer);
	fwdItem = tree->appendItem(serverItem, "Forward-Lookupzonen", icoFolder, icoFolder);
	revItem = tree->appendItem(serverItem, "Reverse-Lookupzonen", icoFolder, icoFolder);
	tree->expandTree(rootItem);
	tree->expandTree(serverItem);

	loadZones();
}

void DnsManager::loadZones() {
	// Alte Zonen-Knoten aus dem Baum entfernen, bevor wir sie neu anlegen --
	// sonst haeufen sich bei jedem loadZones()-Aufruf doppelte Eintraege an.
	FXTreeItem* loop = fwdItem->getFirst();
	while (loop) { FXTreeItem* n = loop->getNext(); tree->removeItem(loop); loop = n; }
	loop = revItem->getFirst();
	while (loop) { FXTreeItem* n = loop->getNext(); tree->removeItem(loop); loop = n; }

	// Wenn named.conf.local fehlt oder nur eine Dummy-Datei ohne Zonen ist,
	// UND wir Root-Rechte haben: gleich eine echte Demo-Zone auf die Platte
	// schreiben, statt nur im Speicher zu simulieren.
	if (g_haveRoot && namedConfLocalIsMissingOrDummy()) {
		if (seedDemoZoneOnDisk()) {
			statuslbl->setText("Keine Konfiguration gefunden -- Demo-Zone nach /etc/bind/ geschrieben.");
		} else {
			statuslbl->setText("Demo-Zone konnte nicht nach /etc/bind/ geschrieben werden.");
		}
	}

	zones = parseNamedConfLocal();
	zoneRecords.clear();
	zoneItems.clear();

	if (zones.empty()) {
		// Fallback, falls wir keine Root-Rechte haben (oder das Schreiben
		// trotzdem fehlgeschlagen ist): Demo nur im Speicher, wie bisher.
		statuslbl->setText(g_haveRoot
			? "Konnte keine Zonen laden -- zeige Demo-Daten nur im Speicher."
			: "Keine Root-Rechte -- zeige Demo-Daten nur im Speicher (nichts wird geschrieben).");

		ZoneInfo demo;
		demo.name = "zwiebelchen.org";
		demo.file = "";
		demo.isReverse = false;
		zones.push_back(demo);

		std::vector<ResourceRecord> recs;
		ResourceRecord r1; r1.name = "(identisch mit übergeordnetem...)"; r1.rawName = "@"; r1.type = "Autoritätsursprung"; r1.data = "[1], win2k-server., admin.";
		ResourceRecord r2; r2.name = "(identisch mit übergeordnetem...)"; r2.rawName = "@"; r2.type = "Namenserver"; r2.data = "win2k-server.";
		ResourceRecord r3; r3.name = "win2k-server"; r3.rawName = "win2k-server"; r3.type = "Host"; r3.data = "10.10.10.91"; r3.rawIp = "10.10.10.91";
		recs.push_back(r1); recs.push_back(r2); recs.push_back(r3);
		zoneRecords.push_back(recs);
	} else {
		for (auto& z : zones) {
			std::vector<ResourceRecord> recs = z.file.empty() ? std::vector<ResourceRecord>() : parseZoneFile(z.file, z.name);
			zoneRecords.push_back(recs);
		}
	}

	for (auto& z : zones) {
		FXTreeItem* parent = z.isReverse ? revItem : fwdItem;
		FXTreeItem* item = tree->appendItem(parent, z.name, icoFolder, icoFolder);
		zoneItems.push_back(item);
	}
}

void DnsManager::showZoneRecords(int idx) {
	list->clearItems();
	if (idx < 0 || idx >= (int)zoneRecords.size()) return;
	for (auto& r : zoneRecords[idx]) {
		FXString txt = r.name + "\t" + r.type + "\t" + r.data;
		list->appendItem(txt, icoFolder, icoFolder);
	}
}

long DnsManager::onTreeChanged(FXObject*, FXSelector, void*) {
	FXTreeItem* cur = tree->getCurrentItem();
	if (!cur) return 1;
	for (size_t i = 0; i < zoneItems.size(); ++i) {
		if (zoneItems[i] == cur) { showZoneRecords((int)i); return 1; }
	}
	list->clearItems();
	return 1;
}

long DnsManager::onTreeRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXTreeItem* item = tree->getItemAt(ev->win_x, ev->win_y);
	if (!item) return 1;
	tree->setCurrentItem(item);
	tree->selectItem(item);

	contextZoneIdx = -1;
	for (size_t i = 0; i < zoneItems.size(); ++i) if (zoneItems[i] == item) contextZoneIdx = (int)i;

	FXMenuPane menu(this);
	if (item == fwdItem || item == revItem) {
		new FXMenuCommand(&menu, "&Neue Zone...", NULL, this, ID_NEWZONE);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	} else if (contextZoneIdx >= 0 && !zones[contextZoneIdx].isReverse) {
		new FXMenuCommand(&menu, "&Neuer Host (A)...", NULL, this, ID_NEWHOST);
		new FXMenuCommand(&menu, "Neuer &Alias (CNAME)...", NULL, this, ID_NEWCNAME);
		new FXMenuCommand(&menu, "Neuer &Mailserver (MX)...", NULL, this, ID_NEWMX);
		new FXMenuCommand(&menu, "&Andere neue Datensätze...", NULL, this, ID_NEWOTHER);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
		new FXMenuCommand(&menu, "E&igenschaften", NULL, this, ID_ZONEPROPS);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETEZONE);
	} else if (contextZoneIdx >= 0 && zones[contextZoneIdx].isReverse) {
		new FXMenuCommand(&menu, "&Neuer Zeiger (PTR)...", NULL, this, ID_NEWPTR);
		new FXMenuCommand(&menu, "&Andere neue Datensätze...", NULL, this, ID_NEWOTHER);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
		new FXMenuCommand(&menu, "E&igenschaften", NULL, this, ID_ZONEPROPS);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETEZONE);
	} else {
		return 1; // fuer andere Knoten gibt es in diesem Prototyp noch kein Kontextmenue
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DnsManager::onNewZone(FXObject*, FXSelector, void*) {
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte",
			"Ohne Root-Rechte kann keine neue Zone angelegt werden.\n"
			"Starte den DNS-Manager neu und gib dein Passwort ein.");
		return 1;
	}

	NewZoneWizardDialog dlg(this);
	if (!dlg.execute(PLACEMENT_OWNER)) return 1;

	FXbool reverse = dlg.isReverse();
	FXString zoneName = reverse ? dlg.getReverseZoneName() : dlg.getDomainName();
	zoneName = zoneName.trim();
	if (zoneName.empty()) return 1;

	for (auto& z : zones) {
		if (z.name == zoneName) {
			FXMessageBox::error(this, MBOX_OK, "Zone existiert bereits",
				"Die Zone \"%s\" ist schon vorhanden.", zoneName.text());
			return 1;
		}
	}

	FXString zoneFile = "/etc/bind/db." + zoneName;
	char hn[256] = {0}; gethostname(hn, sizeof(hn));
	FXString hostnameStr = (hn[0] != '\0') ? FXString(hn) : FXString("win2k-server");

	FXString confBlock =
		"\nzone \"" + zoneName + "\" {\n"
		"\ttype master;\n"
		"\tfile \"" + zoneFile + "\";\n"
		"};\n";

	std::ifstream in(NAMED_CONF_LOCAL);
	std::string existing((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();
	FXString newConf = FXString(existing.c_str()) + confBlock;

	// Reverse-Zonen bekommen nur SOA+NS (keine A-Records); Forward-Zonen
	// zusaetzlich einen A-Record fuer den eigenen Host, wie im Original
	// bei der ersten Zone ueblich.
	FXString zoneContent =
		FXString("$TTL\t604800\n") +
		"@\tIN\tSOA\t" + hostnameStr + ". admin." + zoneName + ". (\n" +
		"\t\t\t      1\t\t; Serial\n" +
		"\t\t\t 604800\t\t; Refresh\n" +
		"\t\t\t  86400\t\t; Retry\n" +
		"\t\t\t2419200\t\t; Expire\n" +
		"\t\t\t 604800 )\t; Negative Cache TTL\n" +
		"@\tIN\tNS\t" + hostnameStr + ".\n";

	bool ok = writeFileAsRoot(NAMED_CONF_LOCAL, newConf) && writeFileAsRoot(zoneFile, zoneContent);
	if (ok) {
		runAsRoot({ FXString("rndc"), FXString("reconfig") });
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Zone " + zoneName + " angelegt.");
	} else {
		statuslbl->setText("Fehler beim Anlegen der Zone " + zoneName + ".");
	}
	return 1;
}

long DnsManager::onNewHost(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];

	if (z.file.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Keine Zonendatei",
			"Für diese Zone ist keine Zonendatei bekannt (Demo-Modus?).");
		return 1;
	}
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte",
			"Ohne Root-Rechte kann kein Host angelegt werden.");
		return 1;
	}

	// Der Dialog bleibt offen und legt bei jedem Klick auf "Host hinzufügen"
	// sofort einen weiteren Host an -- genau wie im Original-Assistenten.
	NewHostDialog dlg(this, this, contextZoneIdx, z.name);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DnsManager::onNewCname(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];
	if (z.file.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Keine Zonendatei", "Für diese Zone ist keine Zonendatei bekannt.");
		return 1;
	}
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Alias angelegt werden.");
		return 1;
	}
	NewAliasDialog dlg(this, this, contextZoneIdx, z.name);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DnsManager::onNewMx(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];
	if (z.file.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Keine Zonendatei", "Für diese Zone ist keine Zonendatei bekannt.");
		return 1;
	}
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Mailserver angelegt werden.");
		return 1;
	}
	NewMxDialog dlg(this, this, contextZoneIdx, z.name);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DnsManager::onNewPtr(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];
	if (z.file.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Keine Zonendatei", "Für diese Zone ist keine Zonendatei bekannt.");
		return 1;
	}
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Zeiger angelegt werden.");
		return 1;
	}
	// Netzwerk-Praefix aus dem Zonennamen ableiten: "c.b.a.in-addr.arpa" -> "a.b.c"
	FXString netPrefix = z.name;
	int p = netPrefix.find(".in-addr.arpa");
	if (p >= 0) netPrefix = netPrefix.left(p);
	std::vector<std::string> octs;
	std::istringstream iss(std::string(netPrefix.text()));
	std::string o;
	while (std::getline(iss, o, '.')) octs.push_back(o);
	FXString displayPrefix = netPrefix;
	if (octs.size() == 3) displayPrefix = FXString(octs[2].c_str()) + "." + octs[1].c_str() + "." + octs[0].c_str();

	NewPtrDialog dlg(this, this, contextZoneIdx, z.name, displayPrefix);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

long DnsManager::onNewOther(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];
	if (z.file.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Keine Zonendatei", "Für diese Zone ist keine Zonendatei bekannt.");
		return 1;
	}
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann kein Datensatz angelegt werden.");
		return 1;
	}

	OtherRecordTypeDialog typeDlg(this);
	if (!typeDlg.execute(PLACEMENT_OWNER)) return 1;
	int sel = typeDlg.getSelected();
	FXString zoneName = z.name;
	FXString err;

	if (sel == 0) { // Namenserver (NS)
		GenericPropsDialog dlg(this, "Neuer Namenserver", "Neuer Namenserver in Zone: " + zoneName,
			{ "Name (bei Nichtangabe wird übergeordnete Domäne verwendet):", "Nameserver (FQDN):" },
			{ FXString(""), FXString("") });
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		FXString name = dlg.getValue(0).trim();
		FXString target = dlg.getValue(1).trim();
		if (target.empty()) { FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte einen Nameserver angeben."); return 1; }
		if (target[target.length()-1] != '.') target += ".";
		FXString rname = name.empty() ? FXString("@") : name;
		FXString fullLine = rname + "\tIN\tNS\t" + target;
		if (appendZoneRecord(contextZoneIdx, fullLine, err)) {
			statuslbl->setText("Namenserver " + target + " in Zone " + zoneName + " angelegt.");
			FXMessageBox::information(this, MBOX_OK, "Neuer Namenserver",
				"Der Namenserverdatensatz für \"%s\" wurde erfolgreich erstellt.", target.text());
		} else FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", err.text());

	} else if (sel == 1) { // Text (TXT)
		GenericPropsDialog dlg(this, "Neuer Textdatensatz", "Neuer Textdatensatz in Zone: " + zoneName,
			{ "Name (bei Nichtangabe wird übergeordnete Domäne verwendet):", "Text:" },
			{ FXString(""), FXString("") });
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		FXString name = dlg.getValue(0).trim();
		FXString text = dlg.getValue(1);
		FXString rname = name.empty() ? FXString("@") : name;
		FXString fullLine = rname + "\tIN\tTXT\t\"" + text + "\"";
		if (appendZoneRecord(contextZoneIdx, fullLine, err)) {
			statuslbl->setText("Textdatensatz in Zone " + zoneName + " angelegt.");
			FXMessageBox::information(this, MBOX_OK, "Neuer Textdatensatz",
				"Der Textdatensatz für \"%s\" wurde erfolgreich erstellt.", rname.text());
		} else FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", err.text());

	} else if (sel == 2) { // Dienst (SRV)
		GenericPropsDialog dlg(this, "Neuer Dienstdatensatz", "Neuer Dienstdatensatz in Zone: " + zoneName,
			{ "Dienst (z.B. _sip._tcp):", "Priorität:", "Gewichtung:", "Port:", "Zielhost (FQDN):" },
			{ FXString(""), FXString("0"), FXString("0"), FXString("0"), FXString("") });
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		FXString svc = dlg.getValue(0).trim();
		FXString prio = dlg.getValue(1).trim();
		FXString weight = dlg.getValue(2).trim();
		FXString port = dlg.getValue(3).trim();
		FXString target = dlg.getValue(4).trim();
		if (svc.empty() || target.empty()) {
			FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte Dienst und Zielhost angeben.");
			return 1;
		}
		if (target[target.length()-1] != '.') target += ".";
		FXString fullLine = svc + "\tIN\tSRV\t" + prio + "\t" + weight + "\t" + port + "\t" + target;
		if (appendZoneRecord(contextZoneIdx, fullLine, err)) {
			statuslbl->setText("Dienstdatensatz " + svc + " in Zone " + zoneName + " angelegt.");
			FXMessageBox::information(this, MBOX_OK, "Neuer Dienstdatensatz",
				"Der Dienstdatensatz für \"%s\" wurde erfolgreich erstellt.", svc.text());
		} else FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", err.text());

	} else if (sel == 3) { // IPv6-Host (AAAA)
		GenericPropsDialog dlg(this, "Neuer IPv6-Host", "Neuer IPv6-Host in Zone: " + zoneName,
			{ "Name (bei Nichtangabe wird übergeordnete Domäne verwendet):", "IPv6-Adresse:" },
			{ FXString(""), FXString("::1") });
		if (!dlg.execute(PLACEMENT_OWNER)) return 1;
		FXString name = dlg.getValue(0).trim();
		FXString ip6 = dlg.getValue(1).trim();
		if (ip6.empty()) { FXMessageBox::error(this, MBOX_OK, "Fehler", "Bitte eine IPv6-Adresse angeben."); return 1; }
		FXString rname = name.empty() ? FXString("@") : name;
		FXString fullLine = rname + "\tIN\tAAAA\t" + ip6;
		if (appendZoneRecord(contextZoneIdx, fullLine, err)) {
			statuslbl->setText("IPv6-Host " + rname + " (" + ip6 + ") in Zone " + zoneName + " angelegt.");
			FXMessageBox::information(this, MBOX_OK, "Neuer IPv6-Host",
				"Der IPv6-Hostdatensatz für \"%s\" wurde erfolgreich erstellt.", rname.text());
		} else FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", err.text());
	}
	return 1;
}

long DnsManager::onZoneProperties(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];

	long serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
	bool soaOk = !z.file.empty() && parseSoaFields(z.file, serial, refresh, retry, expire, minimum);

	FXString networkId;
	if (z.isReverse) {
		FXString netPrefix = z.name;
		int p = netPrefix.find(".in-addr.arpa");
		if (p >= 0) netPrefix = netPrefix.left(p);
		std::vector<std::string> octs;
		std::istringstream iss(std::string(netPrefix.text()));
		std::string o;
		while (std::getline(iss, o, '.')) octs.push_back(o);
		networkId = (octs.size() == 3)
			? FXString(octs[2].c_str()) + "." + octs[1].c_str() + "." + octs[0].c_str() + ".0/24"
			: netPrefix;
	}

	ZonePropertiesDialog dlg(this, z.name, z.file, serial, refresh, retry, expire, minimum, soaOk, z.isReverse, networkId);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

// Gemeinsame Kern-Logik zum Anhaengen eines Ressourcendatensatzes: liest die
// Zonendatei, erhoeht die SOA-Serial um 1, haengt "fullLine" an, schreibt
// als root zurueck und stoesst "rndc reload" an. Wird von
// createHostRecord/createCnameRecord/createMxRecord genutzt.
bool DnsManager::appendZoneRecord(int zoneIdx, const FXString& fullLine, FXString& errorMsg) {
	if (zoneIdx < 0 || zoneIdx >= (int)zones.size()) { errorMsg = "Ungültige Zone."; return false; }
	ZoneInfo z = zones[zoneIdx];
	if (z.file.empty()) { errorMsg = "Für diese Zone ist keine Zonendatei bekannt."; return false; }

	std::ifstream in(z.file.text());
	std::vector<std::string> lines;
	std::string line;
	bool bumped = false;
	while (std::getline(in, line)) {
		if (!bumped && line.find("Serial") != std::string::npos) {
			std::string digits;
			size_t dpos = std::string::npos;
			for (size_t i = 0; i < line.size(); ++i) {
				if (isdigit((unsigned char)line[i])) {
					if (digits.empty()) dpos = i;
					digits += line[i];
				} else if (!digits.empty()) {
					break;
				}
			}
			if (!digits.empty()) {
				long val = atol(digits.c_str()) + 1;
				line.replace(dpos, digits.size(), std::to_string(val));
				bumped = true;
			}
		}
		lines.push_back(line);
	}
	in.close();

	std::string newContent;
	for (auto& l : lines) newContent += l + "\n";
	newContent += std::string(fullLine.text()) + "\n";

	if (!writeFileAsRoot(z.file, newContent.c_str())) {
		errorMsg = "Fehler beim Schreiben der Zonendatei.";
		return false;
	}

	runAsRoot({ FXString("rndc"), FXString("reload"), z.name });
	onRefresh(NULL, 0, NULL);
	return true;
}

// Legt einen A-Record an, ergaenzt best-effort einen PTR-Eintrag.
// Wird von NewHostDialog::onAddHost aufgerufen (siehe unten).
bool DnsManager::createHostRecord(int zoneIdx, const FXString& host, const FXString& ip, bool wantPtr, FXString& errorMsg) {
	if (zoneIdx < 0 || zoneIdx >= (int)zones.size()) { errorMsg = "Ungültige Zone."; return false; }
	FXString zoneName = zones[zoneIdx].name;

	FXString fullLine = host + "\tIN\tA\t" + ip;
	if (!appendZoneRecord(zoneIdx, fullLine, errorMsg)) return false;

	// PTR-Eintrag best-effort: nur falls gewuenscht und eine passende
	// klassische /24-Reverse-Zone (c.b.a.in-addr.arpa) bereits existiert.
	if (wantPtr) {
		std::vector<std::string> octs;
		std::istringstream iss(std::string(ip.text()));
		std::string o;
		while (std::getline(iss, o, '.')) octs.push_back(o);
		if (octs.size() == 4) {
			FXString revZoneName = FXString(octs[2].c_str()) + "." + octs[1].c_str() + "." + octs[0].c_str() + ".in-addr.arpa";
			for (auto& zi : zones) {
				if (zi.name == revZoneName && !zi.file.empty()) {
					std::ifstream rin(zi.file.text());
					std::string rcontent((std::istreambuf_iterator<char>(rin)), std::istreambuf_iterator<char>());
					rin.close();
					FXString ptrLine = FXString(octs[3].c_str()) + "\tIN\tPTR\t" + host + "." + zoneName + ".\n";
					FXString newRevContent = FXString(rcontent.c_str()) + ptrLine;
					writeFileAsRoot(zi.file, newRevContent);
					runAsRoot({ FXString("rndc"), FXString("reload"), zi.name });
					break;
				}
			}
		}
	}

	statuslbl->setText("Host " + host + " (" + ip + ") in Zone " + zoneName + " angelegt.");
	return true;
}

// Legt einen CNAME-Alias an. Aufgerufen von NewAliasDialog::onAddAlias.
bool DnsManager::createCnameRecord(int zoneIdx, const FXString& alias, const FXString& target, FXString& errorMsg) {
	if (zoneIdx < 0 || zoneIdx >= (int)zones.size()) { errorMsg = "Ungültige Zone."; return false; }
	FXString zoneName = zones[zoneIdx].name;

	FXString aliasName = alias.empty() ? FXString("@") : alias;
	FXString targetFqdn = target;
	if (!targetFqdn.empty() && targetFqdn[targetFqdn.length()-1] != '.') targetFqdn += ".";
	if (targetFqdn.empty()) { errorMsg = "Bitte einen Zielhost angeben."; return false; }

	FXString fullLine = aliasName + "\tIN\tCNAME\t" + targetFqdn;
	if (!appendZoneRecord(zoneIdx, fullLine, errorMsg)) return false;

	statuslbl->setText("Alias " + aliasName + " -> " + targetFqdn + " in Zone " + zoneName + " angelegt.");
	return true;
}

// Legt einen MX-Eintrag an. Aufgerufen von NewMxDialog::onAddMx.
bool DnsManager::createMxRecord(int zoneIdx, const FXString& name, const FXString& target, int priority, FXString& errorMsg) {
	if (zoneIdx < 0 || zoneIdx >= (int)zones.size()) { errorMsg = "Ungültige Zone."; return false; }
	FXString zoneName = zones[zoneIdx].name;

	FXString rname = name.empty() ? FXString("@") : name;
	FXString targetFqdn = target;
	if (!targetFqdn.empty() && targetFqdn[targetFqdn.length()-1] != '.') targetFqdn += ".";
	if (targetFqdn.empty()) { errorMsg = "Bitte einen Mailserver angeben."; return false; }

	FXString fullLine = rname + "\tIN\tMX\t" + FXString(std::to_string(priority).c_str()) + "\t" + targetFqdn;
	if (!appendZoneRecord(zoneIdx, fullLine, errorMsg)) return false;

	statuslbl->setText("Mailserver " + targetFqdn + " (Priorität " + FXString(std::to_string(priority).c_str()) + ") in Zone " + zoneName + " angelegt.");
	return true;
}

// Legt einen PTR-Zeiger in einer Reverse-Zone an. Aufgerufen von
// NewPtrDialog::onAddPtr.
bool DnsManager::createPtrRecord(int zoneIdx, const FXString& lastOctet, const FXString& hostFqdn, FXString& errorMsg) {
	if (zoneIdx < 0 || zoneIdx >= (int)zones.size()) { errorMsg = "Ungültige Zone."; return false; }
	FXString zoneName = zones[zoneIdx].name;

	if (lastOctet.empty()) { errorMsg = "Bitte die Host-IP-Nummer angeben."; return false; }
	FXString targetFqdn = hostFqdn;
	if (!targetFqdn.empty() && targetFqdn[targetFqdn.length()-1] != '.') targetFqdn += ".";
	if (targetFqdn.empty()) { errorMsg = "Bitte einen Hostnamen angeben."; return false; }

	FXString fullLine = lastOctet + "\tIN\tPTR\t" + targetFqdn;
	if (!appendZoneRecord(zoneIdx, fullLine, errorMsg)) return false;

	statuslbl->setText("Zeiger " + lastOctet + " -> " + targetFqdn + " in Zone " + zoneName + " angelegt.");
	return true;
}

// Die folgenden Handler muessen nach der vollstaendigen
// DnsManager-Definition stehen, da sie auf deren Methoden zugreifen
// (die Dialoge kennen DnsManager bis hierher nur als Vorwaertsdeklaration).

long NewHostDialog::onAddHost(FXObject*, FXSelector, void*) {
	FXString host = hostField->getText().trim();
	FXString ip = ip1->getText() + "." + ip2->getText() + "." + ip3->getText() + "." + ip4->getText();
	if (host.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Name fehlt", "Bitte einen Hostnamen eingeben.");
		return 1;
	}
	FXString errorMsg;
	if (mgr->createHostRecord(zoneIdx, host, ip, ptrCheck->getCheck(), errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neuer Host",
			"Der Hostdatensatz für \"%s\" wurde erfolgreich erstellt.", host.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long NewAliasDialog::onAddAlias(FXObject*, FXSelector, void*) {
	FXString alias = aliasField->getText().trim();
	FXString target = targetField->getText().trim();
	if (target.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Zielhost fehlt", "Bitte einen Zielhost (FQDN) eingeben.");
		return 1;
	}
	FXString errorMsg;
	if (mgr->createCnameRecord(zoneIdx, alias, target, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neuer Alias",
			"Der Aliasdatensatz für \"%s\" wurde erfolgreich erstellt.", alias.empty() ? "@" : alias.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long NewMxDialog::onAddMx(FXObject*, FXSelector, void*) {
	FXString name = nameField->getText().trim();
	FXString target = targetField->getText().trim();
	int prio = atoi(prioField->getText().text());
	if (target.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Mailserver fehlt", "Bitte einen Mailserver (FQDN) eingeben.");
		return 1;
	}
	FXString errorMsg;
	if (mgr->createMxRecord(zoneIdx, name, target, prio, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neuer Mailserver",
			"Der Mailserverdatensatz für \"%s\" wurde erfolgreich erstellt.", target.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

long NewPtrDialog::onAddPtr(FXObject*, FXSelector, void*) {
	FXString lastOctet = lastOctetField->getText().trim();
	FXString host = hostField->getText().trim();
	if (lastOctet.empty()) {
		FXMessageBox::error(this, MBOX_OK, "IP-Nummer fehlt", "Bitte die Host-IP-Nummer eingeben.");
		return 1;
	}
	if (host.empty()) {
		FXMessageBox::error(this, MBOX_OK, "Hostname fehlt", "Bitte einen Hostnamen (FQDN) eingeben.");
		return 1;
	}
	FXString errorMsg;
	if (mgr->createPtrRecord(zoneIdx, lastOctet, host, errorMsg)) {
		FXMessageBox::information(this, MBOX_OK, "Neuer Zeiger",
			"Der Zeigerdatensatz für \"%s\" wurde erfolgreich erstellt.", lastOctet.text());
		resetFields();
	} else {
		FXMessageBox::error(this, MBOX_OK, "Fehler", "%s", errorMsg.text());
	}
	return 1;
}

int DnsManager::currentZoneIdxFromTree() {
	FXTreeItem* curZone = tree->getCurrentItem();
	for (size_t i = 0; i < zoneItems.size(); ++i) if (zoneItems[i] == curZone) return (int)i;
	return -1;
}

void DnsManager::openHostProperties(int zoneIdx, int recIdx) {
	if (zoneIdx < 0 || zoneIdx >= (int)zoneRecords.size()) return;
	if (recIdx < 0 || recIdx >= (int)zoneRecords[zoneIdx].size()) return;
	ResourceRecord rr = zoneRecords[zoneIdx][recIdx];
	if (rr.type == "Autoritätsursprung") return; // SOA nicht editierbar in diesem Prototyp

	FXString zoneName = zones[zoneIdx].name;
	FXString zoneFile = zones[zoneIdx].file;
	FXString hostDisplay = (rr.rawName == "@") ? zoneName : rr.rawName;

	if (rr.type == "Host") {
		HostPropertiesDialog dlg(this, zoneName, zoneFile, hostDisplay, rr.rawIp);
		if (dlg.execute(PLACEMENT_OWNER)) {
			FXString newIp = dlg.getNewIp();
			if (newIp != rr.rawIp && !zoneFile.empty()) {
				if (updateARecord(zoneFile, hostDisplay, rr.rawIp, newIp, zoneName)) {
					loadZones();
					showZoneRecords(zoneIdx);
					statuslbl->setText("Host " + hostDisplay + " aktualisiert auf " + newIp);
				} else {
					statuslbl->setText("Konnte A-Record nicht in der Zonendatei finden/ändern.");
				}
			}
		}
		return;
	}

	FXString typeKeyword = typeKeywordFor(rr.type);
	if (typeKeyword.empty()) return; // unbekannter Typ

	FXString info = "Eigenschaften von " + hostDisplay + " (" + rr.type + ") in Zone " + zoneName;

	if (rr.type == "Mailaustausch") {
		// rr.data hat die Form "[prio] ziel" -- fuer die Bearbeitung auftrennen
		FXString d = rr.data;
		int lb = d.find('['), rb = d.find(']');
		FXString prio = (lb >= 0 && rb > lb) ? d.mid(lb+1, rb-lb-1) : FXString("10");
		FXString target = (rb >= 0) ? d.mid(rb+1, d.length()-rb-1).trim() : d;

		GenericPropsDialog dlg(this, "Eigenschaften von " + hostDisplay, info,
			{ "Priorität:", "Zielhost (FQDN):" }, { prio, target });
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		FXString newTarget = dlg.getValue(1).trim();
		if (!newTarget.empty() && newTarget[newTarget.length()-1] != '.') newTarget += ".";
		FXString fullLine = rr.rawName + "\tIN\tMX\t" + dlg.getValue(0).trim() + "\t" + newTarget;
		FXString err;
		if (modifyRecordLine(zoneIdx, rr.rawName, typeKeyword, fullLine, err)) {
			showZoneRecords(zoneIdx);
			statuslbl->setText("Mailserver für " + hostDisplay + " aktualisiert.");
		} else statuslbl->setText(err);

	} else if (rr.type == "Dienst") {
		// rr.data hat die Form "[prio][weight][port] ziel"
		FXString d = rr.data;
		std::vector<FXString> nums;
		int pos = 0;
		while (true) {
			int lb = d.find('[', pos), rb = d.find(']', pos);
			if (lb < 0 || rb < 0) break;
			nums.push_back(d.mid(lb+1, rb-lb-1));
			pos = rb + 1;
		}
		FXString target = (pos < (int)d.length()) ? d.mid(pos, d.length()-pos).trim() : FXString("");
		FXString prio = nums.size() > 0 ? nums[0] : FXString("0");
		FXString weight = nums.size() > 1 ? nums[1] : FXString("0");
		FXString port = nums.size() > 2 ? nums[2] : FXString("0");

		GenericPropsDialog dlg(this, "Eigenschaften von " + hostDisplay, info,
			{ "Priorität:", "Gewichtung:", "Port:", "Zielhost (FQDN):" }, { prio, weight, port, target });
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		FXString newTarget = dlg.getValue(3).trim();
		if (!newTarget.empty() && newTarget[newTarget.length()-1] != '.') newTarget += ".";
		FXString fullLine = rr.rawName + "\tIN\tSRV\t" + dlg.getValue(0).trim() + "\t" + dlg.getValue(1).trim() + "\t" + dlg.getValue(2).trim() + "\t" + newTarget;
		FXString err;
		if (modifyRecordLine(zoneIdx, rr.rawName, typeKeyword, fullLine, err)) {
			showZoneRecords(zoneIdx);
			statuslbl->setText("Dienstdatensatz für " + hostDisplay + " aktualisiert.");
		} else statuslbl->setText(err);

	} else {
		// Alias/Zeiger/Namenserver/IPv6-Host: ein Datenfeld; Text: Freitext
		FXString label = "Wert:";
		if (rr.type == "Alias" || rr.type == "Zeiger") label = "Zielhost (FQDN):";
		else if (rr.type == "Namenserver") label = "Nameserver (FQDN):";
		else if (rr.type == "IPv6-Host") label = "IPv6-Adresse:";
		else if (rr.type == "Text") label = "Text:";

		GenericPropsDialog dlg(this, "Eigenschaften von " + hostDisplay, info, { label }, { rr.data });
		if (!dlg.execute(PLACEMENT_OWNER)) return;
		FXString newVal = dlg.getValue(0).trim();

		FXString fullLine;
		if (rr.type == "Text") {
			fullLine = rr.rawName + "\tIN\tTXT\t\"" + dlg.getValue(0) + "\"";
		} else {
			if (!newVal.empty() && newVal[newVal.length()-1] != '.') newVal += ".";
			fullLine = rr.rawName + "\tIN\t" + typeKeyword + "\t" + newVal;
		}
		FXString err;
		if (modifyRecordLine(zoneIdx, rr.rawName, typeKeyword, fullLine, err)) {
			showZoneRecords(zoneIdx);
			statuslbl->setText(rr.type + "-Eintrag für " + hostDisplay + " aktualisiert.");
		} else statuslbl->setText(err);
	}
}

// Generisches Bearbeiten eines Ressourcendatensatzes: findet die Zeile
// anhand von Rohname + Typ-Schluesselwort (robust ueber einen Mini-Parser,
// der die Zonendatei wie parseZoneFile() durchgeht -- nicht per simplem
// Substring-Suchen, damit z.B. SRV/TXT mit Sonderzeichen sicher matchen),
// ersetzt die Zeile durch "newFullLine", erhoeht die SOA-Serial und
// schreibt als root zurueck.
bool DnsManager::modifyRecordLine(int zoneIdx, const FXString& rawName, const FXString& typeKeyword,
                                   const FXString& newFullLine, FXString& errorMsg) {
	if (zoneIdx < 0 || zoneIdx >= (int)zones.size()) { errorMsg = "Ungültige Zone."; return false; }
	ZoneInfo z = zones[zoneIdx];
	if (z.file.empty()) { errorMsg = "Für diese Zone ist keine Zonendatei bekannt."; return false; }

	std::ifstream in(z.file.text());
	std::vector<std::string> lines;
	std::string line;
	std::string lastName = "@";
	bool changed = false, bumped = false, inSoa = false;

	while (std::getline(in, line)) {
		if (!bumped) {
			size_t sp = line.find("Serial");
			if (sp != std::string::npos) {
				std::string digits; size_t dpos = std::string::npos;
				for (size_t i = 0; i < line.size(); ++i) {
					if (isdigit((unsigned char)line[i])) { if (digits.empty()) dpos = i; digits += line[i]; }
					else if (!digits.empty()) break;
				}
				if (!digits.empty()) {
					long val = atol(digits.c_str()) + 1;
					line.replace(dpos, digits.size(), std::to_string(val));
					bumped = true;
				}
			}
		}

		std::string codeOnly = line;
		size_t sc = codeOnly.find(';');
		if (sc != std::string::npos) codeOnly = codeOnly.substr(0, sc);

		if (inSoa) {
			if (codeOnly.find(')') != std::string::npos) inSoa = false;
			lines.push_back(line);
			continue;
		}
		if (codeOnly.find_first_not_of(" \t\r\n") == std::string::npos || (!codeOnly.empty() && codeOnly[0] == '$')) {
			lines.push_back(line);
			continue;
		}

		std::istringstream iss(codeOnly);
		std::vector<std::string> tok;
		std::string t;
		while (iss >> t) tok.push_back(t);

		bool thisLineChanged = false;
		if (!tok.empty()) {
			size_t idx = 0;
			std::string curName = lastName;
			if (tok[0] != "IN" && tok[0] != "in") { curName = tok[0]; lastName = curName; idx = 1; }
			if (idx < tok.size() && (tok[idx] == "IN" || tok[idx] == "in")) idx++;
			if (idx < tok.size()) {
				std::string typ = tok[idx];
				std::transform(typ.begin(), typ.end(), typ.begin(), ::toupper);
				if (typ == "SOA" && codeOnly.find(')') == std::string::npos) inSoa = true;
				if (!changed && curName == std::string(rawName.text()) && typ == std::string(typeKeyword.text())) {
					lines.push_back(std::string(newFullLine.text()));
					changed = true;
					thisLineChanged = true;
				}
			}
		}
		if (!thisLineChanged) lines.push_back(line);
	}
	in.close();

	if (!changed) { errorMsg = "Konnte den Eintrag nicht in der Zonendatei finden."; return false; }

	std::string newContent;
	for (auto& l : lines) newContent += l + "\n";
	if (!writeFileAsRoot(z.file, newContent.c_str())) { errorMsg = "Fehler beim Schreiben der Zonendatei."; return false; }

	runAsRoot({ FXString("rndc"), FXString("reload"), z.name });
	onRefresh(NULL, 0, NULL);
	return true;
}

long DnsManager::onListDouble(FXObject*, FXSelector, void*) {
	int zoneIdx = currentZoneIdxFromTree();
	if (zoneIdx < 0) return 1;
	openHostProperties(zoneIdx, list->getCurrentItem());
	return 1;
}

long DnsManager::onProperties(FXObject*, FXSelector, void*) {
	int zoneIdx = currentZoneIdxFromTree();
	if (zoneIdx < 0) return 1;
	openHostProperties(zoneIdx, list->getCurrentItem());
	return 1;
}

long DnsManager::onListRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	int zoneIdx = currentZoneIdxFromTree();
	if (zoneIdx < 0) return 1;

	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx < 0 || idx >= (int)zoneRecords[zoneIdx].size()) return 1;
	list->setCurrentItem(idx);
	list->selectItem(idx);

	ResourceRecord& rr = zoneRecords[zoneIdx][idx];

	FXMenuPane menu(this);
	if (rr.type != "Autoritätsursprung") {
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_PROPERTIES);
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Löschen", NULL, this, ID_DELETERECORD);
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DnsManager::onDeleteRecord(FXObject*, FXSelector, void*) {
	int zoneIdx = currentZoneIdxFromTree();
	if (zoneIdx < 0) return 1;
	int sel = list->getCurrentItem();
	if (sel < 0 || sel >= (int)zoneRecords[zoneIdx].size()) return 1;

	ResourceRecord rr = zoneRecords[zoneIdx][sel];
	if (rr.type == "Autoritätsursprung") return 1; // SOA nicht loeschbar

	ZoneInfo z = zones[zoneIdx];
	if (z.file.empty()) return 1;
	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann nichts gelöscht werden.");
		return 1;
	}

	FXString hostDisplay = rr.rawName;
	if (FXMessageBox::question(this, MBOX_YES_NO, "Löschen bestätigen",
	        "%s-Eintrag \"%s\" wirklich löschen?", rr.type.text(), hostDisplay.text()) != MBOX_CLICKED_YES) {
		return 1;
	}

	FXString typeKeyword = typeKeywordFor(rr.type);
	FXString errorMsg;
	// Robustes, token-basiertes Loeschen (wie modifyRecordLine, aber die
	// gefundene Zeile wird weggelassen statt ersetzt): identisch aufgebaut,
	// damit auch Datensaetze mit Sonderzeichen (TXT/SRV) sicher matchen.
	std::ifstream in(z.file.text());
	std::vector<std::string> lines;
	std::string line;
	std::string lastName = "@";
	bool removed = false, bumped = false, inSoa = false;

	while (std::getline(in, line)) {
		if (!bumped) {
			size_t sp = line.find("Serial");
			if (sp != std::string::npos) {
				std::string digits; size_t dpos = std::string::npos;
				for (size_t i = 0; i < line.size(); ++i) {
					if (isdigit((unsigned char)line[i])) { if (digits.empty()) dpos = i; digits += line[i]; }
					else if (!digits.empty()) break;
				}
				if (!digits.empty()) {
					long val = atol(digits.c_str()) + 1;
					line.replace(dpos, digits.size(), std::to_string(val));
					bumped = true;
				}
			}
		}

		std::string codeOnly = line;
		size_t sc = codeOnly.find(';');
		if (sc != std::string::npos) codeOnly = codeOnly.substr(0, sc);

		if (inSoa) {
			if (codeOnly.find(')') != std::string::npos) inSoa = false;
			lines.push_back(line);
			continue;
		}
		if (codeOnly.find_first_not_of(" \t\r\n") == std::string::npos || (!codeOnly.empty() && codeOnly[0] == '$')) {
			lines.push_back(line);
			continue;
		}

		std::istringstream iss(codeOnly);
		std::vector<std::string> tok;
		std::string t;
		while (iss >> t) tok.push_back(t);

		bool skipThisLine = false;
		if (!tok.empty()) {
			size_t idx = 0;
			std::string curName = lastName;
			if (tok[0] != "IN" && tok[0] != "in") { curName = tok[0]; lastName = curName; idx = 1; }
			if (idx < tok.size() && (tok[idx] == "IN" || tok[idx] == "in")) idx++;
			if (idx < tok.size()) {
				std::string typ = tok[idx];
				std::transform(typ.begin(), typ.end(), typ.begin(), ::toupper);
				if (typ == "SOA" && codeOnly.find(')') == std::string::npos) inSoa = true;
				if (!removed && curName == std::string(hostDisplay.text()) && typ == std::string(typeKeyword.text())) {
					removed = true;
					skipThisLine = true;
				}
			}
		}
		if (!skipThisLine) lines.push_back(line);
	}
	in.close();

	if (!removed) {
		statuslbl->setText("Konnte den Eintrag nicht in der Zonendatei finden.");
		return 1;
	}

	std::string newContent;
	for (auto& l : lines) newContent += l + "\n";

	if (writeFileAsRoot(z.file, newContent.c_str())) {
		runAsRoot({ FXString("rndc"), FXString("reload"), z.name });
		loadZones();
		showZoneRecords(zoneIdx);
		statuslbl->setText(rr.type + "-Eintrag \"" + hostDisplay + "\" gelöscht.");
	} else {
		statuslbl->setText("Fehler beim Löschen des Eintrags.");
	}
	return 1;
}

long DnsManager::onDeleteZone(FXObject*, FXSelector, void*) {
	if (contextZoneIdx < 0 || contextZoneIdx >= (int)zones.size()) return 1;
	ZoneInfo z = zones[contextZoneIdx];

	if (!g_haveRoot) {
		FXMessageBox::error(this, MBOX_OK, "Keine Root-Rechte", "Ohne Root-Rechte kann keine Zone gelöscht werden.");
		return 1;
	}
	if (FXMessageBox::question(this, MBOX_YES_NO, "Zone löschen",
	        "Zone \"%s\" wirklich löschen? Die Zonendatei wird ebenfalls entfernt.", z.name.text())
	        != MBOX_CLICKED_YES) {
		return 1;
	}

	// Zugehoerigen "zone "NAME" { ... };"-Block aus named.conf.local entfernen
	std::ifstream in(NAMED_CONF_LOCAL);
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();

	FXString marker = "zone \"" + z.name + "\"";
	int p = FXString(content.c_str()).find(marker);
	FXString newConf = content.c_str();
	if (p >= 0) {
		int blockEnd = newConf.find("};", p);
		if (blockEnd >= 0) {
			blockEnd += 2;
			newConf = newConf.left(p) + newConf.mid(blockEnd, newConf.length() - blockEnd);
		}
	}

	bool ok = writeFileAsRoot(NAMED_CONF_LOCAL, newConf);
	if (ok && !z.file.empty()) runAsRoot({ FXString("rm"), FXString("-f"), z.file });
	if (ok) {
		runAsRoot({ FXString("rndc"), FXString("reconfig") });
		onRefresh(NULL, 0, NULL);
		statuslbl->setText("Zone " + z.name + " gelöscht.");
	} else {
		statuslbl->setText("Fehler beim Löschen der Zone " + z.name + ".");
	}
	return 1;
}

long DnsManager::onRefresh(FXObject*, FXSelector, void*) {
	list->clearItems();
	loadZones();
	statuslbl->setText("Aktualisiert.");
	return 1;
}

long DnsManager::onAbout(FXObject*, FXSelector, void*) {
	FXMessageBox::information(this, MBOX_OK, "Über DNS",
		"DNS-Manager für ice2k\n\n"
		"Ein Nachbau des Windows 2000 DNS-Manager-Snapins.\n"
		"Liest/schreibt BIND9-Zonen aus /etc/bind/.");
	return 1;
}

void DnsManager::create() {
	FXMainWindow::create();
	show(PLACEMENT_SCREEN);
}

int main(int argc, char* argv[]) {
	FXApp application("DnsMgr", "Ice2KProj");
	app = &application;
	application.init(argc, argv);

	// Root-Rechte anfragen, BEVOR das Hauptfenster aufgebaut wird -- exakt
	// wie sysdm/timedate im ice2k-Repo: i2ksudo zeigt die GUI-Passwortabfrage
	// im Win2k-Stil. Dank sudo-Timestamp-Caching muss man das i.d.R. nur
	// einmal pro Sitzung eingeben; alle folgenden runAsRoot()-Aufrufe
	// (Zonen/Hosts anlegen, IPs aendern, rndc reload) fragen dann nicht mehr.
	g_haveRoot = (runAsRoot({ FXString("true") }) == 0);

	DnsManager* win = new DnsManager(&application);
	application.create();
	win->show(PLACEMENT_SCREEN);

	if (!g_haveRoot) {
		FXMessageBox::warning(win, MBOX_OK, "Keine Root-Rechte",
			"Es wurden keine Root-Rechte erlangt.\n\n"
			"Der DNS-Manager kann bestehende Zonen weiterhin anzeigen, aber keine\n"
			"neuen Zonen/Hosts anlegen, keine Einträge ändern und keine Demo-Zone\n"
			"nach /etc/bind/ schreiben.");
	}

	return application.run();
}
