// diskcore.cpp -- siehe diskcore.h
#include "diskcore.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <functional>
#include <sstream>

namespace disk {

// ---------------------------------------------------------------------
// Kleiner JSON-Leser -- lsblk und LVM liefern JSON; ein vollständiger
// Leser ist hier kürzer und sicherer als Suchen in Zeichenketten.
// ---------------------------------------------------------------------
struct Json {
	enum Kind { NUL, BOOL, NUM, STR, ARR, OBJ } kind = NUL;
	bool b = false;
	double n = 0;
	std::string s;
	std::vector<Json> arr;
	std::vector<std::pair<std::string, Json>> obj;

	const Json& operator[](const std::string& key) const {
		static Json none;
		for (auto& kv : obj) if (kv.first == key) return kv.second;
		return none;
	}
	std::string str() const {
		if (kind == STR) return s;
		if (kind == NUM) { char buf[32]; snprintf(buf, sizeof(buf), "%.0f", n); return buf; }
		if (kind == BOOL) return b ? "true" : "false";
		return "";
	}
	uint64_t u64() const {
		if (kind == NUM) return (uint64_t)n;
		if (kind == STR) return strtoull(s.c_str(), NULL, 10);   // "264241152B" -> Zahl
		return 0;
	}
	bool truthy() const {
		if (kind == BOOL) return b;
		if (kind == STR) return s == "1" || s == "true";
		if (kind == NUM) return n != 0;
		return false;
	}
};

class JsonParser {
	const std::string& t;
	size_t p = 0;
	void ws() { while (p < t.size() && (t[p] == ' ' || t[p] == '\n' || t[p] == '\r' || t[p] == '\t')) p++; }
	std::string parseString() {
		std::string out;
		p++;   // "
		while (p < t.size() && t[p] != '"') {
			if (t[p] == '\\' && p + 1 < t.size()) {
				char c = t[++p];
				if (c == 'n') out += '\n';
				else if (c == 't') out += '\t';
				else if (c == 'u' && p + 4 < t.size()) {
					unsigned cp = strtoul(t.substr(p + 1, 4).c_str(), NULL, 16);
					p += 4;
					// Als UTF-8 ausgeben (Basisebene genügt für Modellnamen).
					if (cp < 0x80) out += (char)cp;
					else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
					else { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
				} else out += c;
				p++;
				continue;
			}
			out += t[p++];
		}
		p++;   // "
		return out;
	}
public:
	explicit JsonParser(const std::string& text) : t(text) {}
	Json parse() {
		Json j;
		ws();
		if (p >= t.size()) return j;
		char c = t[p];
		if (c == '{') {
			j.kind = Json::OBJ;
			p++;
			ws();
			if (p < t.size() && t[p] == '}') { p++; return j; }
			while (p < t.size()) {
				ws();
				if (t[p] != '"') break;
				std::string key = parseString();
				ws();
				if (p < t.size() && t[p] == ':') p++;
				j.obj.push_back({ key, parse() });
				ws();
				if (p < t.size() && t[p] == ',') { p++; continue; }
				if (p < t.size() && t[p] == '}') { p++; break; }
				break;
			}
		} else if (c == '[') {
			j.kind = Json::ARR;
			p++;
			ws();
			if (p < t.size() && t[p] == ']') { p++; return j; }
			while (p < t.size()) {
				j.arr.push_back(parse());
				ws();
				if (p < t.size() && t[p] == ',') { p++; continue; }
				if (p < t.size() && t[p] == ']') { p++; break; }
				break;
			}
		} else if (c == '"') {
			j.kind = Json::STR;
			j.s = parseString();
		} else if (t.compare(p, 4, "true") == 0) { j.kind = Json::BOOL; j.b = true; p += 4; }
		else if (t.compare(p, 5, "false") == 0) { j.kind = Json::BOOL; p += 5; }
		else if (t.compare(p, 4, "null") == 0) { p += 4; }
		else {
			j.kind = Json::NUM;
			size_t start = p;
			while (p < t.size() && (isdigit((unsigned char)t[p]) || t[p] == '-' || t[p] == '+' || t[p] == '.' || t[p] == 'e' || t[p] == 'E')) p++;
			j.n = strtod(t.substr(start, p - start).c_str(), NULL);
		}
		return j;
	}
};

static Json parseJson(const std::string& text) {
	// LVM schreibt manchmal Warnungen vor das JSON -- ab der ersten Klammer lesen.
	size_t brace = text.find('{');
	if (brace == std::string::npos) return Json();
	std::string body = text.substr(brace);
	return JsonParser(body).parse();
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
	out.push_back(cur);
	return out;
}

// ---------------------------------------------------------------------
// Öffentliche Hilfen
// ---------------------------------------------------------------------
std::string formatSize(uint64_t bytes) {
	// Wie das Original: unter 1 GB ganze MB, darüber GB mit zwei Stellen.
	const double mb = bytes / (1024.0 * 1024.0);
	char buf[40];
	if (mb < 1) snprintf(buf, sizeof(buf), "%llu KB", (unsigned long long)(bytes / 1024));
	else if (mb < 1024) snprintf(buf, sizeof(buf), "%.0f MB", mb);
	else snprintf(buf, sizeof(buf), "%.2f GB", mb / 1024.0);
	std::string s = buf;
	for (auto& c : s) if (c == '.') c = ',';
	return s;
}

const char* kindName(SegmentKind k) {
	// Wortgleich aus dmdskres.dll (Legende, Texte 53381-53389).
	switch (k) {
		case SEG_UNALLOCATED: return "Nicht zugeordnet";
		case SEG_PRIMARY: return "Primäre Partition";
		case SEG_EXTENDED: return "Erweiterte Partition";
		case SEG_FREE: return "Freier Speicherplatz";
		case SEG_LOGICAL: return "Logisches Laufwerk";
		case SEG_SIMPLE: return "Einfacher Datenträger";
		case SEG_SPANNED: return "Übergreifender Datenträger";
		case SEG_STRIPED: return "Stripesetdatenträger";
		case SEG_MIRRORED: return "Gespiegelter Datenträger";
		case SEG_RAID5: return "RAID-5-Datenträger";
	}
	return "";
}

bool kindIsDynamic(SegmentKind k) { return k >= SEG_SIMPLE; }

std::vector<LvInfo> parseLvs(const std::string& json) {
	std::vector<LvInfo> out;
	Json root = parseJson(json);
	for (auto& rep : root["report"].arr)
		for (auto& lv : rep["lv"].arr) {
			LvInfo l;
			l.name = lv["lv_name"].str();
			l.vg = lv["vg_name"].str();
			l.segtype = lv["segtype"].str();
			l.path = lv["lv_path"].str();
			if (l.path.empty()) l.path = "/dev/" + l.vg + "/" + l.name;
			l.size = lv["lv_size"].u64();
			std::string stripes = lv["stripes"].str();
			if (!stripes.empty()) l.stripes = std::max(1, atoi(stripes.c_str()));
			l.health = lv["lv_health_status"].str();
			std::string sync = lv["sync_percent"].str();
			if (!sync.empty()) l.syncPercent = (int)strtod(sync.c_str(), NULL);
			// "devices": "/dev/sdb(0),/dev/sdc(0)"
			for (auto& d : splitOn(lv["devices"].str(), ',')) {
				std::string dev = d.substr(0, d.find('('));
				if (!dev.empty() && std::find(l.devices.begin(), l.devices.end(), dev) == l.devices.end())
					l.devices.push_back(dev);
			}
			// Hilfs-LVs von RAID/Spiegel ("[lv_rimage_0]") gehören nicht in die Liste.
			if (!l.name.empty() && l.name[0] == '[') continue;
			// Ein LV mit mehreren Segmenten steht mehrmals da -- zusammenfassen.
			auto it = std::find_if(out.begin(), out.end(), [&](const LvInfo& x) { return x.name == l.name && x.vg == l.vg; });
			if (it != out.end()) {
				for (auto& d : l.devices) if (std::find(it->devices.begin(), it->devices.end(), d) == it->devices.end()) it->devices.push_back(d);
				continue;
			}
			out.push_back(l);
		}
	return out;
}

std::vector<PvSegment> parsePvSegments(const std::string& json) {
	std::vector<PvSegment> out;
	Json root = parseJson(json);
	for (auto& rep : root["report"].arr)
		for (auto& seg : rep["pvseg"].arr) {
			PvSegment s;
			s.pv = seg["pv_name"].str();
			s.vg = seg["vg_name"].str();
			s.lv = seg["lv_name"].str();
			uint64_t extent = seg["vg_extent_size"].u64();
			if (extent == 0) extent = 4ull * 1024 * 1024;
			s.start = seg["pvseg_start"].u64() * extent;
			s.size = seg["pvseg_size"].u64() * extent;
			// RAID-Teile zeigen ihr Haupt-LV an ("[archiv_rimage_0]" -> "archiv").
			if (!s.lv.empty() && s.lv[0] == '[') {
				std::string inner = s.lv.substr(1, s.lv.find(']') - 1);
				size_t u = inner.rfind("_r");
				s.lv = u == std::string::npos ? inner : inner.substr(0, u);
			}
			out.push_back(s);
		}
	return out;
}

std::vector<PvInfo> parsePvs(const std::string& json) {
	std::vector<PvInfo> out;
	Json root = parseJson(json);
	for (auto& rep : root["report"].arr)
		for (auto& pv : rep["pv"].arr) {
			PvInfo p;
			p.name = pv["pv_name"].str();
			p.vg = pv["vg_name"].str();
			p.size = pv["pv_size"].u64();
			p.free = pv["pv_free"].u64();
			out.push_back(p);
		}
	return out;
}

std::string lvStatus(const LvInfo& lv) {
	// Texte aus dmdskres.dll: 6503 "Fehlerfrei", 6505 "Fehlerhafte
	// Redundanz", 6504 "Fehlgeschlagen". Die Synchronisierung hat im
	// Original keinen eigenen Zustand in der Liste -- hier mit Prozent.
	if (lv.health == "partial") return "Fehlerhafte Redundanz";
	if (lv.health == "refresh needed" || lv.health == "mismatches exist") return "Fehlerhafte Redundanz";
	if (!lv.health.empty()) return "Fehlgeschlagen";
	if (lv.syncPercent < 100) return "Wird neu synchronisiert (" + std::to_string(lv.syncPercent) + " %)";
	return "Fehlerfrei";
}

SegmentKind lvKind(const LvInfo& lv) {
	if (lv.segtype == "raid1" || lv.segtype == "mirror") return SEG_MIRRORED;
	if (lv.segtype.rfind("raid5", 0) == 0) return SEG_RAID5;
	if (lv.segtype == "striped" && lv.stripes > 1) return SEG_STRIPED;
	if (lv.devices.size() > 1) return SEG_SPANNED;
	return SEG_SIMPLE;
}

// ---------------------------------------------------------------------
// Einsammeln
// ---------------------------------------------------------------------
struct FsInfo { std::string type, label; };

static FsInfo probe(Runner run, const std::string& dev) {
	FsInfo f;
	std::string out;
	if (run({ "blkid", "-p", "-o", "export", dev }, out) != 0) return f;
	for (auto& line : splitLines(out)) {
		if (line.rfind("TYPE=", 0) == 0) f.type = line.substr(5);
		else if (line.rfind("LABEL=", 0) == 0) f.label = line.substr(6);
	}
	return f;
}

// parted -m: "1:1048576B:101711871B:100663296B:ext4::;"
struct PartedPart { int number = 0; uint64_t start = 0, size = 0; std::string fs, flags; };

static std::vector<PartedPart> readPartitions(Runner run, const std::string& dev, std::string& table) {
	std::vector<PartedPart> out;
	std::string raw;
	if (run({ "parted", "-m", "-s", dev, "unit", "B", "print" }, raw) != 0) return out;
	int lineNo = 0;
	for (auto& line : splitLines(raw)) {
		lineNo++;
		if (line == "BYT;") continue;
		std::vector<std::string> f = splitOn(line, ':');
		if (f.size() >= 6 && f[0].rfind("/dev/", 0) == 0) { table = f[5]; continue; }
		if (f.size() < 5) continue;
		PartedPart p;
		p.number = atoi(f[0].c_str());
		if (p.number <= 0) continue;
		p.start = strtoull(f[1].c_str(), NULL, 10);
		p.size = strtoull(f[3].c_str(), NULL, 10);
		p.fs = f[4];
		if (f.size() > 6) { p.flags = f[6]; if (!p.flags.empty() && p.flags.back() == ';') p.flags.pop_back(); }
		out.push_back(p);
	}
	return out;
}

static std::string partitionPath(const std::string& disk, int number) {
	// /dev/sda -> /dev/sda1, /dev/nvme0n1 und /dev/loop0 -> ...p1
	char last = disk.empty() ? 'x' : disk.back();
	return disk + (isdigit((unsigned char)last) ? "p" : "") + std::to_string(number);
}

Snapshot collect(Runner run) {
	Snapshot snap;
	std::string raw;
	if (run({ "lsblk", "-J", "-b", "-o", "NAME,PATH,TYPE,SIZE,RM,RO,MODEL,VENDOR,TRAN,SERIAL,MOUNTPOINT" }, raw) != 0) {
		snap.error = "lsblk ist fehlgeschlagen.";
		return snap;
	}
	Json root = parseJson(raw);

	// Mountpunkte aller Geräte (auch Partitionen) für später.
	std::map<std::string, std::string> mounts;
	std::function<void(const Json&)> walk = [&](const Json& n) {
		std::string mp = n["mountpoint"].str();
		if (!mp.empty()) mounts[n["path"].str()] = mp;
		for (auto& c : n["children"].arr) walk(c);
	};
	for (auto& d : root["blockdevices"].arr) walk(d);

	// Belegung eingehängter Dateisysteme.
	std::map<std::string, int64_t> avail;
	std::string dfOut;
	if (run({ "df", "-B1", "--output=target,avail" }, dfOut) == 0)
		for (auto& line : splitLines(dfOut)) {
			std::istringstream iss(line);
			std::string target, a;
			if (iss >> target >> a && target[0] == '/') avail[target] = strtoll(a.c_str(), NULL, 10);
		}

	// LVM
	std::string lvOut, segOut;
	run({ "lvs", "--reportformat", "json", "--units", "b", "-a",
	      "-o", "lv_name,vg_name,lv_size,segtype,stripes,devices,lv_path,lv_health_status,sync_percent" }, lvOut);
	run({ "pvs", "--segments", "--reportformat", "json", "--units", "b",
	      "-o", "pv_name,vg_name,lv_name,pvseg_start,pvseg_size,vg_extent_size" }, segOut);
	std::vector<LvInfo> lvs = parseLvs(lvOut);
	std::vector<PvSegment> pvsegs = parsePvSegments(segOut);
	std::string pvOut;
	run({ "pvs", "--reportformat", "json", "--units", "b", "-o", "pv_name,vg_name,pv_size,pv_free" }, pvOut);
	snap.pvs = parsePvs(pvOut);
	snap.pvsegs = pvsegs;
	auto lvByName = [&](const std::string& vg, const std::string& lv) -> const LvInfo* {
		for (auto& l : lvs) if (l.vg == vg && l.name == lv) return &l;
		return nullptr;
	};

	int cdIndex = 0;
	for (auto& d : root["blockdevices"].arr) {
		std::string type = d["type"].str();
		std::string path = d["path"].str();
		uint64_t size = d["size"].u64();
		if (type == "rom") {
			Disk cd;
			cd.name = d["name"].str();
			cd.path = path;
			cd.cdrom = true;
			cd.size = size;
			cd.model = d["model"].str();
			snap.disks.push_back(cd);
			cdIndex++;
			continue;
		}
		// Platten; Loop-Geräte nur, wenn sie eine Partitionstabelle oder ein
		// LVM-PV tragen (Image-Dateien zum Testen), schreibgeschützte
		// Mini-Geräte (Container, Snap) nicht.
		if (type != "disk" && type != "loop") continue;
		if (size == 0) continue;
		if (d["ro"].truthy() && type != "disk") continue;
		if (d["name"].str().rfind("zram", 0) == 0) continue;

		Disk dk;
		dk.name = d["name"].str();
		dk.path = path;
		dk.model = d["model"].str();
		dk.vendor = d["vendor"].str();
		dk.transport = d["tran"].str();
		dk.serial = d["serial"].str();
		dk.size = size;
		dk.removable = d["rm"].truthy();

		std::vector<PartedPart> parts = readPartitions(run, path, dk.table);
		FsInfo whole = probe(run, path);
		// Weder parted noch blkid kommen an das Gerät -- im Original
		// "Nicht lesbar"; dann keine erfundenen Abschnitte zeigen.
		if (dk.table.empty() && parts.empty() && whole.type.empty() && type == "disk") {
			std::string test;
			if (run({ "blkid", "-p", path }, test) != 0 && test.find("ermission") == std::string::npos &&
			    run({ "dd", "if=" + path, "of=/dev/null", "bs=512", "count=1" }, test) != 0) {
				dk.unreadable = true;
				snap.disks.push_back(dk);
				continue;
			}
		}
		// Loop-Geräte: Snap-Pakete (squashfs) und schreibgeschützte weglassen,
		// beschreibbare Image-Dateien zeigen -- auch leere, damit sich eine
		// Signatur darauf schreiben lässt.
		if (type == "loop" && (whole.type == "squashfs" || d["ro"].truthy())) continue;

		// Ohne Partitionstabelle meldet parted die Kennung "loop" und eine
		// Pseudo-Partition über das ganze Gerät. Liegt ein Dateisystem direkt
		// auf der Platte, ist das ein einziger Abschnitt -- Windows kennt den
		// Fall nicht, er wird als primäre Partition über die ganze Platte
		// gezeigt.
		if (dk.table == "loop" || (parts.empty() && !whole.type.empty() && whole.type != "LVM2_member")) {
			dk.table.clear();
			if (whole.type != "LVM2_member") {
				Segment seg;
				seg.size = size;
				if (whole.type.empty()) { seg.kind = SEG_UNALLOCATED; }
				else {
					seg.kind = SEG_PRIMARY;
					seg.device = path;
					seg.fstype = whole.type;
					seg.label = whole.label;
					if (mounts.count(path)) seg.mountpoint = mounts[path];
				}
				dk.segments.push_back(seg);
				snap.disks.push_back(dk);
				continue;
			}
			parts.clear();
		}

		if (whole.type == "LVM2_member") {
			// Ganze Platte ist PV: die LVs darauf wie dynamische Datenträger.
			dk.dynamic = true;
			uint64_t pos = 0;
			for (auto& s : pvsegs) {
				if (s.pv != path) continue;
				Segment seg;
				seg.start = s.start;
				seg.size = s.size;
				if (s.lv.empty()) { seg.kind = SEG_UNALLOCATED; }
				else {
					const LvInfo* lv = lvByName(s.vg, s.lv);
					seg.kind = lv ? lvKind(*lv) : SEG_SIMPLE;
					seg.lvName = s.lv;
					seg.vgName = s.vg;
					seg.device = lv ? lv->path : "/dev/" + s.vg + "/" + s.lv;
					if (lv) seg.status = lvStatus(*lv);
					FsInfo fi = probe(run, seg.device);
					seg.fstype = fi.type;
					seg.label = fi.label;
					std::string mapper = "/dev/mapper/" + s.vg + "-" + s.lv;
					if (mounts.count(seg.device)) seg.mountpoint = mounts[seg.device];
					else if (mounts.count(mapper)) seg.mountpoint = mounts[mapper];
				}
				dk.segments.push_back(seg);
				pos = std::max(pos, s.start + s.size);
			}
			if (dk.segments.empty()) {
				Segment seg;
				seg.kind = SEG_UNALLOCATED;
				seg.size = size;
				dk.segments.push_back(seg);
			}
			snap.disks.push_back(dk);
			continue;
		}

		// Klassische Partitionstabelle. Bei "msdos" sind Nummern ab 5 logisch;
		// die primäre Partition, die sie umschließt, ist die erweiterte.
		const uint64_t minGap = 1024 * 1024;   // Ausrichtungsreste nicht zeigen
		std::vector<Segment> top, inner;
		uint64_t extStart = 0, extEnd = 0;
		for (auto& p : parts) {
			if (dk.table != "msdos" || p.number > 4) continue;
			for (auto& q : parts)
				if (q.number > 4 && q.start >= p.start && q.start < p.start + p.size) { extStart = p.start; extEnd = p.start + p.size; }
		}
		for (auto& p : parts) {
			Segment seg;
			seg.start = p.start;
			seg.size = p.size;
			seg.device = partitionPath(path, p.number);
			seg.number = p.number;
			seg.bootFlag = p.flags.find("boot") != std::string::npos;
			bool isExtended = dk.table == "msdos" && p.number <= 4 && p.start == extStart && extEnd > extStart;
			if (isExtended) { seg.kind = SEG_EXTENDED; top.push_back(seg); continue; }
			FsInfo fi = probe(run, seg.device);
			seg.fstype = fi.type;
			seg.label = fi.label;
			if (mounts.count(seg.device)) seg.mountpoint = mounts[seg.device];
			if (fi.type == "LVM2_member") { seg.isPv = true; dk.dynamic = true; }
			if (dk.table == "msdos" && p.number > 4) { seg.kind = SEG_LOGICAL; inner.push_back(seg); }
			else { seg.kind = SEG_PRIMARY; top.push_back(seg); }
		}
		// Lücken außen: nicht zugeordnet; innen: freier Speicherplatz.
		auto addGaps = [&](std::vector<Segment>& v, uint64_t from, uint64_t to, SegmentKind gapKind) {
			std::sort(v.begin(), v.end(), [](const Segment& a, const Segment& b) { return a.start < b.start; });
			std::vector<Segment> out;
			uint64_t pos = from;
			for (auto& s : v) {
				if (s.start > pos + minGap) { Segment g; g.kind = gapKind; g.start = pos; g.size = s.start - pos; out.push_back(g); }
				out.push_back(s);
				pos = std::max(pos, s.start + s.size);
			}
			if (to > pos + minGap) { Segment g; g.kind = gapKind; g.start = pos; g.size = to - pos; out.push_back(g); }
			v = out;
		};
		addGaps(top, 0, size, SEG_UNALLOCATED);
		if (extEnd > extStart) addGaps(inner, extStart, extEnd, SEG_FREE);
		// Die logischen Laufwerke folgen direkt auf die erweiterte Partition;
		// die Oberfläche zeichnet um sie den Rahmen.
		for (auto& s : top) {
			dk.segments.push_back(s);
			if (s.kind == SEG_EXTENDED) for (auto& i : inner) dk.segments.push_back(i);
		}
		snap.disks.push_back(dk);
	}

	// Freier Platz eingehängter Dateisysteme je Abschnitt.
	for (auto& dk : snap.disks)
		for (auto& s : dk.segments)
			if (!s.mountpoint.empty() && avail.count(s.mountpoint)) s.freeBytes = avail[s.mountpoint];

	// Volumeliste: Partitionen mit Inhalt und alle LVs.
	auto statusFor = [&](const std::string& mp) {
		// "Fehlerfrei (System)" wie im Original für die Systempartition.
		if (mp == "/") return std::string("Fehlerfrei (System)");
		if (mp == "/boot" || mp == "/boot/efi") return std::string("Fehlerfrei (Startpartition)");
		return std::string("Fehlerfrei");
	};
	auto displayName = [&](const std::string& label, const std::string& mp, const std::string& dev) {
		std::string where = mp.empty() ? dev.substr(dev.rfind('/') + 1) : mp;
		return label.empty() ? "(" + where + ")" : label + " (" + where + ")";
	};
	for (auto& dk : snap.disks)
		for (auto& s : dk.segments) {
			if (s.kind != SEG_PRIMARY && s.kind != SEG_LOGICAL) continue;
			if (s.isPv) continue;   // erscheint über seine LVs
			Volume v;
			v.device = s.device;
			v.name = displayName(s.label, s.mountpoint, s.device);
			v.layout = "Partition";
			v.type = "Basis";
			v.fstype = s.fstype;
			v.status = statusFor(s.mountpoint);
			v.capacity = s.size;
			if (!s.mountpoint.empty() && avail.count(s.mountpoint)) v.freeBytes = avail[s.mountpoint];
			snap.volumes.push_back(v);
		}
	for (auto& lv : lvs) {
		Volume v;
		v.device = lv.path;
		FsInfo fi = probe(run, lv.path);
		std::string mp = mounts.count(lv.path) ? mounts[lv.path] : "";
		if (mp.empty()) {
			std::string mapper = "/dev/mapper/" + lv.vg + "-" + lv.name;
			if (mounts.count(mapper)) mp = mounts[mapper];
		}
		v.name = displayName(fi.label, mp, lv.path);
		SegmentKind k = lvKind(lv);
		v.layout = k == SEG_MIRRORED ? "Gespiegelt" : k == SEG_RAID5 ? "RAID-5" : k == SEG_STRIPED ? "Stripeset"
		         : k == SEG_SPANNED ? "Übergreifend" : "Einfach";
		v.type = "Dynamisch";
		v.fstype = fi.type;
		v.status = statusFor(mp);
		if (lvStatus(lv) != "Fehlerfrei") v.status = lvStatus(lv);
		v.capacity = lv.size;
		if (!mp.empty() && avail.count(mp)) v.freeBytes = avail[mp];
		v.faultTolerant = (k == SEG_MIRRORED || k == SEG_RAID5);
		v.overheadPercent = k == SEG_MIRRORED ? 50 : k == SEG_RAID5 ? std::max(1, 100 / std::max(3, (int)lv.devices.size())) : 0;
		snap.volumes.push_back(v);
	}
	std::sort(snap.volumes.begin(), snap.volumes.end(), [](const Volume& a, const Volume& b) { return a.name < b.name; });
	return snap;
}

} // namespace disk
