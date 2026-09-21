// diskops.cpp -- siehe diskops.h
#include "diskops.h"

#include <algorithm>
#include <cstdio>
#include <sstream>
#include <unistd.h>

namespace disk {

static std::string trim(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

std::string Plan::preview() const {
	std::string out;
	for (auto& s : steps) {
		if (s.kind == Step::FSTAB_SET) out += "# /etc/fstab: " + s.mountpoint + " für " + s.device + " eintragen\n";
		else if (s.kind == Step::FSTAB_REMOVE) out += "# /etc/fstab: Einträge für " + s.device + " entfernen\n";
		else if (s.kind == Step::WAIT_DEVICE) out += "# warten, bis " + s.device + " vorhanden ist\n";
		else {
			std::string line;
			for (auto& a : s.argv) line += (line.empty() ? "" : " ") + (a.find(' ') != std::string::npos ? "'" + a + "'" : a);
			out += line + "\n";
		}
	}
	return out;
}

std::vector<std::string> availableFilesystems(Runner run) {
	std::vector<std::string> out;
	for (const char* fs : { "ext4", "xfs", "btrfs", "vfat", "ntfs", "ext3", "ext2" }) {
		std::string o;
		if (run({ "sh", "-c", std::string("command -v mkfs.") + fs }, o) == 0) out.push_back(fs);
	}
	return out;
}

// Mit dem Dateisystem passender mkfs-Aufruf.
static std::vector<std::string> mkfsArgs(const std::string& fs, const std::string& label, bool quick, const std::string& dev) {
	std::vector<std::string> a = { "mkfs." + fs };
	if (fs == "vfat") { a.push_back("-F"); a.push_back("32"); if (!label.empty()) { a.push_back("-n"); a.push_back(label.substr(0, 11)); } }
	else if (fs == "ntfs") { if (quick) a.push_back("-Q"); if (!label.empty()) { a.push_back("-L"); a.push_back(label); } }
	else if (fs == "xfs" || fs == "btrfs") { a.push_back("-f"); if (!label.empty()) { a.push_back("-L"); a.push_back(label); } }
	else { a.push_back("-F"); if (!label.empty()) { a.push_back("-L"); a.push_back(label.substr(0, 16)); } }
	a.push_back(dev);
	return a;
}

static std::string partitionPath(const std::string& disk, int number) {
	char last = disk.empty() ? 'x' : disk.back();
	return disk + (isdigit((unsigned char)last) ? "p" : "") + std::to_string(number);
}

// Eine Partition, die gerade in Gebrauch ist, darf weder gelöscht noch
// formatiert werden -- im Original die Meldungen 53481/53483.
static std::string refuseInUse(const Segment& s) {
	if (s.mountpoint == "/")
		return "Die Partition, die das System enthält, kann nicht gelöscht oder formatiert werden.";
	if (!s.mountpoint.empty())
		return "Die Partition ist unter " + s.mountpoint + " eingehängt.\n\n"
		       "Hängen Sie sie zuerst aus: \"Laufwerkbuchstaben und -pfad ändern...\" und dort\n"
		       "\"Keinen Laufwerkbuchstaben oder -pfad zuweisen\".";
	if (s.isPv)
		return "Die Partition gehört zu einer LVM-Volumegruppe (dynamische Festplatte)\n"
		       "und lässt sich hier nicht löschen oder formatieren.";
	return "";
}

Plan planCreateTable(const Disk& d, const std::string& table) {
	Plan p;
	if (d.cdrom || d.unreadable) { p.error = "Auf diesen Datenträger kann keine Signatur geschrieben werden."; return p; }
	if (!d.table.empty()) {
		p.error = std::string("Die Festplatte hat bereits eine Signatur (Partitionstabelle ") +
		          (d.table == "msdos" ? "MBR" : d.table == "gpt" ? "GPT" : d.table) + ").";
		return p;
	}
	for (auto& s : d.segments)
		if (s.kind != SEG_UNALLOCATED) {
			p.error = "Der Datenträger enthält bereits Partitionen oder Daten.\n\n"
			          "Eine Signatur lässt sich nur auf eine leere Festplatte schreiben.";
			return p;
		}
	if (d.dynamic) { p.error = "Der Datenträger wird von LVM verwendet (dynamische Festplatte)."; return p; }
	p.steps.push_back({ { "parted", "-s", d.path, "mklabel", table }, "Partitionstabelle anlegen" });
	return p;
}

Plan planCreatePartition(const Disk& d, const Segment& gap, const NewPartition& np) {
	Plan p;
	if (d.table.empty()) { p.error = "Der Datenträger hat keine Partitionstabelle.\n\nSchreiben Sie zuerst eine Signatur."; return p; }
	if (gap.kind != SEG_UNALLOCATED && gap.kind != SEG_FREE) { p.error = "Hier ist kein freier Bereich."; return p; }
	if (np.size == 0 || np.size > gap.size) { p.error = "Die Größe liegt außerhalb des verfügbaren Bereichs."; return p; }
	if (d.table == "msdos") {
		int primaries = 0;
		bool hasExtended = false;
		for (auto& s : d.segments) {
			if (s.kind == SEG_PRIMARY || s.kind == SEG_EXTENDED) primaries++;
			if (s.kind == SEG_EXTENDED) hasExtended = true;
		}
		if (np.type == PART_LOGICAL && gap.kind != SEG_FREE) { p.error = "Logische Laufwerke entstehen im freien Speicherplatz einer erweiterten Partition."; return p; }
		if (np.type != PART_LOGICAL && gap.kind == SEG_FREE) { p.error = "Im freien Speicherplatz einer erweiterten Partition entstehen nur logische Laufwerke."; return p; }
		if (np.type != PART_LOGICAL && primaries >= 4) { p.error = "Eine MBR-Festplatte kann höchstens vier primäre bzw. erweiterte Partitionen haben."; return p; }
		if (np.type == PART_EXTENDED && hasExtended) { p.error = "Es gibt bereits eine erweiterte Partition auf dieser Festplatte."; return p; }
	} else if (np.type != PART_PRIMARY) {
		p.error = "GPT kennt keine erweiterten Partitionen oder logischen Laufwerke; alle Partitionen sind primär.";
		return p;
	}

	// Anfang auf 1 MiB ausrichten; parted richtet selbst noch einmal aus.
	const uint64_t mib = 1024 * 1024;
	uint64_t start = ((gap.start + mib - 1) / mib) * mib;
	if (start < mib) start = mib;
	if (np.type == PART_LOGICAL) start += mib;    // Platz für den EBR
	uint64_t end = std::min(gap.start + gap.size, start + np.size) - 1;
	if (end <= start) { p.error = "Der Bereich ist zu klein."; return p; }

	const char* kind = np.type == PART_PRIMARY ? "primary" : np.type == PART_EXTENDED ? "extended" : "logical";
	std::vector<std::string> mk = { "parted", "-s", "-a", "optimal", d.path, "unit", "B", "mkpart" };
	if (d.table == "gpt") mk.push_back("ice2k");   // GPT: Name statt Typ
	else mk.push_back(kind);
	mk.push_back(std::to_string(start) + "B");
	mk.push_back(std::to_string(end) + "B");
	p.steps.push_back({ mk, "Partition anlegen" });
	// Ohne udev entstehen die Geräteknoten erst durch partx.
	p.steps.push_back({ { "partx", "-u", d.path }, "Kernel über die neue Partition informieren" });

	if (np.type == PART_EXTENDED) return p;   // wird nicht formatiert

	// Nummer der neuen Partition: bei logischen die nächste ab 5, sonst die
	// erste freie ab 1.
	int number = 0;
	std::vector<int> used;
	for (auto& s : d.segments) if (s.number > 0) used.push_back(s.number);
	if (np.type == PART_LOGICAL) { number = 5; while (std::find(used.begin(), used.end(), number) != used.end()) number++; }
	else { number = 1; while (std::find(used.begin(), used.end(), number) != used.end()) number++; }
	std::string dev = partitionPath(d.path, number);
	Step wait;
	wait.kind = Step::WAIT_DEVICE;
	wait.device = dev;
	wait.disk = d.path;
	wait.description = "auf " + dev + " warten";
	p.steps.push_back(wait);

	if (np.format) {
		p.steps.push_back({ mkfsArgs(np.fstype, np.label, np.quick, dev), "Formatieren" });
		if (!np.mountpoint.empty()) {
			p.steps.push_back({ { "mkdir", "-p", np.mountpoint }, "Ordner anlegen" });
			Step fs;
			fs.kind = Step::FSTAB_SET;
			fs.device = dev;
			fs.mountpoint = np.mountpoint;
			fs.fstype = np.fstype;
			fs.description = "In /etc/fstab eintragen";
			p.steps.push_back(fs);
			p.steps.push_back({ { "mount", np.mountpoint }, "Einhängen" });
		}
	}
	return p;
}

Plan planDeletePartition(const Disk& d, const Segment& s) {
	Plan p;
	if (s.kind == SEG_EXTENDED) {
		for (auto& o : d.segments)
			if (o.kind == SEG_LOGICAL) { p.error = "Die erweiterte Partition enthält noch logische Laufwerke.\n\nLöschen Sie diese zuerst."; return p; }
	} else {
		std::string refuse = refuseInUse(s);
		if (!refuse.empty()) { p.error = refuse; return p; }
	}
	if (s.number <= 0) { p.error = "Das ist keine Partition."; return p; }
	std::string name = s.label.empty() ? s.device : s.label + " (" + s.device + ")";
	// Text 40010 aus dmdskres.dll
	p.warning = "Alle Daten auf \"" + name + "\" werden verloren gehen.\n\n"
	            "Sind Sie sicher, dass \"" + name + "\" gelöscht werden soll?";
	if (s.bootFlag)
		// Text 53482
		p.warning = "Dies ist eine aktive Partition auf dieser Festplatte. Alle Daten auf der Partition\n"
		            "werden verloren gehen. Sind Sie sicher, dass die aktive Partition gelöscht werden soll?";
	Step rm;
	rm.kind = Step::FSTAB_REMOVE;
	rm.device = s.device;
	rm.description = "fstab-Einträge entfernen";
	p.steps.push_back(rm);
	p.steps.push_back({ { "parted", "-s", d.path, "rm", std::to_string(s.number) }, "Partition löschen" });
	p.steps.push_back({ { "partx", "-u", d.path }, "Kernel informieren" });
	return p;
}

Plan planFormat(const Disk&, const Segment& s, const std::string& fstype, const std::string& label, bool quick) {
	Plan p;
	std::string refuse = refuseInUse(s);
	if (!refuse.empty()) { p.error = refuse; return p; }
	if (s.device.empty()) { p.error = "Das ist keine Partition."; return p; }
	// Text 40008
	p.warning = "WARNUNG: Alle Daten auf diesem Datenträger werden durch die Formatierung gelöscht.\n"
	            "Klicken Sie auf \"Ja\", um den Datenträger zu formatieren.";
	// Die UUID ändert sich durch mkfs: einen alten fstab-Eintrag vorher
	// entfernen (er verweist sonst ins Leere).
	Step rm;
	rm.kind = Step::FSTAB_REMOVE;
	rm.device = s.device;
	rm.description = "alten fstab-Eintrag entfernen";
	p.steps.push_back(rm);
	p.steps.push_back({ mkfsArgs(fstype, label, quick, s.device), "Formatieren" });
	return p;
}

Plan planSetMountpoint(const Segment& s, const std::string& mp) {
	Plan p;
	if (s.device.empty() || s.fstype.empty() || s.isPv) { p.error = "Der Datenträger ist nicht formatiert."; return p; }
	if (s.mountpoint == "/") { p.error = "Der Pfad der Systempartition lässt sich nicht ändern."; return p; }
	if (!mp.empty() && mp[0] != '/') { p.error = "Geben Sie einen absoluten Pfad an, z.B. /srv/daten."; return p; }
	if (!s.mountpoint.empty()) p.steps.push_back({ { "umount", s.mountpoint }, "Aushängen" });
	Step rm;
	rm.kind = Step::FSTAB_REMOVE;
	rm.device = s.device;
	rm.description = "alten fstab-Eintrag entfernen";
	p.steps.push_back(rm);
	if (!mp.empty()) {
		p.steps.push_back({ { "mkdir", "-p", mp }, "Ordner anlegen" });
		Step fs;
		fs.kind = Step::FSTAB_SET;
		fs.device = s.device;
		fs.mountpoint = mp;
		fs.fstype = s.fstype;
		fs.description = "In /etc/fstab eintragen";
		p.steps.push_back(fs);
		p.steps.push_back({ { "mount", mp }, "Einhängen" });
	}
	return p;
}

Plan planSetActive(const Disk& d, const Segment& s) {
	Plan p;
	if (d.table != "msdos") { p.error = "Nur MBR-Festplatten kennen eine aktive Partition."; return p; }
	if (s.kind != SEG_PRIMARY) { p.error = "Nur primäre Partitionen lassen sich als aktiv markieren."; return p; }
	for (auto& o : d.segments)
		if (o.bootFlag && o.number != s.number)
			p.steps.push_back({ { "parted", "-s", d.path, "set", std::to_string(o.number), "boot", "off" }, "Bisher aktive Partition zurücksetzen" });
	p.steps.push_back({ { "parted", "-s", d.path, "set", std::to_string(s.number), "boot", "on" }, "Als aktiv markieren" });
	return p;
}

// ---------------------------------------------------------------------
// Ausführen
// ---------------------------------------------------------------------

// fstab lesen, Zeilen für ein Gerät (per Gerätename oder UUID) entfernen
// bzw. setzen, zurückschreiben -- alles als root über den Runner.
static bool editFstab(Runner run, const Step& s, std::string& log) {
	std::string fstab, uuid;
	run({ "cat", "/etc/fstab" }, fstab);
	run({ "blkid", "-p", "-s", "UUID", "-o", "value", s.device }, uuid);
	uuid = trim(uuid);
	std::string out;
	std::string keepMp;   // bisheriger Mountpunkt (für "nur UUID anpassen")
	std::istringstream in(fstab);
	std::string line;
	while (std::getline(in, line)) {
		std::istringstream f(line);
		std::string src, mp;
		f >> src >> mp;
		bool match = !src.empty() && src[0] != '#' &&
		             (src == s.device || (!uuid.empty() && src == "UUID=" + uuid));
		if (match) { keepMp = mp; continue; }
		out += line + "\n";
	}
	if (s.kind == Step::FSTAB_SET) {
		std::string mp = s.mountpoint.empty() ? keepMp : s.mountpoint;
		if (!mp.empty()) {
			std::string src = uuid.empty() ? s.device : "UUID=" + uuid;
			std::string opts = s.fstype == "vfat" || s.fstype == "ntfs" ? "defaults,nofail" : "defaults,nofail";
			out += src + "\t" + mp + "\t" + (s.fstype == "ntfs" ? "ntfs-3g" : s.fstype) + "\t" + opts + "\t0\t2\t# ice2k Datenträgerverwaltung\n";
		}
	}
	// Über eine Temp-Datei als root zurückschreiben.
	char tmpl[] = "/tmp/ice2k-fstab-XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) { log += "Temporäre Datei konnte nicht angelegt werden.\n"; return false; }
	if (write(fd, out.data(), out.size()) != (ssize_t)out.size()) { close(fd); unlink(tmpl); return false; }
	close(fd);
	std::string o;
	bool ok = run({ "cp", tmpl, "/etc/fstab" }, o) == 0;
	unlink(tmpl);
	log += std::string("# /etc/fstab angepasst") + (ok ? "\n" : " -- FEHLER\n");
	return ok;
}

bool execute(const Plan& plan, Runner run, std::string& log) {
	for (auto& s : plan.steps) {
		if (s.kind == Step::FSTAB_SET || s.kind == Step::FSTAB_REMOVE) {
			if (!editFstab(run, s, log)) return false;
			continue;
		}
		if (s.kind == Step::WAIT_DEVICE) {
			std::string o;
			bool found = false;
			for (int i = 0; i < 30 && !found; i++) {
				if (run({ "test", "-b", s.device }, o) == 0) found = true;
				else { run({ "partx", "-a", s.disk }, o); usleep(200000); }
			}
			if (!found) { log += "Das Gerät " + s.device + " ist nicht erschienen.\n"; return false; }
			continue;
		}
		std::string line;
		for (auto& a : s.argv) line += (line.empty() ? "" : " ") + a;
		log += "$ " + line + "\n";
		std::string out;
		int rc = run(s.argv, out);
		if (!trim(out).empty()) log += trim(out) + "\n";
		// partx -u meldet einen Fehler, wenn es nichts zu tun gibt -- unschädlich.
		if (rc != 0 && s.argv[0] != "partx") return false;
	}
	return true;
}

} // namespace disk
