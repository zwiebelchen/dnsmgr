// test_diskcore.cpp -- prüft die LVM-Auswertung und das Größenformat
// gegen Beispielausgaben von lvs/pvs. Nötig, weil sich LVs ohne
// Device-Mapper (z.B. in Containern) nicht anlegen lassen.
//
//   g++ -std=c++17 test_diskcore.cpp diskcore.cpp -o test_diskcore && ./test_diskcore
#include "diskcore.h"
#include "diskops.h"
#include <cstdio>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FEHLER Zeile %d: %s\n", __LINE__, #cond); failures++; } } while (0)

// So sieht "lvs --reportformat json -a -o lv_name,vg_name,lv_size,segtype,stripes,devices,lv_path"
// auf einem System mit allen fünf Volumetypen aus (gekürzt).
static const char* LVS = R"JSON(  WARNING: Beispielwarnung vor dem JSON
  {
      "report": [
          {
              "lv": [
                  {"lv_name":"archiv", "vg_name":"daten", "lv_size":"104857600B", "segtype":"linear", "stripes":"1", "devices":"/dev/sdb(0)", "lv_path":"/dev/daten/archiv"},
                  {"lv_name":"gross", "vg_name":"daten", "lv_size":"209715200B", "segtype":"linear", "stripes":"1", "devices":"/dev/sdb(25)", "lv_path":"/dev/daten/gross"},
                  {"lv_name":"gross", "vg_name":"daten", "lv_size":"209715200B", "segtype":"linear", "stripes":"1", "devices":"/dev/sdc(0)", "lv_path":"/dev/daten/gross"},
                  {"lv_name":"schnell", "vg_name":"daten", "lv_size":"104857600B", "segtype":"striped", "stripes":"2", "devices":"/dev/sdb(75),/dev/sdc(25)", "lv_path":"/dev/daten/schnell"},
                  {"lv_name":"sicher", "vg_name":"daten", "lv_size":"52428800B", "segtype":"raid1", "stripes":"2", "devices":"sicher_rimage_0(0),sicher_rimage_1(0)", "lv_path":"/dev/daten/sicher"},
                  {"lv_name":"[sicher_rimage_0]", "vg_name":"daten", "lv_size":"52428800B", "segtype":"linear", "stripes":"1", "devices":"/dev/sdb(90)", "lv_path":""},
                  {"lv_name":"parit", "vg_name":"daten", "lv_size":"104857600B", "segtype":"raid5", "stripes":"3", "devices":"parit_rimage_0(0),parit_rimage_1(0),parit_rimage_2(0)", "lv_path":"/dev/daten/parit"}
              ]
          }
      ]
  }
)JSON";

static const char* PVSEG = R"JSON({
      "report": [
          {
              "pvseg": [
                  {"pv_name":"/dev/sdb", "vg_name":"daten", "lv_name":"archiv", "pvseg_start":"0", "pvseg_size":"25", "vg_extent_size":"4194304B"},
                  {"pv_name":"/dev/sdb", "vg_name":"daten", "lv_name":"gross", "pvseg_start":"25", "pvseg_size":"50", "vg_extent_size":"4194304B"},
                  {"pv_name":"/dev/sdb", "vg_name":"daten", "lv_name":"[sicher_rimage_0]", "pvseg_start":"90", "pvseg_size":"13", "vg_extent_size":"4194304B"},
                  {"pv_name":"/dev/sdb", "vg_name":"daten", "lv_name":"", "pvseg_start":"103", "pvseg_size":"10", "vg_extent_size":"4194304B"}
              ]
          }
      ]
  })JSON";

int main() {
	auto lvs = disk::parseLvs(LVS);
	// Hilfs-LV [sicher_rimage_0] fällt weg, "gross" (zwei Segmente) wird zusammengefasst.
	CHECK(lvs.size() == 5);
	auto find = [&](const char* n) -> const disk::LvInfo* {
		for (auto& l : lvs) if (l.name == n) return &l;
		return nullptr;
	};
	CHECK(find("archiv") && disk::lvKind(*find("archiv")) == disk::SEG_SIMPLE);
	CHECK(find("gross") && find("gross")->devices.size() == 2);
	CHECK(find("gross") && disk::lvKind(*find("gross")) == disk::SEG_SPANNED);
	CHECK(find("schnell") && disk::lvKind(*find("schnell")) == disk::SEG_STRIPED);
	CHECK(find("sicher") && disk::lvKind(*find("sicher")) == disk::SEG_MIRRORED);
	CHECK(find("parit") && disk::lvKind(*find("parit")) == disk::SEG_RAID5);
	CHECK(find("archiv") && find("archiv")->size == 104857600ull);
	CHECK(find("archiv") && find("archiv")->path == "/dev/daten/archiv");

	auto segs = disk::parsePvSegments(PVSEG);
	CHECK(segs.size() == 4);
	CHECK(segs[0].lv == "archiv" && segs[0].start == 0 && segs[0].size == 25ull * 4194304);
	CHECK(segs[1].start == 25ull * 4194304);
	CHECK(segs[2].lv == "sicher");   // RAID-Teil zeigt auf sein Haupt-LV
	CHECK(segs[3].lv.empty());       // freier Bereich der Volumegruppe

	CHECK(disk::formatSize(100663296ull) == "96 MB");
	CHECK(disk::formatSize(21474836480ull) == "20,00 GB");
	CHECK(disk::formatSize(2048ull) == "2 KB");
	CHECK(std::string(disk::kindName(disk::SEG_STRIPED)) == "Stripesetdatenträger");

	// ---- Planung dynamischer Datenträger ----
	auto cmd = [](const disk::Plan& p) {
		std::string s;
		for (auto& st : p.steps) if (st.kind == disk::Step::COMMAND && !st.argv.empty() && st.argv[0] == "lvcreate") {
			for (auto& a : st.argv) s += (s.empty() ? "" : " ") + a;
		}
		return s;
	};
	disk::NewVolume v;
	v.vg = "daten"; v.name = "vol1"; v.sizePerDisk = 100ull << 20; v.format = false;
	v.kind = disk::SEG_SIMPLE; v.pvs = { "/dev/sdb" };
	CHECK(cmd(disk::planCreateVolume(v)) == "lvcreate -y -n vol1 -L 100m daten /dev/sdb");
	v.kind = disk::SEG_SPANNED; v.pvs = { "/dev/sdb", "/dev/sdc" };
	CHECK(cmd(disk::planCreateVolume(v)) == "lvcreate -y -n vol1 -L 200m daten /dev/sdb /dev/sdc");
	v.kind = disk::SEG_STRIPED;
	CHECK(cmd(disk::planCreateVolume(v)) == "lvcreate -y -n vol1 -i 2 -L 200m daten /dev/sdb /dev/sdc");
	v.kind = disk::SEG_MIRRORED;
	CHECK(cmd(disk::planCreateVolume(v)) == "lvcreate -y -n vol1 --type raid1 -m 1 -L 100m daten /dev/sdb /dev/sdc");
	v.kind = disk::SEG_RAID5;
	CHECK(!disk::planCreateVolume(v).ok());            // nur zwei Festplatten
	v.pvs = { "/dev/sdb", "/dev/sdc", "/dev/sdd" };
	CHECK(cmd(disk::planCreateVolume(v)) == "lvcreate -y -n vol1 --type raid5 -i 2 -L 200m daten /dev/sdb /dev/sdc /dev/sdd");
	CHECK(disk::volumeCapacity(v) == 200ull << 20);
	v.kind = disk::SEG_SIMPLE;
	CHECK(!disk::planCreateVolume(v).ok());            // einfach, aber drei Platten
	v.pvs = { "/dev/sdb" }; v.name = "mit leerzeichen";
	CHECK(!disk::planCreateVolume(v).ok());            // ungültiger Name

	// Erweitern nur einfach/übergreifend; Löschen nicht, wenn eingehängt.
	disk::Segment lvseg; lvseg.lvName = "vol1"; lvseg.vgName = "daten"; lvseg.device = "/dev/daten/vol1";
	CHECK(disk::planExtendVolume(lvseg, disk::SEG_SIMPLE, { "/dev/sdc" }, 50ull << 20).ok());
	CHECK(!disk::planExtendVolume(lvseg, disk::SEG_STRIPED, { "/dev/sdc" }, 50ull << 20).ok());
	lvseg.mountpoint = "/srv/x";
	CHECK(!disk::planDeleteVolume(lvseg).ok());
	lvseg.mountpoint.clear();
	CHECK(disk::planDeleteVolume(lvseg).ok());

	// Umwandeln nur leerer Platten
	disk::Disk dk; dk.path = "/dev/sde"; dk.size = 1ull << 30;
	disk::Segment un; un.kind = disk::SEG_UNALLOCATED; un.size = dk.size; dk.segments = { un };
	CHECK(disk::planConvertToDynamic(dk, "daten", true).ok());
	disk::Segment part; part.kind = disk::SEG_PRIMARY; dk.segments = { part };
	CHECK(!disk::planConvertToDynamic(dk, "daten", true).ok());

	// ---- Spiegelungen ----
	auto first = [](const disk::Plan& p) {
		std::string s;
		for (auto& st : p.steps) if (st.kind == disk::Step::COMMAND) { for (auto& a : st.argv) s += (s.empty() ? "" : " ") + a; break; }
		return s;
	};
	disk::Segment m; m.lvName = "vol1"; m.vgName = "daten";
	CHECK(first(disk::planAddMirror(m, disk::SEG_SIMPLE, "/dev/sdc")) == "lvconvert -y --type raid1 -m 1 daten/vol1 /dev/sdc");
	CHECK(!disk::planAddMirror(m, disk::SEG_STRIPED, "/dev/sdc").ok());
	CHECK(first(disk::planRemoveMirror(m, disk::SEG_MIRRORED, "/dev/sdc")) == "lvconvert -y -m 0 daten/vol1 /dev/sdc");
	CHECK(first(disk::planSplitMirror(m, disk::SEG_MIRRORED, "vol1_kopie")) == "lvconvert -y --splitmirrors 1 --name vol1_kopie daten/vol1");
	CHECK(!disk::planSplitMirror(m, disk::SEG_SIMPLE, "x").ok());
	CHECK(first(disk::planRepairVolume(m, disk::SEG_RAID5, "/dev/sde")) == "lvconvert -y --repair daten/vol1 /dev/sde");
	CHECK(first(disk::planResync(m, disk::SEG_MIRRORED)) == "lvchange --syncaction repair daten/vol1");
	CHECK(!disk::planResync(m, disk::SEG_SIMPLE).ok());

	// Zustände
	disk::LvInfo st; st.segtype = "raid1";
	CHECK(disk::lvStatus(st) == "Fehlerfrei");
	st.health = "partial";
	CHECK(disk::lvStatus(st) == "Fehlerhafte Redundanz");
	st.health = ""; st.syncPercent = 42;
	CHECK(disk::lvStatus(st) == "Wird neu synchronisiert (42 %)");

	// PVs eines Datenträgers aus den Segmenten (RAID-Teile zählen zum Haupt-LV)
	disk::Snapshot sn; sn.pvsegs = segs;
	auto pv = disk::pvsOfVolume(sn, "daten", "sicher");
	CHECK(pv.size() == 1 && pv[0] == "/dev/sdb");

	printf(failures ? "%d Fehler\n" : "Alle Prüfungen bestanden.\n", failures);
	return failures ? 1 : 0;
}
