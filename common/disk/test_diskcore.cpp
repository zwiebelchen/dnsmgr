// test_diskcore.cpp -- prüft die LVM-Auswertung und das Größenformat
// gegen Beispielausgaben von lvs/pvs. Nötig, weil sich LVs ohne
// Device-Mapper (z.B. in Containern) nicht anlegen lassen.
//
//   g++ -std=c++17 test_diskcore.cpp diskcore.cpp -o test_diskcore && ./test_diskcore
#include "diskcore.h"
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

	printf(failures ? "%d Fehler\n" : "Alle Prüfungen bestanden.\n", failures);
	return failures ? 1 : 0;
}
