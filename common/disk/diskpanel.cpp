// diskpanel.cpp -- siehe diskpanel.h
#include "diskpanel.h"

#include <algorithm>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

// Befehle als root ausführen (parted und blkid brauchen Zugriff auf die
// Geräte) -- über i2ksudo wie in den übrigen Programmen.
static int runAsRoot(const std::vector<std::string>& args, std::string& out) {
	std::vector<std::string> full = { "i2ksudo" };
	for (auto& a : args) full.push_back(a);
	std::vector<char*> argv;
	for (auto& a : full) argv.push_back((char*)a.c_str());
	argv.push_back(NULL);
	int fd[2];
	if (pipe(fd) != 0) return -1;
	pid_t pid = fork();
	if (pid == 0) {
		dup2(fd[1], STDOUT_FILENO);
		int nul = open("/dev/null", O_WRONLY);
		if (nul >= 0) { dup2(nul, STDERR_FILENO); close(nul); }
		close(fd[0]);
		close(fd[1]);
		execvp(argv[0], argv.data());
		_exit(127);
	}
	close(fd[1]);
	char buf[8192];
	ssize_t n;
	while ((n = read(fd[0], buf, sizeof(buf))) > 0) out.append(buf, n);
	close(fd[0]);
	int st = 0;
	waitpid(pid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// Farben der Legende wie im Original.
static FXColor kindColor(disk::SegmentKind k) {
	switch (k) {
		case disk::SEG_UNALLOCATED: return FXRGB(0, 0, 0);
		case disk::SEG_PRIMARY: return FXRGB(0, 0, 128);
		case disk::SEG_EXTENDED: return FXRGB(0, 128, 0);
		case disk::SEG_FREE: return FXRGB(0, 255, 0);
		case disk::SEG_LOGICAL: return FXRGB(0, 0, 255);
		case disk::SEG_SIMPLE: return FXRGB(128, 128, 0);
		case disk::SEG_SPANNED: return FXRGB(128, 0, 128);
		case disk::SEG_STRIPED: return FXRGB(0, 128, 128);
		case disk::SEG_MIRRORED: return FXRGB(128, 0, 0);
		case disk::SEG_RAID5: return FXRGB(0, 255, 255);
	}
	return FXRGB(0, 0, 0);
}

// ---------------------------------------------------------------------
// Grafische Ansicht
// ---------------------------------------------------------------------
class DiskMapView : public FXFrame {
	FXDECLARE(DiskMapView)
public:
	struct Hit { FXint x, y, w, h; int disk, seg; };
private:
	const disk::Snapshot* snap = nullptr;
	std::vector<Hit> hits;
	int selDisk = -1, selSeg = -1;
	FXFont* bold = nullptr;
	enum { ROW_H = 72, LEFT_W = 118, GAP = 6, MIN_W = 84 };   // enum statt static const: kein Linkersymbol noetig
protected:
	DiskMapView() {}
public:
	DiskMapView(FXComposite* p, FXObject* tgt, FXSelector sel)
		: FXFrame(p, FRAME_NONE | LAYOUT_FILL_X | LAYOUT_FIX_HEIGHT, 0,0,0,ROW_H) {
		setTarget(tgt);
		setSelector(sel);
		flags |= FLAG_ENABLED;
		backColor = FXRGB(255, 255, 255);
	}
	virtual void create() {
		FXFrame::create();
		FXFontDesc d;
		getApp()->getNormalFont()->getFontDesc(d);
		d.weight = FXFont::Bold;
		bold = new FXFont(getApp(), d);
		bold->create();
	}
	void setSnapshot(const disk::Snapshot* s) {
		snap = s;
		selDisk = selSeg = -1;
		FXint rows = s ? (FXint)s->disks.size() : 0;
		setHeight(std::max<FXint>(ROW_H, rows * (ROW_H + GAP) + GAP));
		recalc();
		update();
	}
	void select(int d, int s) { selDisk = d; selSeg = s; update(); }
	int selectedDisk() const { return selDisk; }
	int selectedSegment() const { return selSeg; }

	// Breite je Abschnitt: anteilig zur Plattengröße, aber nie so schmal,
	// dass der Text nicht mehr passt.
	std::vector<FXint> widths(const disk::Disk& d, FXint avail) const {
		std::vector<FXint> w;
		for (auto& s : d.segments) {
			if (s.kind == disk::SEG_EXTENDED) { w.push_back(0); continue; }   // Rahmen, keine eigene Breite
			double part = d.size ? (double)s.size / (double)d.size : 0;
			w.push_back(std::max<FXint>(MIN_W, (FXint)(part * avail)));
		}
		return w;
	}

	long onPaint(FXObject*, FXSelector, void* ptr) {
		FXDCWindow dc(this, (FXEvent*)ptr);
		dc.setForeground(backColor);
		dc.fillRectangle(0, 0, width, height);
		hits.clear();
		if (!snap) return 1;
		FXFont* normal = getApp()->getNormalFont();
		const FXint lineH = normal->getFontHeight();
		int diskNo = 0, cdNo = 0;
		for (size_t di = 0; di < snap->disks.size(); di++) {
			const disk::Disk& d = snap->disks[di];
			FXint y = GAP + (FXint)di * (ROW_H + GAP);

			// Linker Block: "Datenträger 0", "Basis", Größe, "Online"
			dc.setForeground(getApp()->getBaseColor());
			dc.fillRectangle(GAP, y, LEFT_W, ROW_H);
			dc.setForeground(FXRGB(128, 128, 128));
			dc.drawRectangle(GAP, y, LEFT_W - 1, ROW_H - 1);
			dc.setForeground(FXRGB(0, 0, 0));
			dc.setFont(bold);
			FXString title = d.cdrom ? FXString("CD-ROM ") + FXString(std::to_string(cdNo++).c_str())
			                         : FXString("Datenträger ") + FXString(std::to_string(diskNo++).c_str());
			dc.drawText(GAP + 6, y + 4 + bold->getFontAscent(), title);
			dc.setFont(normal);
			FXString l2 = d.cdrom ? FXString("CD-ROM") : d.removable ? FXString("Wechselmedium")
			            : d.dynamic ? FXString("Dynamisch") : FXString("Basis");
			dc.drawText(GAP + 6, y + 4 + lineH + normal->getFontAscent(), l2);
			if (d.size) dc.drawText(GAP + 6, y + 4 + 2 * lineH + normal->getFontAscent(), disk::formatSize(d.size).c_str());
			// Zustandstexte aus dmdskres.dll (6002, 53288, 53289)
			FXString state = d.cdrom ? (d.size ? FXString("Online") : FXString("Kein Medium"))
			               : d.unreadable ? FXString("Nicht lesbar") : FXString("Online");
			dc.drawText(GAP + 6, y + 4 + 3 * lineH + normal->getFontAscent(), state);

			FXint x = GAP + LEFT_W + 2;
			FXint avail = std::max<FXint>(200, width - x - GAP);
			std::vector<FXint> w = widths(d, avail);
			FXint extX = -1;
			for (size_t si = 0; si < d.segments.size(); si++) {
				const disk::Segment& s = d.segments[si];
				if (s.kind == disk::SEG_EXTENDED) { extX = x; continue; }
				FXint sw = w[si];
				bool inExt = (s.kind == disk::SEG_LOGICAL || s.kind == disk::SEG_FREE) && extX >= 0;
				FXint top = y + (inExt ? 4 : 0), hgt = ROW_H - (inExt ? 8 : 0);
				FXint bx = x + (inExt ? 3 : 0), bw = sw - (inExt ? 3 : 0);
				// Körper weiß, oben der farbige Balken
				dc.setForeground(FXRGB(255, 255, 255));
				dc.fillRectangle(bx, top, bw, hgt);
				dc.setForeground(kindColor(s.kind));
				dc.fillRectangle(bx, top, bw, 9);
				dc.setForeground(FXRGB(128, 128, 128));
				dc.drawRectangle(bx, top, bw - 1, hgt - 1);
				// Text: Name, Größe + Dateisystem, Zustand
				dc.setForeground(FXRGB(0, 0, 0));
				FXint ty = top + 12 + normal->getFontAscent();
				dc.setClipRectangle(bx + 2, top, bw - 4, hgt);
				if (s.kind == disk::SEG_UNALLOCATED || s.kind == disk::SEG_FREE) {
					dc.drawText(bx + 4, ty, disk::formatSize(s.size).c_str());
					dc.drawText(bx + 4, ty + lineH, disk::kindName(s.kind));
				} else {
					std::string where = !s.mountpoint.empty() ? s.mountpoint
					                  : !s.lvName.empty() ? s.lvName : s.device.substr(s.device.rfind('/') + 1);
					std::string name = s.label.empty() ? "(" + where + ")" : s.label + " (" + where + ")";
					if (s.isPv) name = "LVM (" + s.device.substr(s.device.rfind('/') + 1) + ")";
					dc.setFont(bold);
					dc.drawText(bx + 4, ty, name.c_str());
					dc.setFont(normal);
					dc.drawText(bx + 4, ty + lineH, (disk::formatSize(s.size) + (s.fstype.empty() ? "" : " " + s.fstype)).c_str());
					dc.drawText(bx + 4, ty + 2 * lineH, s.mountpoint == "/" ? "Fehlerfrei (System)" : "Fehlerfrei");
				}
				dc.clearClipRectangle();
				if ((int)di == selDisk && (int)si == selSeg) {
					// Auswahl wie im Original: gestrichelter Rahmen
					dc.setForeground(FXRGB(0, 0, 0));
					dc.setLineStyle(LINE_ONOFF_DASH);
					dc.drawRectangle(bx + 2, top + 11, bw - 5, hgt - 14);
					dc.setLineStyle(LINE_SOLID);
				}
				hits.push_back({ bx, top, bw, hgt, (int)di, (int)si });
				x += sw;
				// Ende der erweiterten Partition: grüner Rahmen um ihre Kinder
				bool nextInExt = si + 1 < d.segments.size() &&
				                 (d.segments[si + 1].kind == disk::SEG_LOGICAL || d.segments[si + 1].kind == disk::SEG_FREE);
				if (inExt && !nextInExt) {
					dc.setForeground(kindColor(disk::SEG_EXTENDED));
					for (int t = 0; t < 3; t++) dc.drawRectangle(extX + t, y + t, x - extX - 1 - 2 * t, ROW_H - 1 - 2 * t);
					extX = -1;
				}
			}
			if (d.unreadable) {
				dc.setForeground(FXRGB(128, 128, 128));
				dc.drawRectangle(x, y, avail - 1, ROW_H - 1);
				dc.setForeground(FXRGB(0, 0, 0));
				dc.drawText(x + 6, y + ROW_H / 2, "Kein Zugriff auf den Datenträger.");
			}
		}
		return 1;
	}

	long onLeftBtnPress(FXObject*, FXSelector, void* ptr) {
		FXEvent* ev = (FXEvent*)ptr;
		for (auto& h : hits)
			if (ev->win_x >= h.x && ev->win_x < h.x + h.w && ev->win_y >= h.y && ev->win_y < h.y + h.h) {
				select(h.disk, h.seg);
				if (target) target->handle(this, FXSEL(SEL_COMMAND, message), NULL);
				return 1;
			}
		return 1;
	}
	virtual ~DiskMapView() { delete bold; }
};
FXDEFMAP(DiskMapView) DiskMapViewMap[] = {
	FXMAPFUNC(SEL_PAINT, 0, DiskMapView::onPaint),
	FXMAPFUNC(SEL_LEFTBUTTONPRESS, 0, DiskMapView::onLeftBtnPress),
};
FXIMPLEMENT(DiskMapView, FXFrame, DiskMapViewMap, ARRAYNUMBER(DiskMapViewMap))

// ---------------------------------------------------------------------
// DiskPanel
// ---------------------------------------------------------------------
FXDEFMAP(DiskPanel) DiskPanelMap[] = {
	FXMAPFUNC(SEL_COMMAND, DiskPanel::ID_VOLUMES, DiskPanel::onVolumeSelected),
	FXMAPFUNC(SEL_COMMAND, DiskPanel::ID_MAP, DiskPanel::onMapSelected),
};
FXIMPLEMENT(DiskPanel, FXVerticalFrame, DiskPanelMap, ARRAYNUMBER(DiskPanelMap))

DiskPanel::DiskPanel(FXComposite* p, FXuint opts)
	: FXVerticalFrame(p, opts, 0,0,0,0, 0,0,0,0, 0,0) {
	FXSplitter* split = new FXSplitter(this, SPLITTER_VERTICAL | SPLITTER_TRACKING | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	FXPacker* top = new FXPacker(split, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FIX_HEIGHT, 0,0,0,160, 0,0,0,0);
	volumes = new FXIconList(top, this, ID_VOLUMES, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	// Spalten wortgleich aus dmdskres.dll (Text 5002).
	const char* cols[] = { "Datenträger", "Layout", "Typ", "Dateisystem", "Status", "Kapazität",
	                       "Freier Speicher", "% frei", "Fehlertoleranz", "Overhead" };
	const int widths[] = { 170, 90, 80, 90, 150, 80, 100, 60, 100, 70 };
	for (int i = 0; i < 10; i++) volumes->appendHeader(cols[i], NULL, widths[i]);

	FXVerticalFrame* bottom = new FXVerticalFrame(split, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
	mapScroll = new FXScrollWindow(bottom, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y | HSCROLLING_OFF);
	map = new DiskMapView(mapScroll, this, ID_MAP);
	mapScroll->setBackColor(FXRGB(255, 255, 255));

	// Legende -- wird bei jedem Einlesen mit den vorkommenden Arten gefüllt.
	legend = new FXHorizontalFrame(bottom, LAYOUT_FILL_X | FRAME_SUNKEN, 0,0,0,0, 6,6,3,3, 10,0);
}

// Wie im Original nur die Arten, die auf den Datenträgern vorkommen;
// "Nicht zugeordnet" und "Primäre Partition" stehen immer da.
void DiskPanel::rebuildLegend() {
	while (legend->numChildren() > 0) delete legend->getFirst();
	bool present[10] = { true, true, false, false, false, false, false, false, false, false };
	for (auto& d : snap.disks) for (auto& s : d.segments) present[s.kind] = true;
	for (int k = 0; k < 10; k++) {
		if (!present[k]) continue;
		FXHorizontalFrame* item = new FXHorizontalFrame(legend, LAYOUT_CENTER_Y, 0,0,0,0, 0,0,0,0, 3,0);
		FXFrame* sw = new FXFrame(item, FRAME_LINE | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT | LAYOUT_CENTER_Y, 0,0,10,10);
		sw->setBackColor(kindColor((disk::SegmentKind)k));
		new FXLabel(item, disk::kindName((disk::SegmentKind)k), NULL, LAYOUT_CENTER_Y, 0,0,0,0, 0,0,0,0);
		if (legend->id()) item->create();
	}
	legend->recalc();
}

void DiskPanel::reload() {
	getApp()->beginWaitCursor();
	snap = disk::collect(runAsRoot);
	getApp()->endWaitCursor();
	volumes->clearItems();
	for (auto& v : snap.volumes) {
		FXString freeText = v.freeBytes < 0 ? FXString("-") : FXString(disk::formatSize((uint64_t)v.freeBytes).c_str());
		FXString pct = "-";
		if (v.freeBytes >= 0 && v.capacity) pct = FXString(std::to_string((int)(100.0 * v.freeBytes / v.capacity + 0.5)).c_str()) + " %";
		volumes->appendItem(FXString(v.name.c_str()) + "\t" + v.layout.c_str() + "\t" + v.type.c_str() + "\t" +
		                    (v.fstype.empty() ? "-" : v.fstype.c_str()) + "\t" + v.status.c_str() + "\t" +
		                    disk::formatSize(v.capacity).c_str() + "\t" + freeText + "\t" + pct + "\t" +
		                    (v.faultTolerant ? "Ja" : "Nein") + "\t" + FXString(std::to_string(v.overheadPercent).c_str()) + " %");
	}
	map->setSnapshot(&snap);
	rebuildLegend();
}

FXString DiskPanel::statusText() const {
	int basic = 0, dynamic = 0;
	for (auto& d : snap.disks) { if (d.cdrom) continue; if (d.dynamic) dynamic++; else basic++; }
	// "Basisfestplatten: " / "Dynamische Festplatten: " (dmdskres.dll 53355/53357)
	return FXString(" Basisfestplatten: ") + FXString(std::to_string(basic).c_str()) +
	       "   Dynamische Festplatten: " + FXString(std::to_string(dynamic).c_str()) +
	       "   Datenträger: " + FXString(std::to_string(snap.volumes.size()).c_str());
}

// Auswahl in der Liste markiert den passenden Abschnitt in der Grafik --
// und umgekehrt, wie im Original.
long DiskPanel::onVolumeSelected(FXObject*, FXSelector, void*) {
	int idx = volumes->getCurrentItem();
	if (idx < 0 || idx >= (int)snap.volumes.size()) return 1;
	const std::string& dev = snap.volumes[idx].device;
	for (size_t d = 0; d < snap.disks.size(); d++)
		for (size_t s = 0; s < snap.disks[d].segments.size(); s++)
			if (snap.disks[d].segments[s].device == dev) { map->select((int)d, (int)s); return 1; }
	return 1;
}

long DiskPanel::onMapSelected(FXObject*, FXSelector, void*) {
	int d = map->selectedDisk(), s = map->selectedSegment();
	if (d < 0 || s < 0) return 1;
	const std::string& dev = snap.disks[d].segments[s].device;
	for (size_t i = 0; i < snap.volumes.size(); i++)
		if (snap.volumes[i].device == dev) { volumes->setCurrentItem((int)i); volumes->selectItem((int)i); volumes->makeItemVisible((int)i); return 1; }
	volumes->killSelection();
	return 1;
}
