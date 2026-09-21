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

// Für die Ausführung: Fehlerausgabe mitschneiden, damit das Protokoll
// die Meldungen von parted, mkfs und LVM enthält.
static int runAsRootWithErrors(const std::vector<std::string>& args, std::string& out) {
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
		dup2(fd[1], STDERR_FILENO);
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
					std::string st = !s.status.empty() && s.status != "Fehlerfrei" ? s.status
					               : s.mountpoint == "/" ? "Fehlerfrei (System)" : "Fehlerfrei";
					dc.drawText(bx + 4, ty + 2 * lineH, st.c_str());
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

	// Rechtsklick: wählt den Abschnitt (oder mit seg = -1 den Plattenblock)
	// und meldet ihn als SEL_RIGHTBUTTONRELEASE an das Panel.
	long onRightBtnRelease(FXObject*, FXSelector, void* ptr) {
		FXEvent* ev = (FXEvent*)ptr;
		bool hit = false;
		for (auto& h : hits)
			if (ev->win_x >= h.x && ev->win_x < h.x + h.w && ev->win_y >= h.y && ev->win_y < h.y + h.h) { select(h.disk, h.seg); hit = true; break; }
		if (!hit && snap) {
			int row = (ev->win_y - GAP) / (ROW_H + GAP);
			if (ev->win_x < GAP + LEFT_W && row >= 0 && row < (int)snap->disks.size()) { select(row, -1); hit = true; }
		}
		if (target) {
			if (hit) target->handle(this, FXSEL(SEL_COMMAND, message), NULL);
			target->handle(this, FXSEL(SEL_RIGHTBUTTONRELEASE, message), ptr);
		}
		return 1;
	}
	long onLeftBtnPress(FXObject*, FXSelector, void* ptr) {
		FXEvent* ev = (FXEvent*)ptr;
		if (ev->click_count >= 2 && target) {
			// Plattenblock links: Eigenschaften der Platte
			int row = snap ? (ev->win_y - GAP) / (ROW_H + GAP) : -1;
			if (ev->win_x < GAP + LEFT_W && row >= 0 && snap && row < (int)snap->disks.size()) select(row, -1);
			target->handle(this, FXSEL(SEL_DOUBLECLICKED, message), NULL);
			return 1;
		}
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
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, 0, DiskMapView::onRightBtnRelease),
};
FXIMPLEMENT(DiskMapView, FXFrame, DiskMapViewMap, ARRAYNUMBER(DiskMapViewMap))

// ---------------------------------------------------------------------
// DiskPanel
// ---------------------------------------------------------------------
FXDEFMAP(DiskPanel) DiskPanelMap[] = {
	FXMAPFUNC(SEL_COMMAND, DiskPanel::ID_VOLUMES, DiskPanel::onVolumeSelected),
	FXMAPFUNC(SEL_COMMAND, DiskPanel::ID_MAP, DiskPanel::onMapSelected),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, DiskPanel::ID_MAP, DiskPanel::onMapRightClick),
	FXMAPFUNCS(SEL_COMMAND, DiskPanel::ID_SIGNATURE, DiskPanel::ID_RESCAN, DiskPanel::onAction),
	FXMAPFUNCS(SEL_COMMAND, DiskPanel::ID_CONVERT, DiskPanel::ID_DELETE_VOL, DiskPanel::onDynamicAction),
	FXMAPFUNCS(SEL_COMMAND, DiskPanel::ID_ADD_MIRROR, DiskPanel::ID_RESYNC, DiskPanel::onMirrorAction),
	FXMAPFUNC(SEL_COMMAND, DiskPanel::ID_PROPERTIES, DiskPanel::onProperties),
	FXMAPFUNC(SEL_DOUBLECLICKED, DiskPanel::ID_VOLUMES, DiskPanel::onOpenProperties),
	FXMAPFUNC(SEL_DOUBLECLICKED, DiskPanel::ID_MAP, DiskPanel::onOpenProperties),
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
	// Den Besitzer (Programmfenster) informieren, damit er z.B. die
	// Statuszeile nachzieht -- auch nach Änderungen aus dem Kontextmenü.
	if (target) target->handle(this, FXSEL(SEL_CHANGED, message), NULL);
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

// =====================================================================
// Änderungen (Schritt 2: Basisdatenträger)
// =====================================================================
#include "diskops.h"
#include "../ui/msgbox.h"

// Bestätigung: Warntext des Originals, darunter die Befehle, die
// tatsächlich ausgeführt werden.
static bool confirmPlan(FXWindow* owner, const FXString& title, const disk::Plan& plan) {
	FXDialogBox dlg(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_RESIZE, 0,0,560,380, 12,12,12,12, 0,6);
	FXVerticalFrame* main = new FXVerticalFrame(&dlg, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
	if (!plan.warning.empty()) new FXLabel(main, plan.warning.c_str(), NULL, JUSTIFY_LEFT);
	new FXLabel(main, "Folgende Befehle werden ausgeführt:", NULL, JUSTIFY_LEFT);
	FXPacker* tf = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	FXText* text = new FXText(tf, NULL, 0, TEXT_READONLY | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	text->setText(plan.preview().c_str());
	FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,6,0, 8,0);
	new FXButton(btns, "&Ja", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	new FXButton(btns, "&Nein", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	return dlg.execute(PLACEMENT_OWNER) != 0;
}

static void showLog(FXWindow* owner, const FXString& title, const std::string& log) {
	FXDialogBox dlg(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_RESIZE, 0,0,600,360, 12,12,12,12, 0,6);
	FXVerticalFrame* main = new FXVerticalFrame(&dlg, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
	new FXLabel(main, "Der Vorgang konnte nicht abgeschlossen werden:", NULL, JUSTIFY_LEFT);
	FXPacker* tf = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	FXText* text = new FXText(tf, NULL, 0, TEXT_READONLY | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	text->setText(log.c_str());
	new FXButton(main, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_RIGHT, 0,0,0,0, 16,16,3,3);
	dlg.execute(PLACEMENT_OWNER);
}

// Plan prüfen, bestätigen lassen, ausführen.
static bool runPlan(FXWindow* owner, const FXString& title, const disk::Plan& plan) {
	if (!plan.ok()) { ice2kui::error(owner, MBOX_OK, "Datenträgerverwaltung", "%s", plan.error.c_str()); return false; }
	if (!confirmPlan(owner, title, plan)) return false;
	owner->getApp()->beginWaitCursor();
	std::string log;
	bool ok = disk::execute(plan, runAsRootWithErrors, log);
	owner->getApp()->endWaitCursor();
	if (!ok) showLog(owner, title, log);
	return ok;
}

// Auswahllisten für das Dateisystem.
static void fillFs(FXListBox* box, const std::vector<std::string>& fs, const std::string& pick) {
	for (auto& f : fs) box->appendItem(f == "vfat" ? "FAT32 (vfat)" : f == "ntfs" ? "NTFS" : f.c_str());
	box->setNumVisible(std::min<int>(7, box->getNumItems()));
	for (int i = 0; i < box->getNumItems(); i++) if (fs[i] == pick) box->setCurrentItem(i);
}

// ---------------------------------------------------------------------
// "Formatierung" (dmdskres.dll, Dialog 172)
// ---------------------------------------------------------------------
static bool formatDialog(FXWindow* owner, const std::vector<std::string>& fs, std::string& fstype, std::string& label, bool& quick) {
	FXDialogBox dlg(owner, "Formatierung", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,420,0, 12,12,12,12, 0,6);
	FXMatrix* m = new FXMatrix(&dlg, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
	new FXLabel(m, "&Datenträgerbezeichnung:", NULL, JUSTIFY_LEFT);
	FXTextField* lbl = new FXTextField(m, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
	lbl->setText(label.c_str());
	new FXLabel(m, "Zu verwendendes Datei&system:", NULL, JUSTIFY_LEFT);
	FXListBox* fsBox = new FXListBox(m, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
	fillFs(fsBox, fs, fstype);
	new FXLabel(m, "Größe der Z&uordnungseinheit:", NULL, JUSTIFY_LEFT);
	FXListBox* au = new FXListBox(m, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
	au->appendItem("Standard");
	au->setNumVisible(1);
	FXCheckButton* q = new FXCheckButton(&dlg, "Formatierung mit &QuickFormat durchführen");
	q->setCheck(quick);
	FXHorizontalFrame* btns = new FXHorizontalFrame(&dlg, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,8,0, 6,0);
	new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	if (!dlg.execute(PLACEMENT_OWNER) || fs.empty()) return false;
	fstype = fs[std::max(0, fsBox->getCurrentItem())];
	label = lbl->getText().text();
	quick = q->getCheck();
	return true;
}

// ---------------------------------------------------------------------
// "Laufwerkbuchstaben und -pfad ändern" (Dialog 363, vereinfacht: ein Pfad)
// ---------------------------------------------------------------------
static bool mountDialog(FXWindow* owner, const std::string& current, std::string& result) {
	FXDialogBox dlg(owner, "Laufwerkbuchstaben und -pfad ändern", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,480,0, 12,12,12,12, 0,6);
	new FXLabel(&dlg, "Auf diesen Datenträger kann über folgenden Pfad zugegriffen werden:", NULL, JUSTIFY_LEFT);
	FXint choice = current.empty() ? 1 : 0;
	FXDataTarget target(choice);
	new FXRadioButton(&dlg, "&Diesen Datenträger in einem leeren Ordner bereitstellen:", &target, FXDataTarget::ID_OPTION + 0);
	FXTextField* path = new FXTextField(&dlg, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X, 0,0,0,0, 16,2,2,2);
	path->setText(current.empty() ? "/srv/" : current.c_str());
	new FXRadioButton(&dlg, "&Keinen Laufwerkbuchstaben oder -pfad zuweisen", &target, FXDataTarget::ID_OPTION + 1);
	FXHorizontalFrame* btns = new FXHorizontalFrame(&dlg, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,8,0, 6,0);
	new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	if (!dlg.execute(PLACEMENT_OWNER)) return false;
	result = choice == 0 ? std::string(path->getText().text()) : std::string();
	return true;
}

// ---------------------------------------------------------------------
// "Signatur schreiben" -- Wahl zwischen MBR und GPT
// ---------------------------------------------------------------------
static bool signatureDialog(FXWindow* owner, const std::string& diskName, std::string& table) {
	FXDialogBox dlg(owner, "Signatur schreiben", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,460,0, 12,12,12,12, 0,6);
	// Text 4010 aus dmdskres.dll
	new FXLabel(&dlg, FXString("Signatur auf folgende Festplatten schreiben:\n    ") + diskName.c_str(), NULL, JUSTIFY_LEFT);
	new FXHorizontalSeparator(&dlg, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	FXint choice = 1;
	FXDataTarget target(choice);
	new FXRadioButton(&dlg, "&MBR (Master Boot Record) -- wie unter Windows 2000", &target, FXDataTarget::ID_OPTION + 0);
	new FXRadioButton(&dlg, "&GPT (GUID-Partitionstabelle) -- für Platten über 2 TB und UEFI", &target, FXDataTarget::ID_OPTION + 1);
	FXHorizontalFrame* btns = new FXHorizontalFrame(&dlg, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,8,0, 6,0);
	new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	if (!dlg.execute(PLACEMENT_OWNER)) return false;
	table = choice == 0 ? "msdos" : "gpt";
	return true;
}

// ---------------------------------------------------------------------
// "Assistent zum Erstellen von Partitionen" (Dialoge 353, 355-359)
// ---------------------------------------------------------------------
class PartitionWizard : public FXDialogBox {
	FXDECLARE(PartitionWizard)
private:
	FXSwitcher* pages = nullptr;
	FXButton *backBtn = nullptr, *nextBtn = nullptr;
	FXint typeChoice = 0, mountChoice = 0, formatChoice = 1;
	FXDataTarget typeTarget, mountTarget, formatTarget;
	FXLabel* typeDesc = nullptr;
	FXSpinner* sizeSpin = nullptr;
	FXTextField *pathField = nullptr, *labelField = nullptr;
	FXListBox* fsBox = nullptr;
	FXCheckButton* quickCheck = nullptr;
	FXList* summary = nullptr;
	std::vector<std::string> fsList;
	std::vector<disk::PartType> allowedTypes;
	uint64_t maxBytes = 0;
	int page = 0;
	static const int PAGES = 6;
protected:
	PartitionWizard() {}
public:
	enum { ID_BACK = FXDialogBox::ID_LAST, ID_NEXT, ID_TYPE };
	PartitionWizard(FXWindow* owner, const disk::Disk& d, const disk::Segment& gap, const std::vector<std::string>& fs)
		: FXDialogBox(owner, "Assistent zum Erstellen von Partitionen", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,560,400, 0,0,0,0, 0,0),
		  typeTarget(typeChoice, this, ID_TYPE), mountTarget(mountChoice), formatTarget(formatChoice), fsList(fs), maxBytes(gap.size) {
		// Welche Typen hier möglich sind
		if (gap.kind == disk::SEG_FREE) allowedTypes = { disk::PART_LOGICAL };
		else if (d.table == "gpt") allowedTypes = { disk::PART_PRIMARY };
		else {
			bool hasExt = false;
			for (auto& s : d.segments) if (s.kind == disk::SEG_EXTENDED) hasExt = true;
			allowedTypes = { disk::PART_PRIMARY };
			if (!hasExt) allowedTypes.push_back(disk::PART_EXTENDED);
		}
		typeChoice = allowedTypes[0];

		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
		pages = new FXSwitcher(main, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 20,20,16,10);

		// 1: Willkommen (353)
		FXVerticalFrame* p1 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,12);
		FXLabel* w = new FXLabel(p1, "Willkommen", NULL, JUSTIFY_LEFT);
		FXFontDesc fd; getApp()->getNormalFont()->getFontDesc(fd); fd.size = 160; fd.weight = FXFont::Bold;
		w->setFont(new FXFont(getApp(), fd));
		new FXLabel(p1, "Mit diesem Assistenten können Sie eine Partition auf einer Basisfestplatte erstellen.", NULL, JUSTIFY_LEFT);
		new FXLabel(p1, "Eine Basisfestplatte ist eine physische Festplatte, auf der primäre Partitionen,\n"
		                "erweiterte Partitionen und logische Laufwerke enthalten sind.", NULL, JUSTIFY_LEFT);
		new FXLabel(p1, "Klicken Sie auf \"Weiter\", um den Vorgang fortzusetzen.", NULL, JUSTIFY_LEFT);

		// 2: Partitionstyp (355)
		FXVerticalFrame* p2 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(p2, "Wählen Sie den Typ der Partition, die Sie erstellen möchten:", NULL, JUSTIFY_LEFT);
		const char* names[] = { "&Primäre Partition", "&Erweiterte Partition", "&Logisches Laufwerk" };
		for (int t = 0; t < 3; t++) {
			FXRadioButton* r = new FXRadioButton(p2, names[t], &typeTarget, FXDataTarget::ID_OPTION + t, RADIOBUTTON_NORMAL, 0,0,0,0, 16,0,0,0);
			if (std::find(allowedTypes.begin(), allowedTypes.end(), (disk::PartType)t) == allowedTypes.end()) r->disable();
		}
		FXGroupBox* gb = new FXGroupBox(p2, " Beschreibung", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,6,6);
		typeDesc = new FXLabel(gb, "", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

		// 3: Größe (356)
		FXVerticalFrame* p3 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,8);
		new FXLabel(p3, "Geben Sie eine Partitionsgröße an, die kleiner als die Größe der Festplatte ist.", NULL, JUSTIFY_LEFT);
		FXMatrix* m3 = new FXMatrix(p3, 2, MATRIX_BY_COLUMNS, 0,0,0,0, 0,0,8,0, 16,6);
		const FXint maxMb = (FXint)std::max<uint64_t>(1, (gap.size >> 20) - 2);
		new FXLabel(m3, "Maximaler Datenträgerspeicher:", NULL, JUSTIFY_LEFT);
		new FXLabel(m3, (std::to_string(maxMb) + " MB").c_str(), NULL, JUSTIFY_LEFT);
		new FXLabel(m3, "Minimaler Datenträgerspeicher:", NULL, JUSTIFY_LEFT);
		new FXLabel(m3, "8 MB", NULL, JUSTIFY_LEFT);
		new FXLabel(m3, "Zu &verwendender Datenträgerspeicher:", NULL, JUSTIFY_LEFT);
		FXHorizontalFrame* sz = new FXHorizontalFrame(m3, 0, 0,0,0,0, 0,0,0,0, 4,0);
		sizeSpin = new FXSpinner(sz, 8, NULL, 0, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		sizeSpin->setRange(8, maxMb);
		sizeSpin->setValue(maxMb);
		new FXLabel(sz, "MB", NULL, LAYOUT_CENTER_Y);

		// 4: Laufwerkpfad (357)
		FXVerticalFrame* p4 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(p4, "Sie können über einen Pfad, den Sie der Partition zuweisen, auf die Partition zugreifen.\n"
		                "Laufwerkbuchstaben gibt es unter Linux nicht.", NULL, JUSTIFY_LEFT);
		new FXRadioButton(p4, "&Diesen Datenträger in einem leeren Ordner bereitstellen, der Laufwerkpfade unterstützt:", &mountTarget, FXDataTarget::ID_OPTION + 0);
		pathField = new FXTextField(p4, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X, 0,0,0,0, 16,2,2,2);
		pathField->setText("/srv/daten");
		new FXRadioButton(p4, "&Keinen Laufwerkbuchstaben oder -pfad zuweisen", &mountTarget, FXDataTarget::ID_OPTION + 1);

		// 5: Formatieren (358)
		FXVerticalFrame* p5 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(p5, "Geben Sie an, ob diese Partition formatiert werden soll.", NULL, JUSTIFY_LEFT);
		new FXRadioButton(p5, "Diese Partition &nicht formatieren", &formatTarget, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(p5, "D&iese Partition mit folgenden Einstellungen formatieren:", &formatTarget, FXDataTarget::ID_OPTION + 1);
		FXMatrix* m5 = new FXMatrix(p5, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 20,0,4,0, 12,4);
		new FXLabel(m5, "Zu &verwendendes Dateisystem:", NULL, JUSTIFY_LEFT);
		fsBox = new FXListBox(m5, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		fillFs(fsBox, fsList, "ext4");
		new FXLabel(m5, "&Größe der Zuordnungseinheit:", NULL, JUSTIFY_LEFT);
		FXListBox* au = new FXListBox(m5, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		au->appendItem("Standard");
		au->setNumVisible(1);
		new FXLabel(m5, "&Datenträgerbezeichnung:", NULL, JUSTIFY_LEFT);
		labelField = new FXTextField(m5, 16, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		labelField->setText("Daten");
		quickCheck = new FXCheckButton(p5, "Formatierung mit &QuickFormat durchführen", NULL, 0, CHECKBUTTON_NORMAL, 0,0,0,0, 20,0,0,0);
		quickCheck->setCheck(TRUE);

		// 6: Fertigstellen (359)
		FXVerticalFrame* p6 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		FXLabel* f = new FXLabel(p6, "Fertigstellen des Assistenten", NULL, JUSTIFY_LEFT);
		f->setFont(new FXFont(getApp(), fd));
		new FXLabel(p6, "Sie haben folgende Einstellungen angegeben:", NULL, JUSTIFY_LEFT);
		FXPacker* sf = new FXPacker(p6, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		summary = new FXList(sf, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p6, "Klicken Sie auf \"Fertig stellen\", um den Vorgang abzuschließen.", NULL, JUSTIFY_LEFT);

		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 10,10,8,10, 6,0);
		backBtn = new FXButton(btns, "< &Zurück", NULL, this, ID_BACK, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		nextBtn = new FXButton(btns, "&Weiter >", NULL, this, ID_NEXT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		new FXButton(btns, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		onType(NULL, 0, NULL);
		showPage();
	}
	// Seiten, die für eine erweiterte Partition wegfallen (Pfad, Formatieren).
	bool skip(int p) const { return typeChoice == disk::PART_EXTENDED && (p == 3 || p == 4); }
	void showPage() {
		pages->setCurrent(page);
		if (page == 0) backBtn->disable(); else backBtn->enable();
		nextBtn->setText(page == PAGES - 1 ? "Fertig stellen" : "&Weiter >");
		if (page == PAGES - 1) {
			summary->clearItems();
			const char* tn[] = { "Primäre Partition", "Erweiterte Partition", "Logisches Laufwerk" };
			summary->appendItem(FXString("Partitionstyp: ") + tn[typeChoice]);
			summary->appendItem(FXString("Größe: ") + FXString(std::to_string(sizeSpin->getValue()).c_str()) + " MB");
			if (typeChoice != disk::PART_EXTENDED) {
				summary->appendItem(FXString("Pfad: ") + (mountChoice == 0 ? pathField->getText() : FXString("Keiner")));
				if (formatChoice == 1) {
					summary->appendItem(FXString("Dateisystem: ") + fsBox->getItemText(std::max(0, fsBox->getCurrentItem())));
					summary->appendItem(FXString("Datenträgerbezeichnung: ") + labelField->getText());
				} else summary->appendItem("Nicht formatieren");
			}
		}
	}
	long onType(FXObject*, FXSelector, void*) {
		// Beschreibungen aus dmdskres.dll (Texte 2062, 2006, 2024), gekürzt.
		const char* desc[] = {
			"Bei einer primären Partition handelt es sich um einen Datenträger, den Sie unter\n"
			"Verwendung von freiem Speicherplatz auf einer Basisfestplatte erstellen.",
			"Eine erweiterte Partition ist ein Teil eines Basisdatenträgers, der logische Laufwerke\n"
			"enthält. Verwenden Sie sie, wenn Sie mehr als vier Datenträger benötigen.",
			"Ein logisches Laufwerk ist ein Datenträger, der in einer erweiterten Partition eines\n"
			"Basisdatenträgers erstellt wird." };
		typeDesc->setText(desc[typeChoice]);
		return 1;
	}
	long onBack(FXObject*, FXSelector, void*) {
		do { page--; } while (page > 0 && skip(page));
		showPage();
		return 1;
	}
	long onNext(FXObject*, FXSelector, void*) {
		if (page == PAGES - 1) return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
		if (page == 3 && mountChoice == 0) {
			std::string p = pathField->getText().text();
			if (p.empty() || p[0] != '/') {
				ice2kui::error(this, MBOX_OK, "Assistent zum Erstellen von Partitionen", "Geben Sie einen absoluten Pfad an, z.B. /srv/daten.");
				return 1;
			}
		}
		do { page++; } while (page < PAGES - 1 && skip(page));
		showPage();
		return 1;
	}
	disk::NewPartition result() const {
		disk::NewPartition np;
		np.type = (disk::PartType)typeChoice;
		np.size = (uint64_t)sizeSpin->getValue() << 20;
		np.format = np.type != disk::PART_EXTENDED && formatChoice == 1 && !fsList.empty();
		if (np.format) np.fstype = fsList[std::max(0, fsBox->getCurrentItem())];
		np.label = labelField->getText().text();
		np.quick = quickCheck->getCheck();
		if (np.format && mountChoice == 0) np.mountpoint = pathField->getText().text();
		return np;
	}
	virtual ~PartitionWizard() {}
};
FXDEFMAP(PartitionWizard) PartitionWizardMap[] = {
	FXMAPFUNC(SEL_COMMAND, PartitionWizard::ID_BACK, PartitionWizard::onBack),
	FXMAPFUNC(SEL_COMMAND, PartitionWizard::ID_NEXT, PartitionWizard::onNext),
	FXMAPFUNC(SEL_COMMAND, PartitionWizard::ID_TYPE, PartitionWizard::onType),
};
FXIMPLEMENT(PartitionWizard, FXDialogBox, PartitionWizardMap, ARRAYNUMBER(PartitionWizardMap))

// ---------------------------------------------------------------------
// Kontextmenü und Aktionen
// ---------------------------------------------------------------------
long DiskPanel::onMapRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	int d = map->selectedDisk(), s = map->selectedSegment();
	FXMenuPane menu(this);
	bool any = false;
	if (d >= 0 && s < 0) {
		// Klick auf den Plattenblock links
		const disk::Disk& dk = snap.disks[d];
		bool empty = true;
		for (auto& sg : dk.segments) if (sg.kind != disk::SEG_UNALLOCATED) empty = false;
		if (!dk.cdrom && !dk.unreadable && dk.table.empty() && !dk.dynamic) {
			new FXMenuCommand(&menu, "&Signatur schreiben", NULL, this, ID_SIGNATURE);
			any = true;
		}
		// Texte 2007 und 2045 aus dmdskres.dll
		if (!dk.cdrom && !dk.unreadable && !dk.removable && !dk.dynamic && empty) {
			new FXMenuCommand(&menu, "&In dynamische Festplatte umwandeln...", NULL, this, ID_CONVERT);
			any = true;
		}
		if (dk.dynamic && empty) {
			new FXMenuCommand(&menu, "In eine &Basisfestplatte zurückkonvertieren", NULL, this, ID_REVERT);
			any = true;
		}
	} else if (d >= 0 && s >= 0) {
		const disk::Disk& dk = snap.disks[d];
		const disk::Segment& sg = dk.segments[s];
		// Menütexte wortgleich aus dmdskres.dll (2003, 2005, 2013, 2015, 2017)
		if (sg.kind == disk::SEG_UNALLOCATED && !dk.dynamic && !dk.table.empty()) {
			new FXMenuCommand(&menu, "Partition &erstellen...", NULL, this, ID_CREATE);
			any = true;
		} else if (sg.kind == disk::SEG_UNALLOCATED && dk.dynamic) {
			new FXMenuCommand(&menu, "&Datenträger erstellen...", NULL, this, ID_CREATE_VOL);   // Text 2001
			any = true;
		} else if (disk::kindIsDynamic(sg.kind) && !sg.lvName.empty()) {
			// Texte 2013, 2017, 2025, 2021
			new FXMenuCommand(&menu, "&Laufwerkbuchstaben und -pfad ändern...", NULL, this, ID_MOUNTPOINT);
			new FXMenuCommand(&menu, "&Formatieren...", NULL, this, ID_FORMAT);
			if (sg.kind == disk::SEG_SIMPLE || sg.kind == disk::SEG_SPANNED)
				new FXMenuCommand(&menu, "Da&tenträger erweitern...", NULL, this, ID_EXTEND_VOL);
			// Texte 2027, 2031, 2043, 2029, 2055 und 4006
			if (sg.kind == disk::SEG_SIMPLE)
				new FXMenuCommand(&menu, "&Spiegelung hinzufügen...", NULL, this, ID_ADD_MIRROR);
			if (sg.kind == disk::SEG_MIRRORED) {
				new FXMenuSeparator(&menu);
				new FXMenuCommand(&menu, "&Spiegelung erneut synchronisieren...", NULL, this, ID_RESYNC);
				new FXMenuCommand(&menu, "Spiegelung auf&teilen...", NULL, this, ID_SPLIT_MIRROR);
				new FXMenuCommand(&menu, "Spiegelung &entfernen...", NULL, this, ID_REMOVE_MIRROR);
				new FXMenuCommand(&menu, "Datenträger &reparieren...", NULL, this, ID_REPAIR_VOL);
			}
			if (sg.kind == disk::SEG_RAID5) {
				new FXMenuSeparator(&menu);
				new FXMenuCommand(&menu, "&Parität erneut erzeugen", NULL, this, ID_RESYNC);
				new FXMenuCommand(&menu, "Datenträger &reparieren...", NULL, this, ID_REPAIR_VOL);
			}
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, "Datenträger &löschen...", NULL, this, ID_DELETE_VOL);
			any = true;
		} else if (sg.kind == disk::SEG_FREE) {
			new FXMenuCommand(&menu, "&Logisches Laufwerk erstellen...", NULL, this, ID_CREATE);
			bool hasLogical = false;
			for (auto& o : dk.segments) if (o.kind == disk::SEG_LOGICAL) hasLogical = true;
			if (!hasLogical) { new FXMenuSeparator(&menu); new FXMenuCommand(&menu, "Erweiterte Partition &löschen...", NULL, this, ID_DELETE_EXT); }
			any = true;
		} else if ((sg.kind == disk::SEG_PRIMARY || sg.kind == disk::SEG_LOGICAL) && sg.number > 0) {
			new FXMenuCommand(&menu, "&Laufwerkbuchstaben und -pfad ändern...", NULL, this, ID_MOUNTPOINT);
			new FXMenuCommand(&menu, "&Formatieren...", NULL, this, ID_FORMAT);
			if (sg.kind == disk::SEG_PRIMARY && dk.table == "msdos" && !sg.bootFlag)
				new FXMenuCommand(&menu, "&Partition als aktiv markieren", NULL, this, ID_ACTIVE);
			new FXMenuSeparator(&menu);
			new FXMenuCommand(&menu, sg.kind == disk::SEG_LOGICAL ? "Logisches Laufwerk &löschen..." : "Partition &löschen...", NULL, this, ID_DELETE);
			any = true;
		}
	}
	if (any) new FXMenuSeparator(&menu);
	new FXMenuCommand(&menu, "&Festplatten neu einlesen", NULL, this, ID_RESCAN);   // Text 2057
	bool propsPossible = d >= 0 && (s < 0 || (snap.disks[d].segments[s].kind != disk::SEG_UNALLOCATED &&
	                                          snap.disks[d].segments[s].kind != disk::SEG_FREE));
	if (propsPossible) {
		new FXMenuSeparator(&menu);
		new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_PROPERTIES);   // Text 2035
	}
	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long DiskPanel::onAction(FXObject*, FXSelector sel, void*) {
	int d = map->selectedDisk(), s = map->selectedSegment();
	FXuint id = FXSELID(sel);
	if (id == ID_RESCAN) { reload(); return 1; }
	if (d < 0) return 1;
	const disk::Disk dk = snap.disks[d];
	bool changed = false;
	if (id == ID_SIGNATURE) {
		std::string table;
		if (signatureDialog(this, dk.path, table))
			changed = runPlan(this, "Signatur schreiben", disk::planCreateTable(dk, table));
	} else if (s >= 0) {
		const disk::Segment sg = dk.segments[s];
		if (id == ID_CREATE) {
			PartitionWizard wiz(this, dk, sg, disk::availableFilesystems(runAsRoot));
			if (wiz.execute(PLACEMENT_OWNER))
				changed = runPlan(this, "Assistent zum Erstellen von Partitionen", disk::planCreatePartition(dk, sg, wiz.result()));
		} else if (id == ID_DELETE) {
			changed = runPlan(this, "Partition löschen", disk::planDeletePartition(dk, sg));
		} else if (id == ID_DELETE_EXT) {
			for (auto& o : dk.segments)
				if (o.kind == disk::SEG_EXTENDED) { changed = runPlan(this, "Partition löschen", disk::planDeletePartition(dk, o)); break; }
		} else if (id == ID_FORMAT) {
			std::string fstype = sg.fstype.empty() || sg.fstype == "vfat" ? (sg.fstype.empty() ? "ext4" : "vfat") : sg.fstype;
			std::string label = sg.label;
			bool quick = true;
			if (formatDialog(this, disk::availableFilesystems(runAsRoot), fstype, label, quick))
				changed = runPlan(this, "Formatierung", disk::planFormat(dk, sg, fstype, label, quick));
		} else if (id == ID_MOUNTPOINT) {
			std::string mp;
			if (mountDialog(this, sg.mountpoint, mp) && mp != sg.mountpoint)
				changed = runPlan(this, "Laufwerkbuchstaben und -pfad ändern", disk::planSetMountpoint(sg, mp));
		} else if (id == ID_ACTIVE) {
			changed = runPlan(this, "Partition als aktiv markieren", disk::planSetActive(dk, sg));
		}
	}
	if (changed) reload();
	return 1;
}

// =====================================================================
// Dynamische Datenträger (Schritt 3: LVM)
// =====================================================================

// Zwei Listen mit Hinzufügen/Entfernen wie Dialog 378/385; gibt die
// gewählten Einträge zurück.
struct DiskPicker {
	FXList *avail = nullptr, *chosen = nullptr;
	void build(FXComposite* p, FXObject* tgt, FXSelector add, FXSelector rem, FXSelector remAll) {
		FXHorizontalFrame* h = new FXHorizontalFrame(p, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 8,0);
		FXVerticalFrame* l = new FXVerticalFrame(h, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,2);
		new FXLabel(l, "Alle &verfügbaren dynamischen Datenträger:", NULL, JUSTIFY_LEFT);
		FXPacker* lf = new FXPacker(l, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		avail = new FXList(lf, NULL, 0, LIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		FXVerticalFrame* m = new FXVerticalFrame(h, LAYOUT_CENTER_Y | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,0,0, 0,4);
		new FXButton(m, "&Hinzufügen >>", NULL, tgt, add, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);
		new FXButton(m, "<< &Entfernen", NULL, tgt, rem, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);
		new FXButton(m, "<< A&lle entfernen", NULL, tgt, remAll, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);
		FXVerticalFrame* r = new FXVerticalFrame(h, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,2);
		new FXLabel(r, "A&usgewählte dynamische Datenträger:", NULL, JUSTIFY_LEFT);
		FXPacker* rf = new FXPacker(r, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		chosen = new FXList(rf, NULL, 0, LIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	}
	void move(FXList* from, FXList* to, int i) { if (i < 0) return; to->appendItem(from->getItemText(i)); from->removeItem(i); }
	void add() { move(avail, chosen, avail->getCurrentItem()); }
	void remove() { move(chosen, avail, chosen->getCurrentItem()); }
	void removeAll() { while (chosen->getNumItems()) move(chosen, avail, 0); }
	// Einträge haben die Form "/dev/sdb (256 MB frei)"
	std::vector<std::string> selected() const {
		std::vector<std::string> out;
		for (int i = 0; i < chosen->getNumItems(); i++) {
			std::string t = chosen->getItemText(i).text();
			out.push_back(t.substr(0, t.find(' ')));
		}
		return out;
	}
};

static uint64_t pvFree(const disk::Snapshot& snap, const std::string& pv) {
	for (auto& p : snap.pvs) if (p.name == pv) return p.free;
	return 0;
}

// ---------------------------------------------------------------------
// In dynamische Festplatte umwandeln -- Volumegruppe wählen
// ---------------------------------------------------------------------
static bool convertDialog(FXWindow* owner, const disk::Snapshot& snap, const std::string& diskPath, std::string& vg, bool& newVg) {
	std::vector<std::string> vgs;
	for (auto& p : snap.pvs) if (!p.vg.empty() && std::find(vgs.begin(), vgs.end(), p.vg) == vgs.end()) vgs.push_back(p.vg);
	FXDialogBox dlg(owner, "In dynamische Festplatte umwandeln", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,500,0, 12,12,12,12, 0,6);
	// Text 1180 aus Dialog 364
	new FXLabel(&dlg, FXString("Festplatte: ") + diskPath.c_str() + "\n\n"
	                  "Dynamische Festplatten können verwendet werden, um softwarebasierte RAID-Datenträger\n"
	                  "zu erstellen. Sie können auch einzelne Festplatten und übergreifende Datenträger\n"
	                  "erweitern, ohne den Computer neu starten zu müssen.\n\n"
	                  "Unter Linux entspricht das LVM: Die Festplatte wird ein physisches Volume in einer\n"
	                  "Volumegruppe.", NULL, JUSTIFY_LEFT);
	new FXHorizontalSeparator(&dlg, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	FXint choice = vgs.empty() ? 1 : 0;
	FXDataTarget target(choice);
	FXRadioButton* r0 = new FXRadioButton(&dlg, "&Vorhandene Volumegruppe:", &target, FXDataTarget::ID_OPTION + 0);
	FXListBox* box = new FXListBox(&dlg, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL, 0,0,0,0, 20,2,2,2);
	for (auto& v : vgs) box->appendItem(v.c_str());
	box->setNumVisible(std::max(1, std::min<int>(6, (int)vgs.size())));
	if (vgs.empty()) { r0->disable(); box->disable(); }
	new FXRadioButton(&dlg, "&Neue Volumegruppe:", &target, FXDataTarget::ID_OPTION + 1);
	FXTextField* name = new FXTextField(&dlg, 24, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X, 0,0,0,0, 20,2,2,2);
	name->setText(vgs.empty() ? "daten" : "daten2");
	FXHorizontalFrame* btns = new FXHorizontalFrame(&dlg, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,8,0, 6,0);
	new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	if (!dlg.execute(PLACEMENT_OWNER)) return false;
	newVg = choice == 1;
	vg = newVg ? std::string(name->getText().text()) : std::string(box->getItemText(std::max(0, box->getCurrentItem())).text());
	return true;
}

// ---------------------------------------------------------------------
// "Assistent zum Erstellen von Datenträgern" (Dialoge 375, 376, 378, 381, 382, 380)
// ---------------------------------------------------------------------
class VolumeWizard : public FXDialogBox {
	FXDECLARE(VolumeWizard)
private:
	FXSwitcher* pages = nullptr;
	FXButton *backBtn = nullptr, *nextBtn = nullptr;
	FXint typeChoice = 0, mountChoice = 0, formatChoice = 1;
	FXDataTarget typeTarget, mountTarget, formatTarget;
	FXLabel *typeDesc = nullptr, *totalLabel = nullptr, *maxLabel = nullptr;
	FXSpinner* sizeSpin = nullptr;
	FXTextField *nameField = nullptr, *pathField = nullptr, *labelField = nullptr;
	FXListBox* fsBox = nullptr;
	FXCheckButton* quickCheck = nullptr;
	FXList* summary = nullptr;
	DiskPicker picker;
	std::vector<std::string> fsList;
	const disk::Snapshot* snap;
	std::string vg;
	int page = 0;
	static const int PAGES = 6;
protected:
	VolumeWizard() {}
public:
	enum { ID_BACK = FXDialogBox::ID_LAST, ID_NEXT, ID_TYPE, ID_ADD, ID_REM, ID_REMALL, ID_SIZE };
	VolumeWizard(FXWindow* owner, const disk::Snapshot& s, const std::string& vg_, const std::string& clickedPv,
	             const std::vector<std::string>& fs, const std::string& suggestedName)
		: FXDialogBox(owner, "Assistent zum Erstellen von Datenträgern", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,600,440, 0,0,0,0, 0,0),
		  typeTarget(typeChoice, this, ID_TYPE), mountTarget(mountChoice), formatTarget(formatChoice), fsList(fs), snap(&s), vg(vg_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0);
		pages = new FXSwitcher(main, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 20,20,16,10);
		FXFontDesc fd; getApp()->getNormalFont()->getFontDesc(fd); fd.size = 160; fd.weight = FXFont::Bold;
		FXFont* big = new FXFont(getApp(), fd);

		// 1: Willkommen (375)
		FXVerticalFrame* p1 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,12);
		(new FXLabel(p1, "Willkommen", NULL, JUSTIFY_LEFT))->setFont(big);
		new FXLabel(p1, "Mit diesem Assistenten können Sie Datenträger auf dynamischen Festplatten erstellen.", NULL, JUSTIFY_LEFT);
		new FXLabel(p1, "Ein Datenträger ist ein Teil einer oder mehrerer Festplatten, der als separate Festplatte\n"
		                "behandelt wird. Ein Datenträger kann mit einem Dateisystem formatiert werden.", NULL, JUSTIFY_LEFT);
		new FXLabel(p1, FXString("Volumegruppe: ") + vg.c_str(), NULL, JUSTIFY_LEFT);
		new FXLabel(p1, "Klicken Sie auf \"Weiter\", um den Vorgang fortzusetzen.", NULL, JUSTIFY_LEFT);

		// 2: Typ (376)
		FXVerticalFrame* p2 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		FXGroupBox* tg = new FXGroupBox(p2, "Typ des Datenträgers", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8);
		FXMatrix* tm = new FXMatrix(tg, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 30,4);
		new FXRadioButton(tm, "&Einfacher Datenträger", &typeTarget, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(tm, "&Gespiegelter Datenträger", &typeTarget, FXDataTarget::ID_OPTION + 3);
		new FXRadioButton(tm, "Ü&bergreifender Datenträger", &typeTarget, FXDataTarget::ID_OPTION + 1);
		new FXRadioButton(tm, "&RAID-5-Datenträger", &typeTarget, FXDataTarget::ID_OPTION + 4);
		new FXRadioButton(tm, "&Stripesetdatenträger", &typeTarget, FXDataTarget::ID_OPTION + 2);
		FXGroupBox* dg = new FXGroupBox(p2, "Beschreibung", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,6,6);
		typeDesc = new FXLabel(dg, "", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

		// 3: Festplatten und Größe (378) -- dazu der Name, den LVM braucht
		FXVerticalFrame* p3 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		picker.build(p3, this, ID_ADD, ID_REM, ID_REMALL);
		for (auto& p : s.pvs) {
			if (p.vg != vg || p.free < (8ull << 20)) continue;
			FXString item = FXString(p.name.c_str()) + " (" + disk::formatSize(p.free).c_str() + " frei)";
			if (p.name == clickedPv) picker.chosen->appendItem(item); else picker.avail->appendItem(item);
		}
		FXGroupBox* sg = new FXGroupBox(p3, "Größe", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,4,6);
		FXHorizontalFrame* sr = new FXHorizontalFrame(sg, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXLabel(sr, "&Für jede ausgewählte Festplatte:", NULL, LAYOUT_CENTER_Y);
		sizeSpin = new FXSpinner(sr, 7, this, ID_SIZE, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		sizeSpin->setRange(8, 8);
		new FXLabel(sr, "MB", NULL, LAYOUT_CENTER_Y);
		maxLabel = new FXLabel(sr, "", NULL, LAYOUT_CENTER_Y);
		totalLabel = new FXLabel(sg, "", NULL, JUSTIFY_LEFT);
		FXHorizontalFrame* nr = new FXHorizontalFrame(p3, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXLabel(nr, "&Name des Datenträgers (LVM):", NULL, LAYOUT_CENTER_Y);
		nameField = new FXTextField(nr, 20, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		nameField->setText(suggestedName.c_str());

		// 4: Laufwerkpfad (381)
		FXVerticalFrame* p4 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(p4, "Sie können über einen Laufwerkbuchstaben oder -pfad, den Sie dem Datenträger zuweisen,\n"
		                "auf den Datenträger zugreifen. Laufwerkbuchstaben gibt es unter Linux nicht.", NULL, JUSTIFY_LEFT);
		new FXRadioButton(p4, "&Diesen Datenträger in einem leeren Ordner bereitstellen, der Laufwerkpfade unterstützt:", &mountTarget, FXDataTarget::ID_OPTION + 0);
		pathField = new FXTextField(p4, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X, 0,0,0,0, 16,2,2,2);
		pathField->setText(("/srv/" + suggestedName).c_str());
		new FXRadioButton(p4, "&Keinen Laufwerkbuchstaben oder -pfad zuordnen", &mountTarget, FXDataTarget::ID_OPTION + 1);

		// 5: Formatieren (382)
		FXVerticalFrame* p5 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		new FXLabel(p5, "Geben Sie an, ob dieser Datenträger formatiert werden soll", NULL, JUSTIFY_LEFT);
		new FXRadioButton(p5, "Diesen Datenträger &nicht formatieren", &formatTarget, FXDataTarget::ID_OPTION + 0);
		new FXRadioButton(p5, "D&iesen Datenträger folgendermaßen formatieren:", &formatTarget, FXDataTarget::ID_OPTION + 1);
		FXGroupBox* fg = new FXGroupBox(p5, "Formatierung", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,4,6);
		FXMatrix* m5 = new FXMatrix(fg, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,4);
		new FXLabel(m5, "Zu &verwendendes Dateisystem:", NULL, JUSTIFY_LEFT);
		fsBox = new FXListBox(m5, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		fillFs(fsBox, fsList, "ext4");
		new FXLabel(m5, "&Größe der Zuordnungseinheit:", NULL, JUSTIFY_LEFT);
		FXListBox* au = new FXListBox(m5, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LISTBOX_NORMAL);
		au->appendItem("Standard");
		au->setNumVisible(1);
		new FXLabel(m5, "&Datenträgerbezeichnung:", NULL, JUSTIFY_LEFT);
		labelField = new FXTextField(m5, 16, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		labelField->setText("Daten");
		quickCheck = new FXCheckButton(fg, "Formatierung mit &QuickFormat durchführen");
		quickCheck->setCheck(TRUE);

		// 6: Fertigstellen (380)
		FXVerticalFrame* p6 = new FXVerticalFrame(pages, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,6);
		(new FXLabel(p6, "Fertigstellen des Assistenten", NULL, JUSTIFY_LEFT))->setFont(big);
		new FXLabel(p6, "Sie haben neue Einstellungen für folgende Elemente gewählt:", NULL, JUSTIFY_LEFT);
		FXPacker* sf = new FXPacker(p6, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		summary = new FXList(sf, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXLabel(p6, "Klicken Sie auf \"Fertig stellen\", um den Vorgang abzuschließen.", NULL, JUSTIFY_LEFT);

		new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 10,10,8,10, 6,0);
		backBtn = new FXButton(btns, "< &Zurück", NULL, this, ID_BACK, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		nextBtn = new FXButton(btns, "&Weiter >", NULL, this, ID_NEXT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		new FXButton(btns, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
		onType(NULL, 0, NULL);
		updateSize();
		showPage();
	}
	disk::SegmentKind kind() const {
		const disk::SegmentKind k[] = { disk::SEG_SIMPLE, disk::SEG_SPANNED, disk::SEG_STRIPED, disk::SEG_MIRRORED, disk::SEG_RAID5 };
		return k[typeChoice];
	}
	// Größte Größe je Festplatte: das Minimum des freien Platzes der
	// gewählten Festplatten, bei RAID etwas weniger für die Metadaten.
	void updateSize() {
		std::vector<std::string> sel = picker.selected();
		uint64_t minFree = 0;
		for (size_t i = 0; i < sel.size(); i++) {
			uint64_t f = pvFree(*snap, sel[i]);
			minFree = i == 0 ? f : std::min(minFree, f);
		}
		if (kind() == disk::SEG_MIRRORED || kind() == disk::SEG_RAID5) minFree = minFree > (8ull << 20) ? minFree - (8ull << 20) : 0;
		FXint maxMb = (FXint)(minFree >> 20);
		FXint cur = sizeSpin->getValue();
		sizeSpin->setRange(8, std::max<FXint>(8, maxMb));
		sizeSpin->setValue(cur <= 8 || cur > maxMb ? std::max<FXint>(8, maxMb) : cur);
		maxLabel->setText(FXString("  Max: ") + FXString(std::to_string(maxMb).c_str()) + " MB");
		totalLabel->setText(FXString("Gesamtgröße des Datenträgers: ") + disk::formatSize(disk::volumeCapacity(result())).c_str());
	}
	void showPage() {
		pages->setCurrent(page);
		if (page == 0) backBtn->disable(); else backBtn->enable();
		nextBtn->setText(page == PAGES - 1 ? "Fertig stellen" : "&Weiter >");
		if (page == PAGES - 1) {
			disk::NewVolume v = result();
			summary->clearItems();
			summary->appendItem(FXString("Datenträgertyp: ") + disk::kindName(v.kind));
			FXString d;
			for (auto& p : v.pvs) d += (d.empty() ? "" : ", ") + FXString(p.c_str());
			summary->appendItem(FXString("Ausgewählte Festplatten: ") + d);
			summary->appendItem(FXString("Größe: ") + disk::formatSize(disk::volumeCapacity(v)).c_str());
			summary->appendItem(FXString("Name: ") + v.vg.c_str() + "/" + v.name.c_str());
			summary->appendItem(FXString("Pfad: ") + (v.mountpoint.empty() ? FXString("Keiner") : FXString(v.mountpoint.c_str())));
			summary->appendItem(v.format ? FXString("Dateisystem: ") + v.fstype.c_str() + ", Bezeichnung: " + v.label.c_str()
			                             : FXString("Nicht formatieren"));
		}
	}
	long onType(FXObject*, FXSelector, void*) {
		// Beschreibungen wortgleich aus dmdskres.dll (6021-6025), gekürzt auf die ersten Sätze.
		const char* desc[] = {
			"Ein einfacher Datenträger wird aus freiem Speicherplatz auf einer einzigen dynamischen\n"
			"Festplatte erstellt. Ein einfacher Datenträger kann erweitert werden, indem freier\n"
			"Speicherplatz von der Festplatte oder einer anderen Festplatte hinzugefügt wird.",
			"Ein übergreifender Datenträger wird aus freiem Speicherplatz auf mehr als einer dynamischen\n"
			"Festplatte erstellt. Erstellen Sie einen übergreifenden Datenträger, wenn Sie einen\n"
			"Datenträger benötigen, der für eine einzige Festplatte zu groß ist.",
			"Ein Stripesetdatenträger speichert Daten auf mindestens zwei dynamischen Festplatten.\n"
			"Mit einem Stripesetdatenträger kann schneller auf Daten zugegriffen werden als mit einem\n"
			"einfachen oder übergreifenden Datenträger.",
			"Ein gespiegelter Datenträger dupliziert Daten auf zwei dynamische Festplatten. Erstellen Sie\n"
			"einen gespiegelten Datenträger, wenn Sie zwei separate Kopien aller Daten speichern möchten,\n"
			"um Datenverlust zu verhindern.",
			"Ein RAID-5-Datenträger speichert Daten in Stripes auf mindestens drei dynamischen Festplatten.\n"
			"Wie bei einem gespiegelten Datenträger können Daten wiederhergestellt werden, wenn ein Teil\n"
			"der Daten verloren gegangen ist." };
		typeDesc->setText(desc[typeChoice]);
		if (sizeSpin) updateSize();
		return 1;
	}
	long onPick(FXObject*, FXSelector sel, void*) {
		if (FXSELID(sel) == ID_ADD) picker.add();
		else if (FXSELID(sel) == ID_REM) picker.remove();
		else picker.removeAll();
		updateSize();
		return 1;
	}
	long onSize(FXObject*, FXSelector, void*) { updateSize(); return 1; }
	long onBack(FXObject*, FXSelector, void*) { if (page > 0) page--; if (page == 3 && formatChoice == 0) {} showPage(); return 1; }
	long onNext(FXObject*, FXSelector, void*) {
		if (page == PAGES - 1) return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
		if (page == 2) {
			disk::Plan test = disk::planCreateVolume(result());
			if (!test.ok()) { ice2kui::error(this, MBOX_OK, "Assistent zum Erstellen von Datenträgern", "%s", test.error.c_str()); return 1; }
		}
		if (page == 3 && mountChoice == 0) {
			std::string p = pathField->getText().text();
			if (p.empty() || p[0] != '/') { ice2kui::error(this, MBOX_OK, "Assistent zum Erstellen von Datenträgern", "Geben Sie einen absoluten Pfad an, z.B. /srv/daten."); return 1; }
		}
		page++;
		showPage();
		return 1;
	}
	disk::NewVolume result() const {
		disk::NewVolume v;
		v.kind = kind();
		v.vg = vg;
		v.name = nameField->getText().text();
		v.pvs = picker.selected();
		v.sizePerDisk = (uint64_t)sizeSpin->getValue() << 20;
		v.format = formatChoice == 1 && !fsList.empty();
		if (v.format) v.fstype = fsList[std::max(0, fsBox->getCurrentItem())];
		v.label = labelField->getText().text();
		v.quick = quickCheck->getCheck();
		if (v.format && mountChoice == 0) v.mountpoint = pathField->getText().text();
		return v;
	}
	virtual ~VolumeWizard() {}
};
FXDEFMAP(VolumeWizard) VolumeWizardMap[] = {
	FXMAPFUNC(SEL_COMMAND, VolumeWizard::ID_BACK, VolumeWizard::onBack),
	FXMAPFUNC(SEL_COMMAND, VolumeWizard::ID_NEXT, VolumeWizard::onNext),
	FXMAPFUNC(SEL_COMMAND, VolumeWizard::ID_TYPE, VolumeWizard::onType),
	FXMAPFUNCS(SEL_COMMAND, VolumeWizard::ID_ADD, VolumeWizard::ID_REMALL, VolumeWizard::onPick),
	FXMAPFUNC(SEL_COMMAND, VolumeWizard::ID_SIZE, VolumeWizard::onSize),
	FXMAPFUNC(SEL_CHANGED, VolumeWizard::ID_SIZE, VolumeWizard::onSize),
};
FXIMPLEMENT(VolumeWizard, FXDialogBox, VolumeWizardMap, ARRAYNUMBER(VolumeWizardMap))

// ---------------------------------------------------------------------
// "Assistent zum Erweitern von Datenträgern" (385, auf eine Seite verkürzt)
// ---------------------------------------------------------------------
class ExtendDialog : public FXDialogBox {
	FXDECLARE(ExtendDialog)
private:
	DiskPicker picker;
	FXSpinner* sizeSpin = nullptr;
	const disk::Snapshot* snap;
protected:
	ExtendDialog() {}
public:
	enum { ID_ADD = FXDialogBox::ID_LAST, ID_REM, ID_REMALL };
	ExtendDialog(FXWindow* owner, const disk::Snapshot& s, const std::string& vg, const std::string& lvName)
		: FXDialogBox(owner, "Assistent zum Erweitern von Datenträgern", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,560,340, 14,14,12,12, 0,6), snap(&s) {
		new FXLabel(this, FXString("Datenträger: ") + vg.c_str() + "/" + lvName.c_str() + "\n"
		                  "Mit diesem Assistenten können Sie die Größe von einfachen und übergreifenden\n"
		                  "Datenträgern auf dynamischen Festplatten erhöhen. Das Dateisystem wird mit vergrößert.", NULL, JUSTIFY_LEFT);
		picker.build(this, this, ID_ADD, ID_REM, ID_REMALL);
		for (auto& p : s.pvs)
			if (p.vg == vg && p.free >= (8ull << 20))
				picker.avail->appendItem(FXString(p.name.c_str()) + " (" + disk::formatSize(p.free).c_str() + " frei)");
		FXGroupBox* g = new FXGroupBox(this, "Größe des Datenträgers", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,4,6);
		FXHorizontalFrame* r = new FXHorizontalFrame(g, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXLabel(r, "&Für alle ausgewählten Festplatten:", NULL, LAYOUT_CENTER_Y);
		sizeSpin = new FXSpinner(r, 7, NULL, 0, FRAME_SUNKEN | FRAME_THICK | SPIN_NORMAL);
		sizeSpin->setRange(8, 1 << 30);
		sizeSpin->setValue(100);
		new FXLabel(r, "MB", NULL, LAYOUT_CENTER_Y);
		FXHorizontalFrame* btns = new FXHorizontalFrame(this, LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,6,0, 6,0);
		new FXButton(btns, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
		new FXButton(btns, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
	}
	long onPick(FXObject*, FXSelector sel, void*) {
		if (FXSELID(sel) == ID_ADD) picker.add(); else if (FXSELID(sel) == ID_REM) picker.remove(); else picker.removeAll();
		return 1;
	}
	std::vector<std::string> pvs() const { return picker.selected(); }
	uint64_t addPerDisk() const { return (uint64_t)sizeSpin->getValue() << 20; }
	virtual ~ExtendDialog() {}
};
FXDEFMAP(ExtendDialog) ExtendDialogMap[] = {
	FXMAPFUNCS(SEL_COMMAND, ExtendDialog::ID_ADD, ExtendDialog::ID_REMALL, ExtendDialog::onPick),
};
FXIMPLEMENT(ExtendDialog, FXDialogBox, ExtendDialogMap, ARRAYNUMBER(ExtendDialogMap))

// Nächster freier Name für einen neuen Datenträger in der Volumegruppe.
static std::string suggestVolumeName(const disk::Snapshot& snap, const std::string& vg) {
	for (int i = 1; i < 1000; i++) {
		std::string n = "datentraeger" + std::to_string(i);
		bool used = false;
		for (auto& d : snap.disks) for (auto& s : d.segments) if (s.vgName == vg && s.lvName == n) used = true;
		if (!used) return n;
	}
	return "datentraeger";
}

long DiskPanel::onDynamicAction(FXObject*, FXSelector sel, void*) {
	int d = map->selectedDisk(), s = map->selectedSegment();
	if (d < 0) return 1;
	const disk::Disk dk = snap.disks[d];
	FXuint id = FXSELID(sel);
	bool changed = false;
	std::string vg;
	for (auto& p : snap.pvs) if (p.name == dk.path) vg = p.vg;
	if (id == ID_CONVERT) {
		std::string target;
		bool newVg = false;
		if (convertDialog(this, snap, dk.path, target, newVg))
			changed = runPlan(this, "In dynamische Festplatte umwandeln", disk::planConvertToDynamic(dk, target, newVg));
	} else if (id == ID_REVERT) {
		changed = runPlan(this, "In eine Basisfestplatte zurückkonvertieren", disk::planRevertToBasic(dk, snap));
	} else if (id == ID_CREATE_VOL) {
		if (vg.empty()) { ice2kui::error(this, MBOX_OK, "Datenträgerverwaltung", "Die Festplatte gehört zu keiner Volumegruppe."); return 1; }
		VolumeWizard wiz(this, snap, vg, dk.path, disk::availableFilesystems(runAsRoot), suggestVolumeName(snap, vg));
		if (wiz.execute(PLACEMENT_OWNER))
			changed = runPlan(this, "Assistent zum Erstellen von Datenträgern", disk::planCreateVolume(wiz.result()));
	} else if (s >= 0) {
		const disk::Segment sg = dk.segments[s];
		if (id == ID_EXTEND_VOL) {
			ExtendDialog dlg(this, snap, sg.vgName, sg.lvName);
			if (dlg.execute(PLACEMENT_OWNER))
				changed = runPlan(this, "Assistent zum Erweitern von Datenträgern", disk::planExtendVolume(sg, sg.kind, dlg.pvs(), dlg.addPerDisk()));
		} else if (id == ID_DELETE_VOL) {
			changed = runPlan(this, "Datenträger löschen", disk::planDeleteVolume(sg));
		}
	}
	if (changed) reload();
	return 1;
}

// =====================================================================
// Spiegelungen und Reparatur
// =====================================================================

// Auswahl einer Festplatte -- Aufbau wie "Spiegelung zu ... hinzufügen"
// (Dialog 165): Beschreibung, Aufforderung, Liste.
static bool pickDiskDialog(FXWindow* owner, const FXString& title, const FXString& description,
                           const FXString& prompt, const std::vector<std::string>& items,
                           const FXString& okText, std::string& picked) {
	if (items.empty()) {
		ice2kui::information(owner, MBOX_OK, title.text(), "Es ist keine geeignete Festplatte vorhanden.\n\n"
		                     "Benötigt wird eine dynamische Festplatte derselben Volumegruppe mit genügend freiem Speicher.");
		return false;
	}
	FXDialogBox dlg(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,560,380, 12,12,12,12, 0,6);
	// Knöpfe zuerst und unten verankert, damit die Liste sie nicht verdrängt.
	FXHorizontalFrame* btns = new FXHorizontalFrame(&dlg, LAYOUT_SIDE_BOTTOM | LAYOUT_RIGHT, 0,0,0,0, 0,0,6,0, 6,0);
	new FXButton(btns, okText, NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
	new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,3,3);
	FXGroupBox* g = new FXGroupBox(&dlg, "Beschreibung", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8);
	new FXLabel(g, description, NULL, JUSTIFY_LEFT);
	new FXLabel(&dlg, prompt, NULL, JUSTIFY_LEFT);
	FXPacker* lf = new FXPacker(&dlg, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	FXList* list = new FXList(lf, NULL, 0, LIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	for (auto& i : items) list->appendItem(i.c_str());
	list->setCurrentItem(0);
	list->selectItem(0);
	if (!dlg.execute(PLACEMENT_OWNER)) return false;
	std::string t = list->getItemText(std::max(0, list->getCurrentItem())).text();
	picked = t.substr(0, t.find(' '));
	return true;
}

// Festplatten derselben Volumegruppe, auf denen der Datenträger noch
// nicht liegt und die genug Platz haben.
static std::vector<std::string> spareDisks(const disk::Snapshot& snap, const std::string& vg,
                                           const std::vector<std::string>& used, uint64_t need) {
	std::vector<std::string> out;
	for (auto& p : snap.pvs)
		if (p.vg == vg && p.free >= need && std::find(used.begin(), used.end(), p.name) == used.end())
			out.push_back(p.name + " (" + disk::formatSize(p.free) + " frei)");
	return out;
}

long DiskPanel::onMirrorAction(FXObject*, FXSelector sel, void*) {
	int d = map->selectedDisk(), s = map->selectedSegment();
	if (d < 0 || s < 0) return 1;
	const disk::Segment sg = snap.disks[d].segments[s];
	if (sg.lvName.empty()) return 1;
	std::vector<std::string> used = disk::pvsOfVolume(snap, sg.vgName, sg.lvName);
	FXString name = FXString(sg.vgName.c_str()) + "/" + sg.lvName.c_str();
	bool changed = false;
	std::string pv;
	switch (FXSELID(sel)) {
		case ID_ADD_MIRROR:
			// Texte 4000, 4001, 4003
			if (pickDiskDialog(this, FXString("Spiegelung zu ") + name + " hinzufügen",
			        "Das Hinzufügen eines Spiegels zu einem vorhandenen Datenträger führt zu\n"
			        "Datenredundanz, da mehrfache Kopien der Datenträgerdaten gespeichert werden.",
			        FXString("Wählen Sie einen Datenträger, der als gespiegelter Speicherplatz für ") + name + "\nverwendet werden soll.",
			        spareDisks(snap, sg.vgName, used, sg.size + (8ull << 20)), "Spiegelung hinzufügen", pv))
				changed = runPlan(this, "Spiegelung hinzufügen", disk::planAddMirror(sg, sg.kind, pv));
			break;
		case ID_REMOVE_MIRROR: {
			// Texte 4006, 4007, 4008
			std::vector<std::string> items;
			for (auto& u : used) items.push_back(u);
			if (pickDiskDialog(this, "Spiegelung entfernen",
			        "Das Entfernen eines Spiegels dieses Datenträgers entfernt eine Kopie der Daten\n"
			        "dieses Datenträgers. Der Datenträger wird nicht länger zusätzliche Daten enthalten.",
			        FXString("Wählen Sie einen Datenträger, um gespiegelten Speicherplatz von ") + name + "\nzu entfernen.",
			        items, "Spiegelung entfernen", pv))
				changed = runPlan(this, "Spiegelung entfernen", disk::planRemoveMirror(sg, sg.kind, pv));
			break;
		}
		case ID_SPLIT_MIRROR: {
			FXString newName = FXString(sg.lvName.c_str()) + "_2";
			if (FXInputDialog::getString(newName, this, "Spiegelung aufteilen",
			        "Name des einfachen Datenträgers, der aus der zweiten Kopie entsteht:"))
				changed = runPlan(this, "Spiegelung aufteilen", disk::planSplitMirror(sg, sg.kind, newName.text()));
			break;
		}
		case ID_REPAIR_VOL:
			// Dialog 383 (RAID-5) bzw. sinngemäß für Spiegel
			if (pickDiskDialog(this, sg.kind == disk::SEG_RAID5 ? "RAID-5-Datenträger reparieren" : "Gespiegelten Datenträger reparieren",
			        sg.kind == disk::SEG_RAID5
			            ? "Ein fehlender oder fehlerhafter Teil des Datenträgers wird auf einer anderen\nFestplatte neu erzeugt."
			            : "Die fehlende oder fehlerhafte Kopie wird auf einer anderen Festplatte neu erzeugt.",
			        sg.kind == disk::SEG_RAID5
			            ? "Wählen Sie eine der unten aufgeführten Festplatten als Ersatz für den\nbeschädigten RAID-5-Datenträger."
			            : "Wählen Sie eine der unten aufgeführten Festplatten als Ersatz für den\nbeschädigten gespiegelten Datenträger.",
			        spareDisks(snap, sg.vgName, used, sg.size + (8ull << 20)), "OK", pv))
				changed = runPlan(this, "Datenträger reparieren", disk::planRepairVolume(sg, sg.kind, pv));
			break;
		case ID_RESYNC:
			changed = runPlan(this, sg.kind == disk::SEG_RAID5 ? "Parität erneut erzeugen" : "Spiegelung erneut synchronisieren",
			                  disk::planResync(sg, sg.kind));
			break;
	}
	if (changed) reload();
	return 1;
}

// =====================================================================
// Eigenschaften
// =====================================================================

// Kreisdiagramm "Belegter / Freier Speicher" wie im Explorer.
class PieView : public FXFrame {
	FXDECLARE(PieView)
	double usedFraction = 0;
protected:
	PieView() {}
public:
	PieView(FXComposite* p, double used)
		: FXFrame(p, FRAME_NONE | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT | LAYOUT_CENTER_X, 0,0,150,90), usedFraction(used) {}
	long onPaint(FXObject*, FXSelector, void* ptr) {
		FXDCWindow dc(this, (FXEvent*)ptr);
		dc.setForeground(backColor);
		dc.fillRectangle(0, 0, width, height);
		const FXint w = width - 10, h = height - 24, x = 5, y = 4, depth = 12;
		// Seitenwand (dunkler), dann Deckel
		for (FXint d = depth; d > 0; d--) {
			dc.setForeground(FXRGB(128, 0, 128));
			dc.fillArc(x, y + d, w, h, 0, 360 * 64);
			dc.setForeground(FXRGB(0, 0, 128));
			dc.fillArc(x, y + d, w, h, 90 * 64, (FXint)(usedFraction * 360 * 64));
		}
		dc.setForeground(FXRGB(255, 0, 255));   // frei: Magenta
		dc.fillArc(x, y, w, h, 0, 360 * 64);
		dc.setForeground(FXRGB(0, 0, 255));     // belegt: Blau
		dc.fillArc(x, y, w, h, 90 * 64, (FXint)(usedFraction * 360 * 64));
		dc.setForeground(FXRGB(0, 0, 0));
		dc.drawArc(x, y, w, h, 0, 360 * 64);
		return 1;
	}
};
FXDEFMAP(PieView) PieViewMap[] = { FXMAPFUNC(SEL_PAINT, 0, PieView::onPaint) };
FXIMPLEMENT(PieView, FXFrame, PieViewMap, ARRAYNUMBER(PieViewMap))

static void addRow(FXMatrix* m, const char* label, const FXString& value) {
	new FXLabel(m, label, NULL, JUSTIFY_LEFT);
	new FXLabel(m, value, NULL, JUSTIFY_LEFT);
}

// Ergebnis einer Prüfung anzeigen -- auch bei Erfolg, anders als runPlan.
static void runAndShow(FXWindow* owner, const FXString& title, const disk::Plan& plan) {
	if (!plan.ok()) { ice2kui::error(owner, MBOX_OK, "Datenträgerverwaltung", "%s", plan.error.c_str()); return; }
	if (!plan.warning.empty() && ice2kui::information(owner, MBOX_OK_CANCEL, title.text(), "%s", plan.warning.c_str()) != MBOX_CLICKED_OK) return;
	owner->getApp()->beginWaitCursor();
	std::string log;
	bool ok = disk::execute(plan, runAsRootWithErrors, log);
	owner->getApp()->endWaitCursor();
	FXDialogBox dlg(owner, title, DECOR_TITLE | DECOR_BORDER | DECOR_RESIZE, 0,0,600,380, 12,12,12,12, 0,6);
	new FXButton(&dlg, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_SIDE_BOTTOM | LAYOUT_RIGHT, 0,0,0,0, 16,16,3,3);
	new FXLabel(&dlg, ok ? "Die Überprüfung wurde abgeschlossen:" : "Bei der Überprüfung wurden Probleme gemeldet:", NULL, JUSTIFY_LEFT);
	FXPacker* tf = new FXPacker(&dlg, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	FXText* text = new FXText(tf, NULL, 0, TEXT_READONLY | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	text->setText(log.c_str());
	dlg.execute(PLACEMENT_OWNER);
}

// ---------------------------------------------------------------------
// Eigenschaften eines Volumes: Allgemein, Tools, Hardware
// ---------------------------------------------------------------------
class VolumePropertiesDialog : public FXDialogBox {
	FXDECLARE(VolumePropertiesDialog)
private:
	disk::Segment seg;
	const disk::Disk* dsk;
	const disk::Snapshot* snap;
	FXTextField* labelField = nullptr;
	FXCheckButton* repairCheck = nullptr;
protected:
	VolumePropertiesDialog() {}
public:
	enum { ID_CHECK = FXDialogBox::ID_LAST, ID_OK };
	bool changed = false;
	VolumePropertiesDialog(FXWindow* owner, const disk::Snapshot& s, const disk::Disk& d, const disk::Segment& sg)
		: FXDialogBox(owner, "", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,500,480, 6,6,6,6, 0,6),
		  seg(sg), dsk(&d), snap(&s) {
		std::string where = !sg.mountpoint.empty() ? sg.mountpoint : sg.device.substr(sg.device.rfind('/') + 1);
		setTitle(FXString("Eigenschaften von ") + (sg.label.empty() ? "" : (sg.label + " ").c_str()) + "(" + where.c_str() + ")");

		FXHorizontalFrame* btns = new FXHorizontalFrame(this, LAYOUT_SIDE_BOTTOM | LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,4,0, 6,0);
		new FXButton(btns, "OK", NULL, this, ID_OK, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
		new FXButton(btns, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
		FXTabBook* tabs = new FXTabBook(this, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		// ---- Allgemein ----
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* gen = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,10,10, 0,6);
		labelField = new FXTextField(gen, 30, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
		labelField->setText(sg.label.c_str());
		if (sg.fstype.empty()) labelField->disable();
		new FXHorizontalSeparator(gen, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXMatrix* m = new FXMatrix(gen, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 16,3);
		addRow(m, "Typ:", disk::kindIsDynamic(sg.kind) ? "Dynamischer Datenträger" : "Lokaler Datenträger");
		addRow(m, "Dateisystem:", sg.fstype.empty() ? FXString("Nicht formatiert") : FXString(sg.fstype.c_str()));
		addRow(m, "Gerät:", sg.device.c_str());
		addRow(m, "Pfad:", sg.mountpoint.empty() ? FXString("Nicht eingehängt") : FXString(sg.mountpoint.c_str()));
		new FXHorizontalSeparator(gen, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXMatrix* m2 = new FXMatrix(gen, 3, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 12,3);
		auto sizeRow = [&](const char* label, FXColor color, int64_t bytes) {
			FXHorizontalFrame* l = new FXHorizontalFrame(m2, 0, 0,0,0,0, 0,0,0,0, 4,0);
			if (color) { FXFrame* sw = new FXFrame(l, FRAME_LINE | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT | LAYOUT_CENTER_Y, 0,0,10,10); sw->setBackColor(color); }
			new FXLabel(l, label, NULL, LAYOUT_CENTER_Y);
			new FXLabel(m2, bytes < 0 ? FXString("-") : FXString((std::to_string(bytes) + " Byte").c_str()), NULL, JUSTIFY_RIGHT | LAYOUT_FILL_COLUMN);
			new FXLabel(m2, bytes < 0 ? FXString("") : FXString(disk::formatSize((uint64_t)bytes).c_str()), NULL, JUSTIFY_RIGHT);
		};
		int64_t freeB = sg.freeBytes;
		int64_t usedB = freeB < 0 ? -1 : (int64_t)sg.size - freeB;
		sizeRow("Belegter Speicher:", FXRGB(0, 0, 255), usedB);
		sizeRow("Freier Speicher:", FXRGB(255, 0, 255), freeB);
		sizeRow("Speicherkapazität:", 0, (int64_t)sg.size);
		if (freeB >= 0 && sg.size) new PieView(gen, (double)usedB / (double)sg.size);
		else new FXLabel(gen, "Belegung erst nach dem Einhängen bekannt.", NULL, LAYOUT_CENTER_X);

		// ---- Tools ----
		new FXTabItem(tabs, "Tools", NULL);
		FXVerticalFrame* tools = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,10,10, 0,8);
		FXGroupBox* fe = new FXGroupBox(tools, "Fehlerüberprüfung", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8, 0,6);
		new FXLabel(fe, "Mit dieser Option wird der Datenträger auf Fehler überprüft.", NULL, JUSTIFY_LEFT);
		repairCheck = new FXCheckButton(fe, "Dateisystemfehler &automatisch korrigieren");
		if (!sg.mountpoint.empty()) {
			repairCheck->disable();
			new FXLabel(fe, "Der Datenträger ist eingehängt und wird nur lesend geprüft.", NULL, JUSTIFY_LEFT);
		}
		FXButton* check = new FXButton(fe, "&Jetzt prüfen...", NULL, this, ID_CHECK, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_RIGHT, 0,0,0,0, 10,10,3,3);
		if (sg.fstype.empty()) check->disable();
		FXGroupBox* df = new FXGroupBox(tools, "Defragmentierung", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8);
		new FXLabel(df, "Linux-Dateisysteme wie ext4, XFS und btrfs brauchen im Betrieb\n"
		                "keine regelmäßige Defragmentierung.", NULL, JUSTIFY_LEFT);

		// ---- Hardware ----
		new FXTabItem(tabs, "Hardware", NULL);
		FXVerticalFrame* hw = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,10,10, 0,6);
		new FXLabel(hw, "&Alle Laufwerke:", NULL, JUSTIFY_LEFT);
		FXPacker* hf = new FXPacker(hw, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		FXIconList* hl = new FXIconList(hf, NULL, 0, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		hl->appendHeader("Name", NULL, 200);
		hl->appendHeader("Typ", NULL, 150);
		// Bei dynamischen Datenträgern alle Platten, auf denen er liegt.
		std::vector<std::string> paths;
		if (!sg.lvName.empty()) paths = disk::pvsOfVolume(s, sg.vgName, sg.lvName);
		else paths.push_back(d.path);
		for (auto& pth : paths)
			for (auto& dd : s.disks)
				if (dd.path == pth) {
					std::string name = (dd.vendor.empty() ? "" : dd.vendor + " ") + (dd.model.empty() ? dd.name : dd.model);
					hl->appendItem(FXString(name.c_str()) + "\tLaufwerke (" + dd.path.c_str() + ")");
				}
	}
	long onCheck(FXObject*, FXSelector, void*) {
		runAndShow(this, "Datenträger prüfen", disk::planCheckFilesystem(seg, repairCheck->getCheck()));
		return 1;
	}
	long onOk(FXObject*, FXSelector, void*) {
		std::string label = labelField->getText().text();
		if (!seg.fstype.empty() && label != seg.label) {
			changed = runPlan(this, "Bezeichnung ändern", disk::planSetLabel(seg, label));
			if (!changed) return 1;
		}
		return handle(this, FXSEL(SEL_COMMAND, ID_ACCEPT), NULL);
	}
	virtual ~VolumePropertiesDialog() {}
};
FXDEFMAP(VolumePropertiesDialog) VolumePropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, VolumePropertiesDialog::ID_CHECK, VolumePropertiesDialog::onCheck),
	FXMAPFUNC(SEL_COMMAND, VolumePropertiesDialog::ID_OK, VolumePropertiesDialog::onOk),
};
FXIMPLEMENT(VolumePropertiesDialog, FXDialogBox, VolumePropertiesDialogMap, ARRAYNUMBER(VolumePropertiesDialogMap))

// ---------------------------------------------------------------------
// Eigenschaften eines Datenträgers (dmdskres.dll, Dialog 348)
// ---------------------------------------------------------------------
class DiskPropertiesDialog : public FXDialogBox {
	FXDECLARE(DiskPropertiesDialog)
private:
	const disk::Snapshot* snap;
	const disk::Disk* dsk;
	FXIconList* vols = nullptr;
	std::vector<int> segIndex;
protected:
	DiskPropertiesDialog() {}
public:
	enum { ID_VOLPROPS = FXDialogBox::ID_LAST };
	bool changed = false;
	DiskPropertiesDialog(FXWindow* owner, const disk::Snapshot& s, const disk::Disk& d, const FXString& diskTitle)
		: FXDialogBox(owner, FXString("Eigenschaften von ") + diskTitle, DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,430,460, 6,6,6,6, 0,6),
		  snap(&s), dsk(&d) {
		FXHorizontalFrame* btns = new FXHorizontalFrame(this, LAYOUT_SIDE_BOTTOM | LAYOUT_RIGHT | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,4,0, 6,0);
		new FXButton(btns, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
		new FXButton(btns, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 16,16,3,3);
		FXTabBook* tabs = new FXTabBook(this, NULL, 0, TABBOOK_NORMAL | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		new FXTabItem(tabs, "Allgemein", NULL);
		FXVerticalFrame* page = new FXVerticalFrame(tabs, FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,10,10, 0,6);
		uint64_t unalloc = 0;
		for (auto& sg : d.segments) if (sg.kind == disk::SEG_UNALLOCATED) unalloc += sg.size;
		FXMatrix* m = new FXMatrix(page, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 16,4);
		// Beschriftungen wortgleich aus Dialog 348
		addRow(m, "Laufwerk:", diskTitle + " (" + d.path.c_str() + ")");
		addRow(m, "Typ:", d.cdrom ? "CD-ROM" : d.removable ? "Wechselmedium" : d.dynamic ? "Dynamisch" : "Basis");
		addRow(m, "Status:", d.unreadable ? "Nicht lesbar" : "Online");
		addRow(m, "Kapazität:", disk::formatSize(d.size).c_str());
		addRow(m, "Verfügbarer Speicher:", disk::formatSize(unalloc).c_str());
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		FXMatrix* m2 = new FXMatrix(page, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 16,4);
		std::string tran = d.transport == "sata" ? "SATA" : d.transport == "nvme" ? "NVMe" : d.transport == "usb" ? "USB"
		                 : d.transport == "sas" ? "SAS" : d.transport.empty() ? "Unbekannt" : d.transport;
		addRow(m2, "Gerätetyp:", tran.c_str());
		addRow(m2, "Hardwarehersteller:", ((d.vendor.empty() ? "" : d.vendor + " ") + (d.model.empty() ? "Unbekannt" : d.model)).c_str());
		addRow(m2, "Seriennummer:", d.serial.empty() ? "Unbekannt" : d.serial.c_str());
		addRow(m2, "Partitionstabelle:", d.table == "msdos" ? "MBR" : d.table == "gpt" ? "GPT" : d.dynamic ? "LVM" : "Keine");
		new FXHorizontalSeparator(page, SEPARATOR_GROOVE | LAYOUT_FILL_X);
		new FXLabel(page, "Datenträger auf diesem Laufwerk:", NULL, JUSTIFY_LEFT);
		FXPacker* vf = new FXPacker(page, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		vols = new FXIconList(vf, this, ID_VOLPROPS, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
		vols->appendHeader("Datenträger", NULL, 180);
		vols->appendHeader("Kapazität", NULL, 90);
		for (size_t i = 0; i < d.segments.size(); i++) {
			const disk::Segment& sg = d.segments[i];
			if (sg.kind == disk::SEG_UNALLOCATED || sg.kind == disk::SEG_FREE || sg.kind == disk::SEG_EXTENDED || sg.isPv) continue;
			std::string where = !sg.mountpoint.empty() ? sg.mountpoint : !sg.lvName.empty() ? sg.lvName : sg.device.substr(sg.device.rfind('/') + 1);
			vols->appendItem(FXString((sg.label.empty() ? "(" + where + ")" : sg.label + " (" + where + ")").c_str()) + "\t" + disk::formatSize(sg.size).c_str());
			segIndex.push_back((int)i);
		}
		new FXButton(page, "&Eigenschaften", NULL, this, ID_VOLPROPS, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_RIGHT, 0,0,0,0, 10,10,3,3);
	}
	long onVolumeProps(FXObject*, FXSelector, void*) {
		int i = vols->getCurrentItem();
		if (i < 0 || i >= (int)segIndex.size()) return 1;
		VolumePropertiesDialog dlg(this, *snap, *dsk, dsk->segments[segIndex[i]]);
		dlg.execute(PLACEMENT_OWNER);
		if (dlg.changed) changed = true;
		return 1;
	}
	virtual ~DiskPropertiesDialog() {}
};
FXDEFMAP(DiskPropertiesDialog) DiskPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, DiskPropertiesDialog::ID_VOLPROPS, DiskPropertiesDialog::onVolumeProps),
	FXMAPFUNC(SEL_DOUBLECLICKED, DiskPropertiesDialog::ID_VOLPROPS, DiskPropertiesDialog::onVolumeProps),
};
FXIMPLEMENT(DiskPropertiesDialog, FXDialogBox, DiskPropertiesDialogMap, ARRAYNUMBER(DiskPropertiesDialogMap))

long DiskPanel::onProperties(FXObject*, FXSelector, void*) {
	int d = map->selectedDisk(), s = map->selectedSegment();
	if (d < 0) return 1;
	const disk::Disk& dk = snap.disks[d];
	bool changed = false;
	if (s < 0) {
		// Titel "Datenträger N" bzw. "CD-ROM N" wie in der Grafik
		int diskNo = 0, cdNo = 0;
		FXString title;
		for (int i = 0; i <= d; i++) {
			if (snap.disks[i].cdrom) { if (i == d) title = FXString("CD-ROM ") + FXString(std::to_string(cdNo).c_str()); cdNo++; }
			else { if (i == d) title = FXString("Datenträger ") + FXString(std::to_string(diskNo).c_str()); diskNo++; }
		}
		DiskPropertiesDialog dlg(this, snap, dk, title);
		dlg.execute(PLACEMENT_OWNER);
		changed = dlg.changed;
	} else {
		const disk::Segment& sg = dk.segments[s];
		if (sg.kind == disk::SEG_UNALLOCATED || sg.kind == disk::SEG_FREE) return 1;
		VolumePropertiesDialog dlg(this, snap, dk, sg);
		dlg.execute(PLACEMENT_OWNER);
		changed = dlg.changed;
	}
	if (changed) reload();
	return 1;
}

// Doppelklick in der Liste oder auf einen Abschnitt öffnet die Eigenschaften.
long DiskPanel::onOpenProperties(FXObject* sender, FXSelector, void*) {
	if (sender == volumes) onVolumeSelected(NULL, 0, NULL);
	return onProperties(NULL, 0, NULL);
}
