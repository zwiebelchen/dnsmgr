// diskmgmt.cpp
//
// "Datenträgerverwaltung" fuer ice2k -- Nachbau von diskmgmt.msc aus
// Windows 2000. Die eigentliche Ansicht steckt in common/disk
// (diskcore, diskpanel), damit die Computerverwaltung sie unter
// "Datenspeicher" genauso zeigen kann.
//
// Stand: nur Anzeige. Partitionieren, Formatieren und LVM folgen in
// eigenen Schritten.

#include <fx.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "../common/disk/diskpanel.h"
#include "../common/ui/msgbox.h"

class DiskMgmtWindow : public FXMainWindow {
	FXDECLARE(DiskMgmtWindow)
private:
	DiskPanel* panel = nullptr;
	FXLabel* statusbar = nullptr;
protected:
	DiskMgmtWindow() {}
public:
	enum { ID_REFRESH = FXMainWindow::ID_LAST, ID_ABOUT };
	DiskMgmtWindow(FXApp* a) : FXMainWindow(a, "Datenträgerverwaltung", NULL, NULL, DECOR_ALL, 0,0, 980,620) {
		FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
		FXMenuPane* vorgang = new FXMenuPane(this);
		new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
		new FXMenuCommand(vorgang, "&Aktualisieren", NULL, this, ID_REFRESH);
		FXMenuPane* ansicht = new FXMenuPane(this);
		new FXMenuTitle(menubar, "A&nsicht", NULL, ansicht);
		new FXMenuCommand(ansicht, "&Aktualisieren", NULL, this, ID_REFRESH);
		FXMenuPane* hilfe = new FXMenuPane(this);
		new FXMenuTitle(menubar, "&?", NULL, hilfe);
		new FXMenuCommand(hilfe, "&Info", NULL, this, ID_ABOUT);

		FXToolBar* toolbar = new FXToolBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);
		auto gif = [&](const unsigned char* d) { return new FXGIFIcon(getApp(), d); };
		auto tb = [&](const char* tip, FXIcon* ic, FXSelector sel) {
			new FXButton(toolbar, tip, ic, this, sel, BUTTON_TOOLBAR | FRAME_RAISED | LAYOUT_CENTER_Y, 0,0,0,0, 2,2,2,2);
		};
		tb("\tZurück", gif(resico_mmc_back), 0);
		tb("\tVor", gif(resico_mmc_forward), 0);
		new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
		tb("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
		tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
		new FXToolTip(getApp());

		statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);
		panel = new DiskPanel(this);
	}
	virtual void create() {
		FXMainWindow::create();
		show(PLACEMENT_SCREEN);
		reload();
	}
	void reload() {
		panel->reload();
		statusbar->setText(panel->statusText());
	}
	long onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }
	long onAbout(FXObject*, FXSelector, void*) {
		ice2kui::information(this, MBOX_OK, "Info",
			"Datenträgerverwaltung (ice2k)\n\n"
			"Datenträger, Partitionen und LVM. Basisdatenträger sind Platten mit\n"
			"klassischer Partitionstabelle; dynamische Datenträger sind LVM-Volumes.\n\n"
			"Diese Fassung zeigt nur an; Änderungen folgen.");
		return 1;
	}
	virtual ~DiskMgmtWindow() {}
};
FXDEFMAP(DiskMgmtWindow) DiskMgmtWindowMap[] = {
	FXMAPFUNC(SEL_COMMAND, DiskMgmtWindow::ID_REFRESH, DiskMgmtWindow::onRefresh),
	FXMAPFUNC(SEL_COMMAND, DiskMgmtWindow::ID_ABOUT, DiskMgmtWindow::onAbout),
};
FXIMPLEMENT(DiskMgmtWindow, FXMainWindow, DiskMgmtWindowMap, ARRAYNUMBER(DiskMgmtWindowMap))

int main(int argc, char* argv[]) {
	FXApp application("DiskMgmt", "Ice2KProj");
	application.init(argc, argv);
	new DiskMgmtWindow(&application);
	application.create();
	return application.run();
}
