// services.cpp
//
// Eigenstaendiges "Dienste"-Werkzeug fuer ice2k -- Nachbau von
// services.msc. Die eigentliche Ansicht steckt komplett in SvcPanel
// (../common/svc), dasselbe Widget benutzt auch die Computerverwaltung
// in ihrem Zweig "Dienste und Anwendungen". Hier drumherum ist nur der
// MMC-Rahmen: Menue, Werkzeugleiste und der Strukturbaum.

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "../common/svc/svcpanel.h"
#include "../common/ui/msgbox.h"

class Services : public FXMainWindow {
	FXDECLARE(Services)
private:
	FXMenuBar* menubar;
	FXDockSite* topdock;
	FXToolBarShell* tbshell;
	FXToolBar* toolbar;
	FXMenuPane *vorgangmenu, *ansichtmenu, *hilfemenu;
	FXSplitter* splitter;
	FXTreeList* tree;
	SvcPanel* panel;
	FXIcon *icoRoot, *icoService;
	FXIcon *icoBack, *icoForward, *icoUp, *icoContree, *icoProperties, *icoRefresh, *icoHelp;
protected:
	Services() : menubar(NULL), topdock(NULL), tbshell(NULL), toolbar(NULL),
	             vorgangmenu(NULL), ansichtmenu(NULL), hilfemenu(NULL), splitter(NULL),
	             tree(NULL), panel(NULL), icoRoot(NULL), icoService(NULL), icoBack(NULL),
	             icoForward(NULL), icoUp(NULL), icoContree(NULL), icoProperties(NULL),
	             icoRefresh(NULL), icoHelp(NULL) {}
public:
	enum { ID_START = FXMainWindow::ID_LAST, ID_STOP, ID_RESTART, ID_PROPERTIES, ID_REFRESH, ID_ABOUT };

	long onStart(FXObject*, FXSelector, void*);
	long onStop(FXObject*, FXSelector, void*);
	long onRestart(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);

	Services(FXApp* a);
	virtual void create();
	virtual ~Services() {}
};

FXDEFMAP(Services) ServicesMap[] = {
	FXMAPFUNC(SEL_COMMAND, Services::ID_START, Services::onStart),
	FXMAPFUNC(SEL_COMMAND, Services::ID_STOP, Services::onStop),
	FXMAPFUNC(SEL_COMMAND, Services::ID_RESTART, Services::onRestart),
	FXMAPFUNC(SEL_COMMAND, Services::ID_PROPERTIES, Services::onProperties),
	FXMAPFUNC(SEL_COMMAND, Services::ID_REFRESH, Services::onRefresh),
	FXMAPFUNC(SEL_COMMAND, Services::ID_ABOUT, Services::onAbout),
};
FXIMPLEMENT(Services, FXMainWindow, ServicesMap, ARRAYNUMBER(ServicesMap))

Services::Services(FXApp* a)
	: FXMainWindow(a, "Dienste", NULL, NULL, DECOR_ALL, 0,0, 900,600) {

	FXGIFIcon* winIcon = new FXGIFIcon(a, resico_services);
	FXGIFIcon* winIconBig = new FXGIFIcon(a, resico_services_32);
	setIcon(winIconBig);
	setMiniIcon(winIcon);

	topdock = new FXDockSite(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	menubar = new FXMenuBar(topdock, LAYOUT_DOCK_NEXT | LAYOUT_SIDE_TOP | LAYOUT_FILL_X | FRAME_RAISED);

	vorgangmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Starten", NULL, this, ID_START);
	new FXMenuCommand(vorgangmenu, "&Beenden", NULL, this, ID_STOP);
	new FXMenuCommand(vorgangmenu, "Neu s&tarten", NULL, this, ID_RESTART);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "&Eigenschaften", NULL, this, ID_PROPERTIES);
	new FXMenuCommand(vorgangmenu, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(vorgangmenu);
	new FXMenuCommand(vorgangmenu, "Be&enden", NULL, getApp(), FXApp::ID_QUIT);

	ansichtmenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Ansicht", NULL, ansichtmenu);
	FXMenuCommand* mv = new FXMenuCommand(ansichtmenu, "&Details"); mv->disable();

	hilfemenu = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&?", NULL, hilfemenu);
	new FXMenuCommand(hilfemenu, "&Info...", NULL, this, ID_ABOUT);

	tbshell = new FXToolBarShell(this, FRAME_SUNKEN);
	toolbar = new FXToolBar(topdock, tbshell,
	                         LAYOUT_FILL_Y | LAYOUT_DOCK_SAME | LAYOUT_SIDE_TOP | FRAME_RAISED,
	                         0,0,0,0, 0,5,0,0, 1,1);
	new FXToolBarGrip(toolbar, toolbar, FXToolBar::ID_TOOLBARGRIP, TOOLBARGRIP_SINGLE, 0,0,0,0, 2,3,2,2);

	icoBack = new FXGIFIcon(a, resico_mmc_back);
	icoForward = new FXGIFIcon(a, resico_mmc_forward);
	icoUp = new FXGIFIcon(a, resico_mmc_up);
	icoContree = new FXGIFIcon(a, resico_mmc_contree);
	icoProperties = new FXGIFIcon(a, resico_mmc_properties);
	icoRefresh = new FXGIFIcon(a, resico_mmc_refresh);
	icoHelp = new FXGIFIcon(a, resico_mmc_help);

	FXButton* btn;
	btn = new FXButton(toolbar, "\tZurück", icoBack, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	btn = new FXButton(toolbar, "\tVor", icoForward, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	btn = new FXButton(toolbar, "\tEbene nach oben", icoUp, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2); btn->disable();
	new FXButton(toolbar, "\tStruktur/Favoriten anzeigen/ausblenden", icoContree, NULL, 0, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	new FXButton(toolbar, "\tEigenschaften", icoProperties, this, ID_PROPERTIES, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	new FXButton(toolbar, "\tAktualisieren", icoRefresh, this, ID_REFRESH, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	// Die Originalleiste hat hier die vier Wiedergabe-Schaltflaechen
	// (Starten/Beenden/Anhalten/Fortsetzen). Passende Icons gibt es im
	// ice2k-Bestand noch nicht, deshalb vorerst als Text.
	new FXButton(toolbar, "Starten", NULL, this, ID_START, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,6,6,2,2);
	new FXButton(toolbar, "Beenden", NULL, this, ID_STOP, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,6,6,2,2);
	new FXButton(toolbar, "Neu starten", NULL, this, ID_RESTART, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,6,6,2,2);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE|LAYOUT_FILL_Y,0,0,0,0,3,2,2,2);
	new FXButton(toolbar, "\tHilfe", icoHelp, this, ID_ABOUT, BUTTON_TOOLBAR|FRAME_RAISED|LAYOUT_CENTER_Y,0,0,0,0,2,2,2,2);

	new FXSeparator(this, SEPARATOR_NONE|LAYOUT_FIX_HEIGHT, 0,0,0,2);

	splitter = new FXSplitter(this, LAYOUT_FILL_X|LAYOUT_FILL_Y|SPLITTER_TRACKING);

	FXPacker* treeframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y, 0,0,200,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, NULL, 0,
	                       SCROLLERS_DONT_TRACK|FRAME_NORMAL|LAYOUT_FILL_X|LAYOUT_FILL_Y|
	                       TREELIST_SHOWS_BOXES|TREELIST_SHOWS_LINES|TREELIST_BROWSESELECT|TREELIST_ROOT_BOXES);

	FXPacker* panelframe = new FXPacker(splitter, FRAME_NORMAL|LAYOUT_FILL_Y|LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);

	icoRoot = new FXPNGIcon(a, resico_network, IMAGE_NEAREST); icoRoot->create();
	icoService = new FXPNGIcon(a, resico_key, IMAGE_NEAREST); icoService->create();

	tree->appendItem(0, "Dienste (Lokal)", icoRoot, icoRoot);
	panel = new SvcPanel(panelframe, icoService);
}

void Services::create() {
	FXMainWindow::create();
	if (!svc::systemdAvailable()) {
		ice2kui::warning(this, MBOX_OK, "Dienste",
			"Auf diesem System ist kein systemd erreichbar.\n"
			"Die Liste bleibt deshalb leer.");
	}
	panel->reload();
	show(PLACEMENT_SCREEN);
}

long Services::onStart(FXObject*, FXSelector, void*) { panel->startSelected(); return 1; }
long Services::onStop(FXObject*, FXSelector, void*) { panel->stopSelected(); return 1; }
long Services::onRestart(FXObject*, FXSelector, void*) { panel->restartSelected(); return 1; }
long Services::onProperties(FXObject*, FXSelector, void*) { panel->propertiesForSelected(); return 1; }
long Services::onRefresh(FXObject*, FXSelector, void*) { panel->reload(); return 1; }

long Services::onAbout(FXObject*, FXSelector, void*) {
	ice2kui::information(this, MBOX_OK, "Über Dienste",
		"Dienste für ice2k\n\n"
		"Verwaltet systemd-Dienste im Stil von services.msc.\n"
		"Dieselbe Ansicht steckt auch in der Computerverwaltung\n"
		"unter \"Dienste und Anwendungen\".");
	return 1;
}

int main(int argc, char** argv) {
	FXApp application("Dienste", "ice2k");
	application.init(argc, argv);
	new Services(&application);
	application.create();
	return application.run();
}
