// eventvwr.cpp
//
// "Ereignisanzeige" fuer ice2k -- Nachbau von eventvwr.msc aus Windows
// 2000: links die drei Protokolle Anwendung, Sicherheit und System,
// rechts die Ereignisliste.
//
// Das Einsammeln der Ereignisse und die Liste samt Dialogen stecken in
// common/evt (evtcore, evtpanel) -- die Computerverwaltung zeigt
// dieselbe Ansicht in ihrem Zweig "Systemprogramme".

#include <fx.h>
#include <FXPNGIcon.h>
#include <FXGIFIcon.h>
#include "res/foxres.h"
#include "../common/evt/evtpanel.h"

#include <string>
#include <unistd.h>
#include "../common/ui/msgbox.h"

static FXApp* app = NULL;

// ---------------------------------------------------------------------
// Hauptfenster
// ---------------------------------------------------------------------
class EventViewer : public FXMainWindow {
	FXDECLARE(EventViewer)
private:
	FXTreeList* tree = nullptr;
	EvtPanel* panel = nullptr;
	FXLabel* statusbar = nullptr;
	FXTreeItem* rootItem = nullptr;
	FXTreeItem* logItems[evt::LOG_COUNT] = { nullptr };
	FXIcon *icoRoot = nullptr, *icoLog = nullptr;
protected:
	EventViewer() {}
public:
	enum { ID_TREE = FXMainWindow::ID_LAST, ID_LIST, ID_REFRESH, ID_PROPERTIES, ID_FILTER, ID_CLEAR, ID_ABOUT };

	EventViewer(FXApp* a);
	virtual void create();
	long onTree(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onFilter(FXObject*, FXSelector, void*);
	long onClear(FXObject*, FXSelector, void*);
	long onAbout(FXObject*, FXSelector, void*);
	void reload();
	virtual ~EventViewer() {}
};

FXDEFMAP(EventViewer) EventViewerMap[] = {
	FXMAPFUNC(SEL_CHANGED, EventViewer::ID_TREE, EventViewer::onTree),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_REFRESH, EventViewer::onRefresh),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_PROPERTIES, EventViewer::onProperties),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_FILTER, EventViewer::onFilter),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_CLEAR, EventViewer::onClear),
	FXMAPFUNC(SEL_COMMAND, EventViewer::ID_ABOUT, EventViewer::onAbout),
};
FXIMPLEMENT(EventViewer, FXMainWindow, EventViewerMap, ARRAYNUMBER(EventViewerMap))

EventViewer::EventViewer(FXApp* a)
	: FXMainWindow(a, "Ereignisanzeige", NULL, NULL, DECOR_ALL, 0,0, 920,560) {
	icoRoot = new FXPNGIcon(a, resico_evt_log, IMAGE_NEAREST);
	icoLog = new FXPNGIcon(a, resico_evt_log, IMAGE_NEAREST);
	for (FXIcon* i : { icoRoot, icoLog }) i->create();

	FXMenuBar* menubar = new FXMenuBar(this, LAYOUT_SIDE_TOP | LAYOUT_FILL_X);
	FXMenuPane* vorgang = new FXMenuPane(this);
	new FXMenuTitle(menubar, "&Vorgang", NULL, vorgang);
	new FXMenuCommand(vorgang, "Alle Ereignisse &löschen", NULL, this, ID_CLEAR);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(vorgang);
	new FXMenuCommand(vorgang, "&Eigenschaften", NULL, this, ID_PROPERTIES);
	FXMenuPane* ansicht = new FXMenuPane(this);
	new FXMenuTitle(menubar, "A&nsicht", NULL, ansicht);
	new FXMenuCommand(ansicht, "&Filter...", NULL, this, ID_FILTER);
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
	tb("\tEigenschaften", gif(resico_mmc_properties), ID_PROPERTIES);
	tb("\tAktualisieren", gif(resico_mmc_refresh), ID_REFRESH);
	tb("\tListe exportieren", gif(resico_mmc_export), 0);
	new FXVerticalSeparator(toolbar, SEPARATOR_GROOVE | LAYOUT_FILL_Y, 0,0,0,0, 3,2,2,2);
	tb("\tHilfe", gif(resico_mmc_help), ID_ABOUT);
	new FXToolTip(getApp());

	statusbar = new FXLabel(this, " ", NULL, LABEL_NORMAL | FRAME_SUNKEN | LAYOUT_SIDE_BOTTOM | LAYOUT_FILL_X | JUSTIFY_LEFT, 0,0,0,0, 4,4,2,2);

	FXSplitter* splitter = new FXSplitter(this, LAYOUT_FILL_X | LAYOUT_FILL_Y | SPLITTER_TRACKING);
	FXPacker* treeframe = new FXPacker(splitter, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_Y, 0,0,260,0, 0,0,0,0);
	tree = new FXTreeList(treeframe, this, ID_TREE,
	                      LAYOUT_FILL_X | LAYOUT_FILL_Y | TREELIST_SHOWS_BOXES | TREELIST_SHOWS_LINES | TREELIST_BROWSESELECT | TREELIST_ROOT_BOXES);
	panel = new EvtPanel(splitter);

	char host[256] = { 0 };
	gethostname(host, sizeof(host) - 1);
	rootItem = tree->appendItem(0, FXString("Ereignisanzeige (Lokal: ") + host + ")", icoRoot, icoRoot);
	logItems[evt::LOG_APPLICATION] = tree->appendItem(rootItem, "Anwendung", icoLog, icoLog);
	logItems[evt::LOG_SECURITY] = tree->appendItem(rootItem, "Sicherheit", icoLog, icoLog);
	logItems[evt::LOG_SYSTEM] = tree->appendItem(rootItem, "System", icoLog, icoLog);
	tree->expandTree(rootItem);
	tree->setCurrentItem(logItems[evt::LOG_APPLICATION]);
	tree->selectItem(logItems[evt::LOG_APPLICATION]);
}

void EventViewer::create() {
	FXMainWindow::create();
	reload();
	show(PLACEMENT_SCREEN);
}

void EventViewer::reload() {
	panel->reload();
	statusbar->setText(panel->statusText());
}

long EventViewer::onTree(FXObject*, FXSelector, void*) {
	FXTreeItem* cur = tree->getCurrentItem();
	for (int i = 0; i < evt::LOG_COUNT; i++)
		if (cur == logItems[i]) {
			panel->showLog((evt::LogKind)i);
			statusbar->setText(panel->statusText());
			return 1;
		}
	return 1;
}

long EventViewer::onProperties(FXObject*, FXSelector, void*) { panel->openProperties(); return 1; }

long EventViewer::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }

long EventViewer::onFilter(FXObject*, FXSelector, void*) {
	panel->editFilter(this);
	statusbar->setText(panel->statusText());
	return 1;
}

long EventViewer::onClear(FXObject*, FXSelector, void*) {
	panel->clearLog(this);
	statusbar->setText(panel->statusText());
	return 1;
}

long EventViewer::onAbout(FXObject*, FXSelector, void*) {
	ice2kui::information(this, MBOX_OK, "Info",
		"Ereignisanzeige (ice2k)\n\n"
		"Zeigt die Ereignisse dieses Servers aus dem systemd-Journal;\n"
		"ohne Journal aus den Logdateien unter /var/log.\n\n"
		"Die Zuordnung zu Anwendung, Sicherheit und System folgt den\n"
		"Syslog-Facilities.");
	return 1;
}

int main(int argc, char* argv[]) {
	FXApp application("EventVwr", "Ice2KProj");
	app = &application;
	application.init(argc, argv);
	new EventViewer(&application);
	application.create();
	return application.run();
}
