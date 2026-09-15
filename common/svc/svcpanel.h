// svcpanel.h
//
// Die komplette Dienste-Ansicht als einhaengbares FOX-Widget: Liste im
// MMC-Look, Kontextmenue und der vierteilige Eigenschaften-Dialog.
// Beide Programme -- das eigenstaendige "Dienste" und der Zweig
// "Dienste und Anwendungen" der Computerverwaltung -- benutzen genau
// diese Klasse, es gibt also keine zweite Umsetzung.
//
// Bewusst ohne Bezug auf res/foxres.h: die Icons kommen vom Aufrufer,
// damit das Widget nicht an die Ressourcen eines bestimmten Programms
// gebunden ist.

#ifndef SVCPANEL_H
#define SVCPANEL_H

#include <fx.h>
#include <vector>
#include "svccore.h"

class SvcPanel : public FXVerticalFrame {
	FXDECLARE(SvcPanel)
private:
	FXIconList* list;
	FXIcon* icoService;
	std::vector<svc::ServiceInfo> services;
protected:
	SvcPanel() : list(NULL), icoService(NULL) {}
public:
	enum {
		ID_LIST = FXVerticalFrame::ID_LAST,
		ID_START, ID_STOP, ID_RESTART, ID_PROPERTIES, ID_REFRESH,
		ID_LAST
	};

	SvcPanel(FXComposite* parent, FXIcon* serviceIcon);

	// Liste neu einlesen; behaelt die Markierung nach Moeglichkeit bei.
	void reload();

	// Vom Host (Toolbar/Menue) aufrufbar.
	void startSelected();
	void stopSelected();
	void restartSelected();
	void propertiesForSelected();
	bool hasSelection() const;

	long onListDoubleClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onStart(FXObject*, FXSelector, void*);
	long onStop(FXObject*, FXSelector, void*);
	long onRestart(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);

	virtual ~SvcPanel() {}
};

#endif
