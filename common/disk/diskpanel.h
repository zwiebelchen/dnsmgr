// diskpanel.h -- Datenträgerverwaltung als FOX-Widget.
//
// Aufbau wie im Original: oben die Volumeliste, unten die grafische
// Ansicht mit einem Block je Datenträger und farbigen Balken je
// Abschnitt, darunter die Legende. Wird vom eigenständigen Programm
// diskmgmt und von compmgmt (Zweig "Datenspeicher") verwendet.
#pragma once

#include <fx.h>
#include "diskcore.h"

class DiskMapView;

class DiskPanel : public FXVerticalFrame {
	FXDECLARE(DiskPanel)
private:
	FXIconList* volumes;
	DiskMapView* map;
	FXScrollWindow* mapScroll;
	FXHorizontalFrame* legend = nullptr;
	disk::Snapshot snap;
	void rebuildLegend();
protected:
	DiskPanel() : volumes(NULL), map(NULL), mapScroll(NULL) {}
public:
	enum { ID_VOLUMES = FXVerticalFrame::ID_LAST, ID_MAP, ID_MAP_MENU,
	       ID_SIGNATURE, ID_CREATE, ID_DELETE, ID_DELETE_EXT, ID_FORMAT, ID_MOUNTPOINT, ID_ACTIVE, ID_RESCAN, ID_LAST };
	DiskPanel(FXComposite* p, FXuint opts = LAYOUT_FILL_X | LAYOUT_FILL_Y);
	long onVolumeSelected(FXObject*, FXSelector, void*);
	long onMapSelected(FXObject*, FXSelector, void*);
	long onMapRightClick(FXObject*, FXSelector, void*);
	long onAction(FXObject*, FXSelector, void*);

	void reload();                        // neu einlesen (braucht root für parted/blkid)
	FXString statusText() const;
	const disk::Snapshot& snapshot() const { return snap; }
	virtual ~DiskPanel() {}
};
