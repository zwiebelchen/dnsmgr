// msgbox.h -- Meldungsfenster mit deutscher Beschriftung.
//
// FXMessageBox beschriftet seine Knöpfe fest mit "Yes", "No", "OK" und
// "Cancel". Diese Ersatzfunktionen haben denselben Aufruf wie
// FXMessageBox::question/warning/error/information und liefern dieselben
// Rückgabewerte (MBOX_CLICKED_YES usw.), zeigen aber "Ja", "Nein" und
// "Abbrechen".
//
// Header-only, damit jedes Programm sie ohne Änderung am Makefile
// einbinden kann.
#pragma once

#include <fx.h>
#include <FXPNGIcon.h>
#include "msgicons.h"
#include <cstdarg>
#include <cstdio>

namespace ice2kui {

// Baut das Fenster: Symbol links, Text rechts, darunter die Knöpfe.
inline FXuint showBox(FXWindow* owner, FXuint opts, const FXString& title, const FXString& text, FXIcon* icon) {
	FXDialogBox dlg(owner, title, DECOR_TITLE | DECOR_BORDER, 0,0,0,0, 12,12,12,12, 0,0);
	FXVerticalFrame* main = new FXVerticalFrame(&dlg, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,10);
	FXHorizontalFrame* body = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 16,0);
	if (icon) new FXLabel(body, "", icon, LAYOUT_CENTER_Y);
	new FXLabel(body, text, NULL, JUSTIFY_LEFT | LAYOUT_CENTER_Y);
	new FXHorizontalSeparator(main, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	FXHorizontalFrame* btns = new FXHorizontalFrame(main, LAYOUT_CENTER_X | PACK_UNIFORM_WIDTH, 0,0,0,0, 0,0,0,0, 8,0);
	const FXuint style = BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK;
	// "Ja" bzw. "OK" bestätigen den Dialog, "Nein"/"Abbrechen" brechen ihn ab.
	if (opts == MBOX_YES_NO || opts == MBOX_YES_NO_CANCEL) {
		new FXButton(btns, "&Ja", NULL, &dlg, FXDialogBox::ID_ACCEPT, style | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,0,0, 16,16,3,3);
		new FXButton(btns, "&Nein", NULL, &dlg, FXDialogBox::ID_CANCEL, style, 0,0,0,0, 16,16,3,3);
		return dlg.execute(PLACEMENT_OWNER) ? MBOX_CLICKED_YES : MBOX_CLICKED_NO;
	}
	if (opts == MBOX_OK_CANCEL) {
		new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, style | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,0,0, 16,16,3,3);
		new FXButton(btns, "Abbrechen", NULL, &dlg, FXDialogBox::ID_CANCEL, style, 0,0,0,0, 16,16,3,3);
		return dlg.execute(PLACEMENT_OWNER) ? MBOX_CLICKED_OK : MBOX_CLICKED_CANCEL;
	}
	new FXButton(btns, "OK", NULL, &dlg, FXDialogBox::ID_ACCEPT, style | BUTTON_DEFAULT | BUTTON_INITIAL, 0,0,0,0, 16,16,3,3);
	dlg.execute(PLACEMENT_OWNER);
	return MBOX_CLICKED_OK;
}

inline FXString formatText(const char* fmt, va_list args) {
	char buf[4096];
	vsnprintf(buf, sizeof(buf), fmt, args);
	return buf;
}

// Symbole: FXMessageBox hält seine eigenen unter Verschluss, deshalb
// liegen hier eigene (msgicons.cpp, von reswrap erzeugt).
inline FXIcon* boxIcon(FXApp* app, int kind) {
	static FXIcon* icons[4] = { NULL, NULL, NULL, NULL };
	if (!icons[kind]) {
		const unsigned char* data[4] = { msg_question, msg_warning, msg_error, msg_info };
		icons[kind] = new FXPNGIcon(app, data[kind], 0, IMAGE_NEAREST);
		icons[kind]->create();
	}
	return icons[kind];
}

inline FXuint question(FXWindow* owner, FXuint opts, const char* title, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	FXString text = formatText(fmt, args);
	va_end(args);
	return showBox(owner, opts, title, text, boxIcon(owner->getApp(), 0));
}

inline FXuint warning(FXWindow* owner, FXuint opts, const char* title, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	FXString text = formatText(fmt, args);
	va_end(args);
	return showBox(owner, opts, title, text, boxIcon(owner->getApp(), 1));
}

inline FXuint error(FXWindow* owner, FXuint opts, const char* title, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	FXString text = formatText(fmt, args);
	va_end(args);
	return showBox(owner, opts, title, text, boxIcon(owner->getApp(), 2));
}

inline FXuint information(FXWindow* owner, FXuint opts, const char* title, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	FXString text = formatText(fmt, args);
	va_end(args);
	return showBox(owner, opts, title, text, boxIcon(owner->getApp(), 3));
}

} // namespace ice2kui
