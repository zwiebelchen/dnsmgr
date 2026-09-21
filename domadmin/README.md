# domadmin -- Active Directory-Domänen und -Vertrauensstellungen

Nachbau des gleichnamigen Snap-Ins aus Windows 2000 Server.

## Aufbau

Links "Active Directory-Domänen und -Vertrauensstellungen" mit der
Domäne darunter, rechts die Liste mit Name und Typ. Das Kontextmenü der
Wurzel bietet "Betriebsmaster..." und "Eigenschaften" (UPN-Suffixe), das
der Domäne "Verwalten" (startet dsadmin) und "Eigenschaften".

## Was umgesetzt ist

- **Eigenschaften der Domäne**, Reiter "Allgemein": Domänenname
  (Windows NT 3.5x/4.0), Beschreibung (änderbar), Betriebsmodus.
- Reiter **"Vertrauensstellungen"**: "Domänen, denen diese Domäne
  vertraut" und "Domänen, die dieser Domäne vertrauen", je mit
  Hinzufügen, Bearbeiten und Entfernen. Bearbeiten zeigt Typ, Richtung
  und Transitivität, "Überprüfen" (`samba-tool domain trust validate`)
  und "Vertrauensstellung aufheben".
- **UPN-Suffixe**: alternative Suffixe hinzufügen und entfernen
  (Attribut `uPNSuffixes` an `CN=Partitions`). Sie erscheinen in dsadmin
  in der Auswahl beim Benutzeranmeldenamen, wie im Original.
- **Betriebsmaster**: zeigt den Domänennamen-Betriebsmaster
  (`samba-tool fsmo show`) und überträgt die Funktion
  (`samba-tool fsmo transfer --role=naming`).

## Abgleich mit dem Original

Texte und Dialoge stammen aus `domadmin.dll` (Wurzel, Spalten, Befehle
"Verwalten" und "Betriebsmaster...", UPN-Suffixe samt Meldungen, Dialog
"Betriebsmaster ändern" mit seinen Meldungen) und `dsprop.dll`
(Eigenschaftenseiten "Allgemein" und "Vertrauensstellungen", Dialoge
"Vertraute/Vertrauende Domäne hinzufügen", Eigenschaften einer
Vertrauensstellung, Anmeldung an der anderen Domäne). Die Symbole liegen
unter `res/domadmin`. Beide DLLs (deutsch, Windows 2000 SP4) liegen
nicht im Repository.

## Abweichungen vom Original

- **Domänenmodus**: Samba kennt keinen gemischten Modus und setzt
  mindestens Funktionsebene 2003 voraus. Die Seite zeigt deshalb
  "Einheitlicher Modus" mit der tatsächlichen Funktionsebene;
  "Modus wechseln" ist gesperrt.
- **Vertrauensstellung hinzufügen**: Windows 2000 verlangt ein
  gemeinsames Vertrauenskennwort auf beiden Seiten. `samba-tool domain
  trust create` meldet sich stattdessen mit einem Administratorkonto der
  anderen Domäne an -- der Dialog fragt deshalb Benutzername und
  Kennwort ab (wie der Anmeldedialog des Originals, Dialog 334).
  Angelegt werden externe Vertrauensstellungen.
- Mehrere Domänen einer Gesamtstruktur werden angezeigt, soweit sie im
  Konfigurationsteil stehen; getestet ist nur die Einzeldomäne.
- "Verbindung mit Domänencontroller herstellen..." fehlt.

## Bauen

```sh
cd domadmin && make && ./domadmin
```
