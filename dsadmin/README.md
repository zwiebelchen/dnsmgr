# dsadmin -- Active Directory-Benutzer und -Computer für ice2k

Ein Nachbau des echten `dsa.msc`-Snapins für
[ice2k](https://github.com/comdlg32/ice2k). Backend: **Samba-AD-
Domäne via `samba-tool`** (`user`/`group`/`ou`/`computer`/`gpo`).

![Baumstruktur: Domäne -> Builtin/Computers/Users/Domain Controllers](../docs/dsadmin/screenshots/screenshot-baumstruktur.png)

## Einordnung im Projekt

Sobald ein Server per `dcpromo` zum Domänencontroller wird, verwaltet
`compmgmt` ("Lokale Benutzer und Gruppen") keine echten Konten mehr --
genau wie im Original wandern Benutzer/Gruppen in die
Domänendatenbank. `dsadmin` übernimmt genau das: die Verwaltung von
**Domänenkonten** statt lokaler Konten.

## Funktionsumfang
- Baumstruktur: Domäne -> Builtin/Computers/Users/Domain Controllers
  + eigene Organisationseinheiten
- Container-Anzeige mit Typ-Klassifizierung (Benutzer/Sicherheits-
  gruppe/Computer/Organisationseinheit/Container) und passenden Icons
- **Neu**: Benutzer/Gruppe/Organisationseinheit anlegen
- **Löschen** für Benutzer/Gruppe/Organisationseinheit
- **Eigenschaften** mit dem **"Gruppenrichtlinie"**-Reiter (GPOs
  anlegen/verknüpfen/lösen über `samba-tool gpo`) -- der eigentliche
  Editor der Administrativen Vorlagen ist ein eigener, späterer
  Baustein (siehe unten)

## Gruppenmitgliedschaft

"Eigenschaften" auf einer Sicherheitsgruppe öffnet eine
Mitgliederliste mit Hinzufügen/Entfernen (`samba-tool group
addmembers`/`removemembers`/`listmembers`) -- für besonders
geschützte Gruppen greift bei Bedarf derselbe Administrator-
Anmeldedaten-Fallback wie bei GPOs.

## Anzeigename vs. Anmeldename

Der Anzeigename eines Objekts (CN, z.B. "Max Mustermann") und sein
Anmeldename (sAMAccountName, z.B. "mmustermann") können sich
unterscheiden. `dsadmin` führt beide getrennt (`accountName`-Feld) --
ermittelt über einen `samba-tool ... list --full-dn`-Abgleich statt
über einen reinen Namensvergleich, der bei abweichenden CNs sonst
fehlschlagen würde.

## GPOs brauchen echte Administrator-Anmeldedaten

`CN=Policies,CN=System` ist besonders geschützt: Weder root noch das
Maschinenkonto des Domänencontrollers dürfen dort schreiben --
genau wie im echten AD dürfen nur Domain Admins GPOs anlegen. Beim
ersten GPO-Schreibzugriff (Neu/Hinzufügen/Entfernen) fragt `dsadmin`
deshalb einmalig nach Administrator-Anmeldedaten und cacht sie für
die laufende Sitzung. **Lesen** (GPO-Liste, Verknüpfungen anzeigen)
funktioniert dagegen problemlos ohne das.

## Bauen
```sh
cd dsadmin
make
./dsadmin
```

## Bekannte Grenzen
- Der eigentliche Editor der Administrativen Vorlagen (ADM-Format,
  `registry.pol`-Schreiber) ist noch nicht umgesetzt -- kommt als
  eigener, späterer Baustein.
- Nur eine Ebene von Organisationseinheiten unter der Domänenwurzel
  wird im Baum abgebildet (keine rekursive Verschachtelung).
- Kein Umbenennen, kein Verschieben zwischen Containern/OUs.
- Bekannte, ungelöste Einschränkung aus dem Testen: Das Eingabefeld
  für einen neuen GPO-Namen (aus dem bereits modalen Eigenschaften-
  Dialog heraus geöffnet) nahm in der Xvfb-Testumgebung ohne
  Fenstermanager keinen Tastaturfokus an -- noch nicht auf einem
  echten System mit Fenstermanager verifiziert.
