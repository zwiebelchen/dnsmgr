# dssite -- Active Directory-Standorte und -Dienste

Nachbau des Snap-Ins "Active Directory-Standorte und -Dienste" aus
Windows 2000 Server.

## Aufbau

Links der Baum: die Standorte mit ihrem Ordner "Servers" und den darin
liegenden Domänencontrollern, dazu "Subnets" und "Inter-Site Transports"
mit IP und SMTP. Rechts die passende Liste, Änderungen über Kontextmenü
und Menü "Vorgang".

## Unterbau

Gelesen wird der Konfigurationsteil des Verzeichnisses unter
`CN=Sites,CN=Configuration,<Basis>` über den ldapi-Socket:

| Anzeige | Objekt |
|---|---|
| Standort | `objectClass=site` |
| Server im Standort | `objectClass=server` unter `CN=Servers` |
| Subnetz | `objectClass=subnet` unter `CN=Subnets`, Standort über `siteObject` |
| Standortverknüpfung | `objectClass=siteLink` unter `CN=IP` bzw. `CN=SMTP`, mit `siteList`, `cost` und `replInterval` |
| Verbindung (Replikationstopologie) | `objectClass=nTDSConnection` unter `CN=NTDS Settings` des Servers, Quelle über `fromServer` |

Unter jedem Server liegt "NTDS Settings" mit den Verbindungen: Name,
Von Server, Von Standort und Typ ("Automatisch erzeugt", wenn das
unterste Bit von `options` gesetzt ist, sonst "Manuell"). Das
Kontextmenü legt Verbindungen an, löscht sie, repliziert sofort
(`samba-tool drs replicate`) und lässt die Topologie neu berechnen
(`samba-tool drs kcc`). Beide DRS-Aufrufe laufen mit einer Zeitgrenze
von 60 Sekunden -- antwortet die Schnittstelle nicht, sagt das eine
Meldung, statt das Fenster hängen zu lassen.

Geändert wird über `samba-tool sites` (Standort anlegen und löschen,
Subnetz anlegen, löschen und einem Standort zuweisen). Für
Standortverknüpfungen hat `samba-tool` keinen Befehl -- Kosten,
Replikationsintervall und die beteiligten Standorte schreibt `ldbmodify`
direkt in `sam.ldb`.

## Abweichungen vom Original

- Die Container heißen wie im Verzeichnis (`Servers`, `Subnets`,
  `Inter-Site Transports`); sobald die Ressourcen des Originals
  (`dssite.dll`) vorliegen, werden Beschriftungen und Symbole
  angeglichen.
- Noch nicht umgesetzt: neue Standortverknüpfungen und
  Standortverknüpfungsbrücken anlegen, Server zwischen Standorten
  verschieben, Zeitpläne (weder für Verknüpfungen noch für
  Verbindungen), Eigenschaften einer Verbindung.
- Die Symbole sind noch die allgemeinen aus dem Projektbestand.

## Bauen

```sh
cd dssite && make && ./dssite
```
