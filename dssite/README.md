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
  Standortverknüpfungsbrücken anlegen, Verbindungen unter "NTDS
  Settings" (Replikationstopologie), Server zwischen Standorten
  verschieben, Zeitplan der Replikation, "Jetzt replizieren".
- Die Symbole sind noch die allgemeinen aus dem Projektbestand.

## Bauen

```sh
cd dssite && make && ./dssite
```
