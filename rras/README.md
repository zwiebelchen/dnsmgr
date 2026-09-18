# rras -- Routing und RAS

Nachbau des Snap-Ins "Routing und RAS" von Windows 2000 Server.

## Aufbau

Wie im Original: links der Baum mit "Routing und RAS", darunter
"Serverstatus" und der lokale Server, rechts der Startbildschirm bzw.
die Serverstatusliste mit den Spalten Servername, Servertyp, Status,
Verwendete Ports, Ports gesamt und Betriebszeit. Das Kontextmenü des
Servers bietet "Routing und RAS konfigurieren und aktivieren",
"Routing und RAS deaktivieren" (jeweils nur das gerade Sinnvolle),
Aktualisieren und Eigenschaften.

## Was umgesetzt ist

- **Konfigurieren und aktivieren**: Der Dialog bietet dieselben
  Serverrollen wie der Assistent des Originals. Umgesetzt sind
  "Netzwerkrouter" und "Manuell konfigurierter Server" -- beide schalten
  die IP-Weiterleitung des Kernels ein, sofort per
  `sysctl -w net.ipv4.ip_forward=1` und dauerhaft über
  `/etc/sysctl.d/99-ice2k-rras.conf`.
- **Deaktivieren** schaltet sie wieder ab.
- **Eigenschaften**, Reiter "Allgemein": Router an/aus sowie "Nur
  lokales Netzwerk (LAN-Routing)" bzw. "LAN- und Einwählrouting".
- **Serverstatus**: Servername, Betriebssystem als Servertyp und der
  Status ("Gestartet" bzw. "Beendet (nicht konfiguriert)").

Die gewählte Rolle merkt sich `/etc/ice2k/rras.conf`.

## Was noch fehlt

- Einwähl- und VPN-Server: Ports, Schnittstellen, Anschlüsse,
  RAS-Richtlinien und Protokollierung. Der Dialog sagt das ausdrücklich,
  statt etwas vorzutäuschen.
- Adressumsetzung (Internetverbindungsserver) und Firewallregeln.
- Routingprotokolle (RIP, OSPF) und statische Routen -- unter Linux wäre
  FRR der naheliegende Unterbau.
- "LAN- und Einwählrouting" unterscheidet sich derzeit nur im
  gespeicherten Zustand, solange es keine Einwahl gibt.

## Abgleich mit dem Original

Texte und Symbole stammen aus der deutschen `mprsnap.dll` (Windows 2000
SP4, 5.00.2195.6609; die DLL selbst liegt nicht im Repository):

- Startbildschirme "Willkommen" (291) und "Den Routing- und RAS-Server
  konfigurieren" (300-302)
- Zustandstexte "Gestartet" (105), "Beendet" (102) und
  "%s (nicht konfiguriert)" (97), Spalten der Serverstatusliste (45-49,
  91), Menüeintrag "Routing und RAS deaktivieren" (59)
- Setup-Assistent mit den fünf Serverrollen und ihren Beschreibungen
  (Dialog 12611)
- Eigenschaften, Reiter "Allgemein" (Dialog 12517): "Diesen Computer
  aktivieren als:", "Router", "Nur LAN-Routing", "LAN und bei Bedarf
  wählendes Routing", "RAS-Server"
- Symbole unter `res/rras`: Wurzel, Serverstatus sowie der Server in den
  Zuständen gestartet/beendet -- der Knoten wechselt sein Symbol wie im
  Original

`iprtrmgr.dll` (IP-Routerverwaltung) enthält nur vier Texte und keine
Dialoge; daraus war nichts zu übernehmen.

## Bauen

```sh
cd rras && make && ./rras
```
