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

## Bauen

```sh
cd rras && make && ./rras
```
