Anwesenheitserkennung, Netzwerksteuerung, Energieüberwachung

- Anwesenheitserkennung basierend auf Smartphone-WLAN- oder Ethernet-Verbindung
- Überwachen und steuern* Sie Ihr(e) WLAN-Netzwerk(e) und die verbundenen Geräte
- Blockieren Sie das WLAN Ihrer Kinder nach dem Abendessen
- Überwachen Sie den Energieverbrauch Ihrer Netzwerkgeräte, z. B. des Fernsehers

Ansehen und protokollieren:
- Status der Internetverbindung
- Internet-Upload- und Download-Geschwindigkeit
- Verbindungsstatus angeschlossener Geräte
- WLAN-Qualität und Bandbreite pro Gerät
- Energieverbrauch pro Gerät

Reagieren auf:
- Gerät geht online oder offline (Anwesenheit)
- Änderung der Gerätebandbreite oder WLAN-Verbindung
- Erkennung eines unbekannten Geräts, das sich mit dem Netzwerk verbindet
- Alarm, wenn die Internetverbindung ausfällt
- Änderung der Internet-Upload-/Download-Geschwindigkeit

Ausführen:
- WakeOnLan (WOL) an eine MAC-Adresse senden*
- Ein angeschlossenes Gerät per MAC-Adresse blockieren und zulassen*
- Gast-WLAN aktivieren und deaktivieren*
- Router neu starten*

* In Arbeit

Einrichtung des Router-Geräts in Homey:
Die App ist für OpenWRT-Router gedacht, die im Router-Modus arbeiten. Sie können OpenWRT-Router hinzufügen, die im Access Point (AP)-Modus konfiguriert sind, um WLAN-Geräte im ganzen Haus besser/schneller zu erkennen. Ihr Homey sollte im LAN-Teil des Routers verbunden sein, nicht von außen (WAN). Beim Start der App versucht Homey automatisch, Verkehrsstatistiken (Upload-/Download-Geschwindigkeit) zu aktivieren, indem das Paket nlbwmon installiert wird.

Anwesenheitserkennung:
Nachdem Sie Ihren Router zu Homey hinzugefügt haben, können Sie mobile oder feste Geräte hinzufügen, deren Anwesenheit Sie verfolgen möchten.

Energieüberwachung:
Nachdem Sie Ihren Router zu Homey hinzugefügt haben, können Sie zusätzliche Geräte hinzufügen, deren Stromverbrauch Sie überwachen möchten, z. B. Ihren Fernseher oder Drucker. Geben Sie in den erweiterten Geräteeinstellungen den geschätzten / durchschnittlichen Stromverbrauch des Geräts ein, wenn es AUS oder EIN ist. Wenn Sie nun Ihren Fernseher einschalten, sehen Sie, dass der geschätzte Stromverbrauch im Homey-Energie-Tab enthalten ist.

Unterstützte Router:
Diese App wurde auf einem Netgear R7800 Router mit OpenWRT 24.10 entwickelt und getestet. Sie sollte mit allen OpenWRT-Routern kompatibel sein, auf denen Firmware 24.10 oder höher läuft.