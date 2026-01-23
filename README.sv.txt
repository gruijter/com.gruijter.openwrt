Närvarodetektering, nätverkskontroll, energimonitorering

- Närvarodetektering baserad på smartphone WiFi eller ethernet-anslutning
- Övervaka och kontrollera* ditt/dina wifi-nätverk och dess anslutna enheter
- Blockera barnens WiFi efter middagen
- Övervaka energianvändningen för dina nätverksenheter, t.ex. TV:n.

Se och logga:
- internetanslutningsstatus
- internet uppladdnings- och nedladdningshastighet
- anslutningsstatus för anslutna enheter
- WiFi-kvalitet och bandbredd per enhet
- Energianvändning per enhet

Agera på:
- enhet kommer online eller går offline (närvaro)
- ändring av enhetens bandbredd eller wifi-länk
- detektering av en okänd enhet som ansluter till nätverket
- larm när internetanslutningen går ner
- ändring av internet upp/nedladdningshastighet

Gör:
- skicka WakeOnLan* (WOL) till en MAC-adress
- blockera och tillåt en ansluten enhet via MAC-adress
- aktivera och inaktivera Gäst-WiFi*
- starta om routern*

* Arbete pågår

Routerenhetsinställning i Homey:
Appen är avsedd för OpenWRT-routrar som fungerar i Router-läge. Du kan lägga till OpenWRT-routrar som är konfigurerade i Access Point (AP)-läge för bättre/snabbare detektering av wifi-enheter i hela huset. Din Homey bör vara ansluten inom LAN-delen av routern, inte från utsidan (WAN). Vid appstart kommer Homey att försöka aktivera trafikstatistik (upp/nedladdningshastighet) automatiskt genom att installera nlbwmon-paketet.

Närvarodetektering:
Efter att ha lagt till din router i Homey kan du börja lägga till de mobila eller fasta enheter som du vill spåra för närvaro.

Energimonitorering:
Efter att ha lagt till din router i Homey kan du lägga till ytterligare enheter som du vill övervaka för ström, t.ex. din TV eller skrivare. I avancerade enhetsinställningar anger du den uppskattade / genomsnittliga strömförbrukningen för enheten när den är AV eller PÅ. När du nu slår på din TV kommer du att se att den uppskattade effekten ingår i Homey Energi-fliken.

Stödda routrar:
Denna app har utvecklats och testats på en Netgear R7800 router som kör OpenWRT 24.10. Den bör vara kompatibel med alla OpenWRT-routrar som kör firmware 24.10 eller högre.