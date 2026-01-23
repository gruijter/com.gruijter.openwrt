Aanwezigheidsdetectie, Netwerkbeheer, Energiemonitoring

- Aanwezigheidsdetectie op basis van smartphone WiFi- of ethernetverbinding
- Monitor en beheer uw wifi-netwerk(en) en de verbonden apparaten
- Blokkeer de WiFi van uw kinderen na het avondeten
- Monitor het energieverbruik van uw netwerkapparaten, bijv. de TV

Inzien en loggen:
- status van internetverbinding
- de upload- en downloadsnelheid van internet
- verbindingsstatus van aangesloten apparaten
- WiFi-kwaliteit en bandbreedte per apparaat
- Energieverbruik per apparaat

Reageer op:
- apparaat dat online komt of offline gaat (aanwezigheid)
- verandering in bandbreedte of wifi-link van apparaat
- detectie van een onbekend apparaat dat verbinding maakt met het netwerk
- alarm wanneer de internetverbinding wegvalt
- verandering van internet upload-/downloadsnelheid

Doe:
- stuur WakeOnLan (WOL) naar een MAC-adres
- blokkeer en sta een aangesloten apparaat toe op basis van MAC-adres
- schakel Gast-Wifi in en uit
- herstart de router


Routerapparaat instellen in Homey:
De app is bedoeld voor OpenWRT-routers die in Router-modus werken. U kunt OpenWRT-routers toevoegen die zijn geconfigureerd in Access Point (AP)-modus voor betere/snellere detectie van wifi-apparaten in uw huis. Uw Homey moet verbonden zijn binnen het LAN-gedeelte van de router, niet van buitenaf (WAN). Bij het opstarten van de app zal Homey proberen automatisch verkeersstatistieken (upload-/downloadsnelheid) in te schakelen door het nlbwmon-pakket te installeren.

Aanwezigheidsdetectie:
Na het toevoegen van uw router aan Homey, kunt u beginnen met het toevoegen van de mobiele of vaste apparaten die u wilt volgen voor aanwezigheid.

Energiemonitoring:
Na het toevoegen van uw router aan Homey, kunt u extra apparaten toevoegen die u wilt monitoren op stroomverbruik, bijv. uw TV of printer. Voer in de geavanceerde apparaatinstellingen het geschatte / gemiddelde stroomverbruik van het apparaat in wanneer het UIT of AAN staat. Wanneer u nu uw TV aanzet, ziet u dat het geschatte vermogen wordt opgenomen in het Homey Energie-tabblad.

Ondersteunde routers:
Deze app is ontwikkeld en getest op een Netgear R7800 router die draait op OpenWRT 24.10. Het zou compatibel moeten zijn met alle OpenWRT-routers die firmware 24.10 of hoger draaien.