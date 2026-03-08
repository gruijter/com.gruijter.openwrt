Tilstedeværelsesdetektion, netværksstyring, energiovervågning

- Tilstedeværelsesdetektion baseret på smartphone WiFi eller ethernet-forbindelse
- Overvåg og styr dit/dine wifi-netværk og dets tilsluttede enheder
- Bloker børnenes WiFi efter aftensmaden
- Overvåg energiforbruget for dine netværksenheder, f.eks. TV'et.

Se og log:
- internetforbindelsesstatus, upload-/downloadhastighed og pakkefejl
- CPU- og hukommelsesudnyttelse af routeren
- forbindelsesstatus for tilsluttede enheder
- WiFi-kvalitet (Signal, SNR, MCS, Kanalbredde), båndbredde og dominerende protokol pr. enhed
- Energiforbrug pr. enhed

Reager på:
- enhed kommer online eller går offline (tilstedeværelse)
- ændring i enhedens båndbredde eller wifi-link
- detektion af en ukendt enhed, der opretter forbindelse til netværket
- alarm når internetforbindelsen ryger
- ændring af internet upload/download hastighed

Gør:
- send WakeOnLan (WOL) til en MAC-adresse
- bloker og tillad en tilsluttet enhed via MAC-adresse
- aktiver og deaktiver Gæste-WiFi
- genstart routeren

Opsætning af routerenhed i Homey:
Appen er beregnet til OpenWRT-routere, der fungerer i Router-tilstand. Du kan tilføje OpenWRT-routere, der er konfigureret i Access Point (AP)-tilstand for bedre/hurtigere detektion af wifi-enheder i hele huset. Din Homey skal være tilsluttet inden for LAN-delen af routeren, ikke udefra (WAN). Ved opstart af appen vil Homey forsøge automatisk at aktivere trafikstatistik (upload/download hastighed) ved at installere nlbwmon-pakken.

Tilstedeværelsesdetektion:
Efter at have tilføjet din router til Homey, kan du begynde at tilføje de mobile eller faste enheder, du vil spore for tilstedeværelse.

Energiovervågning:
Efter at have tilføjet din router til Homey, kan du tilføje yderligere enheder, som du vil overvåge for strøm, f.eks. dit TV eller printer. I avancerede enhedsindstillinger indtastes det estimerede / gennemsnitlige strømforbrug for enheden, når den er SLUKKET eller TÆNDT. Når du nu tænder dit TV, vil du se, at det estimerede strømforbrug er inkluderet i Homey Energi-fanen.

Understøttede routere:
Denne app er udviklet og testet på Netgear R7800-routere, der kører nyere OpenWRT-versioner (22.03 og nyere). Den bør være kompatibel med de fleste routere, der kører OpenWRT-firmware 21.02 eller højere.