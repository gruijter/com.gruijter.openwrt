Tilstedeværelsesdeteksjon, nettverksstyring, energiovervåkning

- Tilstedeværelsesdeteksjon basert på smarttelefon WiFi eller ethernet-tilkobling
- Overvåk og kontroller* ditt/dine wifi-nettverk og dets tilkoblede enheter
- Blokker barnas WiFi etter middag
- Overvåk energiforbruket til nettverksenhetene dine, f.eks. TV-en.

Se og logg:
- internett-tilkoblingsstatus
- internett opplastings- og nedlastingshastighet
- tilkoblingsstatus for tilkoblede enheter
- WiFi-kvalitet og båndbredde per enhet
- Energibruk per enhet

Ager på:
- enhet kommer på nett eller går av nett (tilstedeværelse)
- endring i enhetens båndbredde eller wifi-link
- deteksjon av en ukjent enhet som kobler seg til nettverket
- alarm når internettforbindelsen går ned
- endring av internett opp/nedlastingshastighet

Gjør:
- send WakeOnLan* (WOL) til en MAC-adresse
- blokker og tillat en tilkoblet enhet via MAC-adresse
- aktiver og deaktiver Gjestenettverk*
- start ruteren på nytt*

* Arbeid pågår

Oppsett av ruterenhet i Homey:
Appen er beregnet for OpenWRT-rutere som fungerer i rutermodus. Du kan legge til OpenWRT-rutere som er konfigurert i tilgangspunktmodus (AP) for bedre/raskere deteksjon av wifi-enheter i hele huset. Din Homey bør være koblet til på LAN-siden av ruteren, ikke fra utsiden (WAN). Ved oppstart av appen vil Homey prøve å automatisk aktivere trafikkstatistikk (opp/nedlastingshastighet) ved å installere nlbwmon-pakken.

Tilstedeværelsesdeteksjon:
Etter at du har lagt til ruteren din i Homey, kan du begynne å legge til de mobile eller faste enhetene du vil spore for tilstedeværelse.

Energiovervåkning:
Etter at du har lagt til ruteren din i Homey, kan du legge til flere enheter som du vil overvåke for strøm, f.eks. TV-en eller skriveren din. I avanserte enhetsinnstillinger angir du estimert / gjennomsnittlig strømforbruk for enheten når den er AV eller PÅ. Når du nå slår på TV-en, vil du se at den estimerte effekten er inkludert i Homey Energi-fanen.

Støttede rutere:
Denne appen er utviklet og testet på en Netgear R7800 ruter som kjører OpenWRT 24.10. Den bør være kompatibel med alle OpenWRT-rutere som kjører fastvare 24.10 eller høyere.