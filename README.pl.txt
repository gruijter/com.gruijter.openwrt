Wykrywanie obecności, sterowanie siecią, monitorowanie energii

- Wykrywanie obecności na podstawie połączenia WiFi smartfona lub ethernet
- Monitoruj i steruj* swoją siecią (sieciami) wifi i podłączonymi urządzeniami
- Zablokuj WiFi dzieciom po kolacji
- Monitoruj zużycie energii przez urządzenia sieciowe, np. telewizor.

Zobacz i rejestruj:
- status połączenia internetowego
- prędkość wysyłania i pobierania danych z internetu
- status połączenia podłączonych urządzeń
- jakość WiFi i przepustowość na urządzenie
- zużycie energii na urządzenie

Reaguj na:
- pojawienie się urządzenia online lub przejście w tryb offline (obecność)
- zmianę przepustowości urządzenia lub łącza wifi
- wykrycie nieznanego urządzenia łączącego się z siecią
- alarm, gdy połączenie internetowe zostanie przerwane
- zmianę prędkości wysyłania/pobierania danych z internetu

Wykonaj:
- wyślij WakeOnLan* (WOL) na adres MAC
- zablokuj i zezwól na podłączone urządzenie według adresu MAC
- włącz i wyłącz WiFi dla gości*
- zrestartuj router*

* Prace w toku

Konfiguracja urządzenia routera w Homey:
Aplikacja jest przeznaczona dla routerów OpenWRT działających w trybie Routera. Możesz dodać routery OpenWRT skonfigurowane w trybie Punktu Dostępu (AP) dla lepszego/szybszego wykrywania urządzeń wifi w całym domu. Twój Homey powinien być podłączony wewnątrz części LAN routera, a nie z zewnątrz (WAN). Przy uruchomieniu aplikacji Homey spróbuje automatycznie włączyć statystyki ruchu (prędkość wysyłania/pobierania) instalując pakiet nlbwmon.

Wykrywanie obecności:
Po dodaniu routera do Homey możesz zacząć dodawać urządzenia mobilne lub stacjonarne, które chcesz śledzić pod kątem obecności.

Monitorowanie energii:
Po dodaniu routera do Homey możesz dodać dodatkowe urządzenia, które chcesz monitorować pod kątem zużycia energii, np. telewizor lub drukarkę. W zaawansowanych ustawieniach urządzenia wprowadź szacowane / średnie zużycie energii przez urządzenie, gdy jest WYŁĄCZONE lub WŁĄCZONE. Teraz, gdy włączysz telewizor, zobaczysz, że szacowana moc jest uwzględniona w zakładce Energia Homey.

Obsługiwane routery:
Ta aplikacja została opracowana i przetestowana na routerze Netgear R7800 z systemem OpenWRT 24.10. Powinna być kompatybilna ze wszystkimi routerami OpenWRT z oprogramowaniem układowym 24.10 lub nowszym.