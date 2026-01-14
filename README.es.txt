Detección de presencia, control de red, monitorización de energía

- Detección de presencia basada en conexión WiFi o ethernet de smartphone
- Supervise y controle* su(s) red(es) wifi y sus dispositivos conectados
- Bloquee el WiFi de sus hijos después de la cena
- Supervise el uso de energía de sus dispositivos de red, p. ej., la TV.

Ver y registrar:
- estado de la conexión a internet
- velocidad de subida y bajada de internet
- estado de conexión de los dispositivos conectados
- calidad WiFi y ancho de banda por dispositivo
- uso de energía por dispositivo

Actuar sobre:
- dispositivo que se conecta o desconecta (presencia)
- cambio de ancho de banda o enlace wifi del dispositivo
- detección de un dispositivo desconocido conectándose a la red
- alarma cuando se cae la conexión a internet
- cambio de velocidad de subida/bajada de internet

Hacer:
- enviar WakeOnLan* (WOL) a una dirección MAC
- bloquear y permitir un dispositivo conectado por dirección MAC
- habilitar y deshabilitar WiFi de invitados*
- reiniciar el router*

* Trabajo en progreso

Configuración del dispositivo router en Homey:
La aplicación está destinada a routers OpenWRT que funcionan en modo Router. Puede agregar routers OpenWRT configurados en modo Punto de Acceso (AP) para una mejor/más rápida detección de dispositivos wifi en toda su casa. Su Homey debe estar conectado dentro de la parte LAN del router, no desde fuera (WAN). Al iniciar la aplicación, Homey intentará habilitar automáticamente las estadísticas de tráfico (velocidad de subida/bajada) instalando el paquete nlbwmon.

Detección de presencia:
Después de agregar su router a Homey, puede comenzar a agregar los dispositivos móviles o fijos que desea rastrear para presencia.

Monitorización de energía:
Después de agregar su router a Homey, puede agregar dispositivos adicionales que desea monitorear por energía, p. ej., su TV o impresora. En la configuración avanzada del dispositivo, ingrese el uso de energía estimado / promedio del dispositivo cuando está APAGADO o ENCENDIDO. Ahora, cuando encienda su TV, verá que la potencia estimada se incluye en la pestaña Energía de Homey.

Routers soportados:
Esta aplicación ha sido desarrollada y probada en un router Netgear R7800 ejecutando OpenWRT 24.10. Debería ser compatible con todos los routers OpenWRT que ejecuten firmware 24.10 o superior.