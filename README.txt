Presence Detection, Network control, Energy Monitoring

- Presence detection based on smartphone WiFi or ethernet connection
- Monitor and control your wifi network(s) and its connected devices
- Block the WiFi of your kids after dinner
- Monitor the energy usage of your network devices, e.g. the T.V.

See and log:
- internet connection status
- the internet upload and download speed
- connection status of attached devices
- WiFi quality and bandwidth per device
- Energy use per device

Act on:
- device coming online or going offline (presence)
- device bandwidth or wifi link change
- detection of an unknown device connecting to the network
- alarm when internet connection goes down
- change of internet up/download speed

Do:
- send WakeOnLan (WOL) to a MAC address
- block and allow an attached device by MAC address
- enable and disable Guest Wifi
- reboot the router


Router device setup in Homey:
The app is intended for OpenWRT routers that work in Router mode. You can add OpenWRT routers that are configured in Access Point (AP) mode for better/faster detection of wifi devices throughout your house.Your Homey should be connected inside the LAN part of the router, not from outside (WAN). On app startup, Homey will try to automatically enable traffic statistics (up/download speed) by installing the nlbwmon package.

Presence detection:
After adding your router to Homey, you can start adding the mobile or fixed devices that you want to track for presence.

Energy monitoring:
After adding your router to Homey, you can add additional devices that you want to monitor for power, e.g. your T.V. or printer. In advanced device settings enter the estimated / average power usage of the device when it is OFF or ON. Now when you turn on your T.V. you will see that the estimated power is included in Homey Energy tab.

Supported routers:
This app has been developed and tested on a Netgear R7800 router running OpenWRT 24.10. It should be compatible with all OpenWRT routers running firmware 24.10 or higher.
