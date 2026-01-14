'use strict';

const Homey = require('homey');

const capabilities = ['device_connected', 'ip_address', 'name_in_router', 'router_name', 'port', 'measure_link_speed',
  'firewall_zone', 'measure_connections', 'measure_signal_strength', 'measure_signal_strength.snr',
  'measure_download_speed', 'measure_upload_speed', 'onoff'];

module.exports = class MyDriver extends Homey.Driver {

  // {
  //   routerId: 'B0:7F:B9:F8:1D:EB',
  //   routerName: 'TT-2',
  //   ip: '10.0.10.234',
  //   mac: '90:13:DA:AA:00:76',
  //   name: 'homey-63c568c7ff65f90b973af57b',
  //   onlineSince: 1767016703515,
  //   onlineForSeconds: 0,
  //   lastSeen: 1767016703515,
  //   source: 'iwinfo',
  //   interface: 'phy0-ap0',
  //   linkSpeed: null,
  //   connectedVia: 'wifi',
  //   wifi: {
  //     ssid: 'TT11g',
  //     signal: -5,
  //     noise: -78,
  //     snr: 73,
  //     inactiveTime: 5730,
  //     rxRate: 58500,
  //     rxMcs: 6,
  //     rxChannelWidth: 20,
  //     rxPackets: 16,
  //     txRate: 6500,
  //     txMcs: 0,
  //     txChannelWidth: 20,
  //     txPackets: 14,
  //     txShortGi: false
  //   },
  //   traffic: { rxBytes: 0, txBytes: 320955, connections: { total: 1, mDNS: 1 } },
  //   network: [ '10_FAMILIE' ],
  //   bridge: 'br-trunk',
  //   port: 'TT11g'
  // }

  async onInit() {
    this.ds = {
      capabilities,
    };
    this.log(`${this.id} driver has been initialized`);
  }

  async onPairListDevices() {
    const routerDriver = this.homey.drivers.getDriver('router');
    if (!routerDriver) return [];

    const devices = routerDriver.knownDevices || [];

    return devices.map((device) => {
      const name = (device.name && device.name !== 'unknown') ? device.name : device.mac;
      return {
        name,
        data: { id: device.mac },
        capabilities,
        settings: {
          mac: device.mac,
          name: device.name,
          hasWifi: true,
        },
      };
    });
  }

};
