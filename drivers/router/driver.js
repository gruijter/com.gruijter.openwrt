'use strict';

const Homey = require('homey');
const Router = require('../../lib/openwrt');

const commonCaps = [
  'uptime',
  'measure_temperature',
  'measure_cpu_utilization',
  'measure_mem_utilization',
];
const dhcpCaps = [
  'measure_attached_devices',
];
const routerCaps = [
  'alarm_connectivity',
  'measure_download_speed',
  'measure_upload_speed',
];
const wifiCaps24 = [
  'measure_attached_devices.wifi_2_4',
  'measure_data_rate.2_4',
  'measure_signal_strength.tx_2_4',
  'measure_signal_strength.noise_2_4',
  'measure_signal_strength.snr_2_4',
];
const wifiCaps5 = [
  'measure_attached_devices.wifi_5',
  'measure_data_rate.5',
  'measure_signal_strength.tx_5',
  'measure_signal_strength.noise_5',
  'measure_signal_strength.snr_5',
];

module.exports = class MyDriver extends Homey.Driver {

  async onInit() {
    this.ds = {
      commonCaps, dhcpCaps, routerCaps, wifiCaps24, wifiCaps5,
    };
    this.flowQueue = [];
    this.isProcessingFlows = false;

    // Reconstruct macCache from devices
    const devices = this.getDevices();
    const initialMacCache = {};
    for (const device of devices) {
      try {
        const knownDevices = await device.getStoreValue('knownDevices');
        if (knownDevices) {
          for (const d of Object.values(knownDevices)) {
            if (d.mac) {
              initialMacCache[d.mac] = {
                ...d,
                lastSeen: d.lastSeen || Date.now(),
              };
            }
          }
        }
      } catch (e) {
        // ignore
      }
    }

    Router.setPersistentMacCache(initialMacCache);
    this.knownDevices = Object.values(initialMacCache);

    this.log(`${this.id} driver has been initialized`);
  }

  async onPair(session) {
    let deviceList = [];

    session.setHandler('pairSettings', async (data) => {
      try {
        const username = data.username === '' ? 'root' : data.username;
        const { password, host } = data;
        const sshPort = Number(data.port) || 22;
        const router = new Router({
          host, sshPort, username, password,
        });
        await router.login();
        const routerInfo = await router.getStaticRouterInfo();
        const capabilities = [...commonCaps];
        if (routerInfo?.isDhcpServer) capabilities.push(...dhcpCaps);
        if (routerInfo?.isInternetRouter) capabilities.push(...routerCaps);
        if (routerInfo?.isAp) capabilities.push(...wifiCaps24);
        if (routerInfo?.isAp) capabilities.push(...wifiCaps5);
        deviceList = [{
          name: `${routerInfo.hostname}`,
          data: {
            id: routerInfo.uniqueId,
          },
          capabilities,
          settings: {
            username,
            password,
            host,
            sshPort,
            id: routerInfo.uniqueId,
            name: routerInfo.hostname,
            firmwareVersion: routerInfo.firmwareVersion || '',
            luciVersion: routerInfo.luciVersion || '',
            model: routerInfo.model || '',
            architecture: routerInfo.architecture || '',
            totalMemoryMB: routerInfo?.totalMemoryMB || '',
            pollingInterval: 15,
            deviceCacheTTL: 60,
            isInternetRouter: !!routerInfo.isInternetRouter,
            isDhcpServer: !!routerInfo.isDhcpServer,
            isFirewall: !!routerInfo.isFirewall,
            isAp: !!routerInfo.isAp,
          },
        }];
        await router.logout().catch(this.error);
        await session.showView('list_devices');
        return deviceList;
      } catch (error) {
        const msg = error.message && error.message.includes('"message":') ? JSON.parse(error.message).message : error;
        this.error(error);
        throw msg;
      }
    });

    session.setHandler('list_devices', async () => {
      try {
        return Promise.all(deviceList);
      } catch (error) {
        const msg = error.message && error.message.includes('"message":') ? JSON.parse(error.message).message : error;
        this.error(error);
        throw msg;
      }
    });
  }

  triggerFlow(triggerName, device, tokens, logMessage) {
    this.flowQueue.push({
      triggerName, device, tokens, logMessage,
    });
    this.processFlowQueue().catch(this.error);
  }

  async processFlowQueue() {
    if (this.isProcessingFlows) return;
    this.isProcessingFlows = true;
    while (this.flowQueue.length > 0) {
      const {
        triggerName, device, tokens, logMessage,
      } = this.flowQueue.shift();
      if (logMessage) this.log(logMessage);
      try {
        if (this.homey.app[triggerName]) {
          await this.homey.app[triggerName](device, tokens);
        }
      } catch (e) {
        this.error(e);
      }
      await new Promise((resolve) => this.homey.setTimeout(resolve, 50));
    }
    this.isProcessingFlows = false;
  }

  /**
   * Updates the global list of known devices by aggregating data from this router,
   * and triggers Homey flows for device presence changes.
   */
  async aggregateAttachedDevices(routerDevice, attachedDevices) {
    const routerId = routerDevice.getData().id;
    const routerName = routerDevice.getName();
    const isInternetRouter = !!routerDevice.getSettings().isInternetRouter;
    const registeredRouterIds = this.getDevices().map((d) => d.getData().id);

    const oldDevicesMap = new Map(this.knownDevices.map((d) => [d.mac, d]));

    this.knownDevices = Router.aggregateDevices(
      { routerId, routerName, isInternetRouter },
      attachedDevices,
      registeredRouterIds,
    );

    this.emit('knownDevices', this.knownDevices);

    // Check for changes and trigger flows
    for (const device of this.knownDevices) {
      const oldDevice = oldDevicesMap.get(device.mac);
      const isConnected = device.connected;
      const wasConnected = oldDevice?.connected;

      if (isConnected === wasConnected && oldDevice) continue;

      const targetRouter = this.getDevices().find((d) => d.getData().id === device.routerId) || routerDevice;
      const tokens = {
        mac: device.mac,
        name: device.name,
        ip: device.ip,
        routerName: device.routerName || targetRouter.getName(),
        port: device.port || '',
        linkSpeed: parseInt(device.linkSpeed, 10) || 0,
        wifiSsid: device.wifi?.ssid || '',
        wifiSignal: device.wifi?.signal || 0,
        wifiSnr: device.wifi?.snr || 0,
        rxBytes: device.traffic?.rxBytes || 0,
        txBytes: device.traffic?.txBytes || 0,
        network: device.network ? JSON.stringify(device.network) : '',
        firewallZones: device.firewallZones ? JSON.stringify(device.firewallZones) : '',
      };

      if (!oldDevice && isConnected) {
        this.triggerFlow('trigger_device_new_detected', targetRouter, tokens, `New device detected: ${device.mac}, ${device.name}`);
        if (targetRouter.handleDeviceConnected) await targetRouter.handleDeviceConnected(device);
      }

      if (isConnected && !wasConnected) {
        this.triggerFlow('trigger_device_came_online', targetRouter, tokens, `Device connected: ${device.mac}, ${device.name}, ${device.ip}`);
      } else if (!isConnected && wasConnected) {
        this.triggerFlow('trigger_device_went_offline', targetRouter, tokens, `Device disconnected: ${device.mac}, ${device.name}`);
      }
    }

    return this.knownDevices;
  }
};
