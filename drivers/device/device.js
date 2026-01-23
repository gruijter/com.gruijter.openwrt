'use strict';

const Homey = require('homey');

module.exports = class MyDevice extends Homey.Device {

  async onInit() {
    try {
      await this.migrate();
      this.registerListeners();
      await this.setAvailable();
      this.log(`${this.getName()} has been initialized`);
    } catch (error) {
      this.error(error);
      // this.setUnavailable(error).catch(() => null);
      this.restartDevice(60 * 1000).catch(this.error);
    }
  }

  async onAdded() {
    this.log(`${this.getName()} has been added`);
  }

  async onSettings({ oldSettings, newSettings, changedKeys }) {
    this.log(`${this.getName()} settings where changed`);
  }

  async onRenamed(name) {
    this.log(`${this.getName()} was renamed`);
  }

  async onDeleted() {
    this.log(`${this.getName()} has been deleted`);
    this.unregisterListeners();
  }

  onUninit() {
    this.unregisterListeners();
  }

  wait(ms) {
    return new Promise((resolve) => {
      this.homey.setTimeout(resolve, ms);
    });
  }

  /**
   * Restarts the device (re-initializes) after a delay.
   * @param {number} delay - Delay in milliseconds.
   */
  async restartDevice(delay) {
    try {
      if (this.restarting) return;
      this.restarting = true;
      this.unregisterListeners();
      const dly = delay || 2000;
      this.log(`Device will restart in ${dly / 1000} seconds`);
      await this.wait(dly);
      this.restarting = false;
      this.onInit().catch(this.error);
    } catch (error) {
      this.error(error);
    }
  }

  /*
  * Migrates capability states when the driver capabilities change.
  */
  async migrate() {
    try {
      this.log(`checking device migration for ${this.getName()}`);
      // store the capability states before migration
      const sym = Object.getOwnPropertySymbols(this).find((s) => String(s) === 'Symbol(state)');
      const state = this[sym] || {};
      // check and repair incorrect capability(order)
      let capsChanged = false;
      const correctCaps = [...this.driver.ds.capabilities];

      const currentCaps = this.getCapabilities();
      const capsToRemove = currentCaps.filter((c) => !correctCaps.includes(c));
      for (const cap of capsToRemove) {
        this.log(`removing capability ${cap} for ${this.getName()}`);
        try {
          await this.removeCapability(cap);
          capsChanged = true;
          await this.wait(1000);
        } catch (error) {
          this.error(`Could not remove capability ${cap}:`, error);
        }
      }

      const activeCaps = this.getCapabilities();
      let matchIndex = 0;
      while (matchIndex < activeCaps.length && matchIndex < correctCaps.length) {
        if (activeCaps[matchIndex] !== correctCaps[matchIndex]) {
          break;
        }
        matchIndex += 1;
      }

      if (matchIndex < activeCaps.length || matchIndex < correctCaps.length) {
        for (let i = activeCaps.length - 1; i >= matchIndex; i -= 1) {
          const cap = activeCaps[i];
          this.log(`removing out-of-order capability ${cap} for ${this.getName()}`);
          await this.removeCapability(cap);
          capsChanged = true;
          await this.wait(1000);
        }

        for (let i = matchIndex; i < correctCaps.length; i += 1) {
          const cap = correctCaps[i];
          this.log(`adding capability ${cap} for ${this.getName()}`);
          await this.addCapability(cap);
          capsChanged = true;
          if (state[cap] !== undefined) {
            this.log(`${this.getName()} restoring value ${cap} to ${state[cap]}`);
            this.setCapability(cap, state[cap]).catch(this.error);
          }
          await this.wait(1000);
        }
      }
      if (capsChanged) this.restartDevice(2 * 1000).catch(this.error);
    } catch (error) {
      this.error(error);
    }
  }

  /**
   * Calculates network speed based on traffic stats difference.
   * @param {object} newstats - New router info stats.
   * @param {object} oldstats - Previous router info stats.
   * @returns {object|null} Object containing wanDs and wanUs in Mbps, or null if not calculable.
   * @example
   * {
   *   wanDs: 150.5, // Download speed in Mbps
   *   wanUs: 50.2   // Upload speed in Mbps
   * }
   */
  calculateSpeed(newstats, oldstats) {
    try {
      if (!oldstats) return null;
      // calculate speeds
      const deltaTime = (newstats?.lastSeen - oldstats?.lastSeen); // milliseconds
      if (!deltaTime || deltaTime < 20000) return null;

      const newRx = newstats?.traffic?.rxBytes || 0;
      const oldRx = oldstats?.traffic?.rxBytes || 0;
      const newTx = newstats?.traffic?.txBytes || 0;
      const oldTx = oldstats?.traffic?.txBytes || 0;

      let wanDs = Math.round(((8 * (newRx - oldRx)) / deltaTime)) / 1000;
      let wanUs = Math.round(((8 * (newTx - oldTx)) / deltaTime)) / 1000;

      // Handle counter reset (negative speed) or invalid data
      if (wanDs < 0 || Number.isNaN(wanDs)) wanDs = 0;
      if (wanUs < 0 || Number.isNaN(wanUs)) wanUs = 0;

      return {
        wanDs, wanUs,
      };
    } catch (error) {
      this.error(error);
      return null;
    }
  }

  /**
   * Sets a capability value if the device has that capability.
   * @param {string} capability - The capability ID.
   * @param {*} value - The value to set.
   */
  async setCapability(capability, value) {
    if (this.hasCapability(capability) && value !== undefined) {
      await this.setCapabilityValue(capability, value)
        .catch((error) => {
          this.log(error, capability, value);
        });
    }
  }

  async updateHomeyDeviceState(deviceInfo) {
    try {
      if (!this.lastSpeedStats) this.lastSpeedStats = { ...deviceInfo };
      const speeds = this.calculateSpeed(deviceInfo, this.lastSpeedStats);
      if (speeds) {
        this.lastSpeedStats = { ...deviceInfo };
      }

      const isConnected = deviceInfo.connected || false;
      const isWifi = deviceInfo.connectedVia === 'wifi';

      const currentWanUp = this.getCapabilityValue('measure_upload_speed') || 0;
      const currentWanDown = this.getCapabilityValue('measure_download_speed') || 0;

      const nextWanUp = speeds ? speeds.wanUs : currentWanUp;
      const nextWanDown = speeds ? speeds.wanDs : currentWanDown;

      const capabilityStates = {
        device_connected: isConnected,
        ip_address: isConnected ? (deviceInfo.ip || '') : '',
        name_in_router: deviceInfo.name || '',
        router_name: isConnected ? (deviceInfo.routerName || '') : '',
        port: isConnected ? (deviceInfo.port || '') : '',
        measure_link_speed: isConnected ? (parseInt(deviceInfo.linkSpeed, 10) || 0) : 0,
        firewall_zone: isConnected ? (deviceInfo.firewallZone || '') : '',
        measure_connections: isConnected ? (deviceInfo?.traffic?.connections?.total || 0) : 0,
        measure_signal_strength: (isConnected && isWifi) ? (deviceInfo?.wifi?.signal ?? null) : null,
        'measure_signal_strength.snr': (isConnected && isWifi) ? deviceInfo?.wifi?.snr : null,
        measure_upload_speed: isConnected ? nextWanUp : 0,
        measure_download_speed: isConnected ? nextWanDown : 0,
        onoff: isConnected,
      };

      // set the capabilities
      Object.entries(capabilityStates).forEach((entry) => {
        this.setCapability(entry[0], entry[1]).catch(this.error);
      });
    } catch (error) {
      this.error(error);
    }
  }

  getMonitoredMacs() {
    const mac = this.getData().id;
    const settings = this.getSettings();
    const macs = new Set([mac]);
    if (settings.alias1) macs.add(settings.alias1.trim().toUpperCase());
    if (settings.alias2) macs.add(settings.alias2.trim().toUpperCase());
    if (settings.alias3) macs.add(settings.alias3.trim().toUpperCase());
    if (settings.alias4) macs.add(settings.alias4.trim().toUpperCase());
    return macs;
  }

  findDevices(knownDevices, macs) {
    if (Array.isArray(knownDevices)) {
      return knownDevices.filter((d) => macs.has(d.mac));
    }
    const foundDevices = [];
    for (const m of macs) {
      if (knownDevices[m]) foundDevices.push(knownDevices[m]);
    }
    return foundDevices;
  }

  mergeDeviceData(foundDevices) {
    const merged = { ...foundDevices[0] };
    merged.connected = false;
    merged.traffic = { rxBytes: 0, txBytes: 0, connections: { total: 0 } };
    let maxLinkSpeed = 0;
    let maxLastSeen = 0;

    for (const d of foundDevices) {
      if (d.connected) merged.connected = true;
      if (d.lastSeen > maxLastSeen) maxLastSeen = d.lastSeen;

      if (d.traffic) {
        merged.traffic.rxBytes += (d.traffic.rxBytes || 0);
        merged.traffic.txBytes += (d.traffic.txBytes || 0);
        if (d.traffic.connections) {
          merged.traffic.connections.total += (d.traffic.connections.total || 0);
        }
      }

      const speed = parseInt(d.linkSpeed, 10) || 0;
      if (speed > maxLinkSpeed) maxLinkSpeed = speed;
    }

    merged.lastSeen = maxLastSeen;
    merged.linkSpeed = maxLinkSpeed;

    if (!merged.wifi) {
      const wifiDev = foundDevices.find((d) => d.wifi);
      if (wifiDev) {
        merged.wifi = wifiDev.wifi;
      }
    }

    if (!merged.firewallZone) {
      const fwDev = foundDevices.find((d) => d.firewallZone);
      if (fwDev) {
        merged.firewallZone = fwDev.firewallZone;
      }
    }
    return merged;
  }

  updateRouterTTL(merged) {
    // Check offline_after setting
    const offlineAfter = this.getSettings().offline_after;

    // Push setting to router
    if (merged.routerId && (this.lastRouterId !== merged.routerId || this.lastOfflineAfter !== offlineAfter)) {
      this.lastRouterId = merged.routerId;
      this.lastOfflineAfter = offlineAfter;
      const routerDriver = this.homey.drivers.getDriver('router');
      if (routerDriver) {
        const routerDevice = routerDriver.getDevices().find((d) => d.getData().id === merged.routerId);
        if (routerDevice && routerDevice.setDeviceTTL) {
          routerDevice.setDeviceTTL(this.getData().id, offlineAfter).catch(() => {});
        }
      }
    }
  }

  unregisterListeners() {
    if (this.onKnownDevicesChanged) {
      const routerDriver = this.homey.drivers.getDriver('router');
      if (routerDriver) {
        routerDriver.removeListener('knownDevices', this.onKnownDevicesChanged);
      }
    }
  }

  registerListeners() {
    this.unregisterListeners();
    this.onKnownDevicesChanged = (knownDevices) => {
      const macs = this.getMonitoredMacs();
      const foundDevices = this.findDevices(knownDevices, macs);

      if (foundDevices.length > 0) {
        const merged = this.mergeDeviceData(foundDevices);
        this.updateRouterTTL(merged);
        this.updateHomeyDeviceState(merged).catch(this.error);
      }
    };
    const routerDriver = this.homey.drivers.getDriver('router');
    if (routerDriver) {
      routerDriver.on('knownDevices', this.onKnownDevicesChanged);
      if (routerDriver.knownDevices) this.onKnownDevicesChanged(routerDriver.knownDevices);
    }
  }

  // flow action handler from app.js
  async handleFlowAction({ action, args }) {
    if (this[action]) return this[action](args, 'flow');
    return Promise.reject(Error('action not found'));
  }

};
