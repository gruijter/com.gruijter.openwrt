/*
Copyright 2026, Robin de Gruijter (gruijter@hotmail.com)

This file is part of com.gruijter.openwrt.

com.gruijter.openwrt is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

com.gruijter.openwrt is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with com.gruijter.openwrt.  If not, see <http://www.gnu.org/licenses/>.
*/

'use strict';

const { Device } = require('homey');

const Router = require('../../lib/openwrt');

class RouterDevice extends Device {

  async onInit() {
    try {
      // this.setUnavailable('Waiting for connection').catch(() => null);
      await this.destroyListeners();
      this.busy = false;
      this.skipCounter = 0;
      this.watchDogCounter = 10;
      this.lastQuarterHourlyPollTm = 0;
      this.routerStatsHistory = [];
      const pollingInterval = this.getSettings().pollingInterval || 10;
      let deviceCacheTTL = 5 * pollingInterval;
      if (deviceCacheTTL < 60) deviceCacheTTL = 60;
      await this.setSettings({ deviceCacheTTL }).catch(this.error);
      this.settings = { ...this.getSettings() };
      if (!this.router) this.router = new Router(this.settings);
      if (this.router) {
        this.router.updateOptions(this.settings);
        await this.router.login();
        await this.router.getStaticRouterInfo();
      }
      await this.migrate();
      // start polling device for info
      this.startPolling(pollingInterval).catch(this.error);
      await this.registerListeners();
      this.log(`${this.getName()} has been initialized`);
    } catch (error) {
      this.error(error);
      // this.setUnavailable(error).catch(() => null);
      this.restartDevice(60 * 1000).catch(this.error);
    }
  }

  /**
   * Migrates capability states when the driver capabilities change.
   */
  async migrate() {
    try {
      this.log(`checking device migration for ${this.getName()}`);
      // check if nlbwmon is installed
      if (this.settings.isInternetRouter) {
        this.log(`Checking if nlbwmon is installed on ${this.getName()}`);
        const { isNlbwmonInstalled } = this.router;
        if (!isNlbwmonInstalled) {
          this.log(`nlbwmon is not installed on ${this.getName()}, installing now`);
          await this.router.installNlbwmon().catch(this.error);
          await this.router.getStaticRouterInfo();
        }
      }

      // store the capability states before migration
      const sym = Object.getOwnPropertySymbols(this).find((s) => String(s) === 'Symbol(state)');
      const state = this[sym] || {};
      // check and repair incorrect capability(order)
      let capsChanged = false;
      const correctCaps = [...this.driver.ds.commonCaps];
      if (this.settings?.isDhcpServer) correctCaps.push(...this.driver.ds.dhcpCaps);
      if (this.settings?.isInternetRouter) correctCaps.push(...this.driver.ds.routerCaps);
      if (this.settings?.isAp) correctCaps.push(...this.driver.ds.wifiCaps24);
      if (this.settings?.isAp) correctCaps.push(...this.driver.ds.wifiCaps5);

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

  async onUninit() {
    this.log('Device unInit', this.getName());
    await this.stopPolling();
    if (this.knownDevices && Object.keys(this.knownDevices).length > 0) {
      this.log(`${this.getName()} storing known devices to storage`);
      await this.setStoreValue('knownDevices', this.knownDevices);
    }
    await this.destroyListeners();
    // await this.wait(5000); // wait 5 secs
  }

  async onAdded() {
    this.log(`${this.getName()} has been added`);
  }

  async onSettings({ oldSettings, newSettings, changedKeys }) {
    this.log(`${this.getName()} settings where changed`, newSettings);
    this.restartDevice(3 * 1000).catch(this.error);
    return Promise.resolve('Device will restart');
  }

  async onDeleted() {
    await this.stopPolling();
    await this.destroyListeners();
    this.log('Device deleted', this.getName());
  }

  /**
   * Starts the polling interval.
   * @param {number} interval - Polling interval in seconds.
   */
  async startPolling(interval) {
    this.homey.clearInterval(this.intervalIdPoll);
    this.log(`start polling ${this.getName()} @${interval} seconds interval`);
    await this.doPoll().catch(this.error);
    this.intervalIdPoll = this.homey.setInterval(() => {
      this.doPoll().catch(this.error);
    }, interval * 1000);
  }

  /**
   * Stops the polling interval.
   */
  async stopPolling() {
    this.log(`Stop polling ${this.getName()}`);
    this.homey.clearInterval(this.intervalIdPoll);
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
      await this.stopPolling();
      // this.destroyListeners();
      if (this.knownDevices && Object.keys(this.knownDevices).length > 0) {
        this.log(`${this.getName()} storing known devices to storage`);
        await this.setStoreValue('knownDevices', this.knownDevices);
      }
      const dly = delay || 2000;
      this.log(`Device will restart in ${dly / 1000} seconds`);
      // await this.setUnavailable('Device is restarting. Wait a few minutes!');
      await this.wait(dly);
      this.restarting = false;
      this.onInit().catch(this.error);
    } catch (error) {
      this.error(error);
    }
  }

  /**
   * Performs a single poll to update device data.
   */
  async doPoll() {
    try {
      if (this.watchDogCounter <= 0) {
        this.log('watchdog triggered, restarting Homey device now');
        this.setUnavailable(this.homey.__('device.connectionError')).catch(() => null);
        this.restartDevice(60 * 1000).catch(this.error);
        return;
      }
      const now = Date.now();
      const doQuarterHourlyPoll = (now - this.lastQuarterHourlyPollTm) > 1000 * 60 * 15;
      if (this.busy) {
        this.watchDogCounter -= 1;
        this.skipCounter += 1;
        if (this.skipCounter > 1) this.log(`${this.getName()} skipping multiple polls`, this.skipCounter, this.watchDogCounter);
        return;
      }
      this.busy = true;
      this.skipCounter = 0;
      // update sysinfo hourly, and backup known devices
      if (doQuarterHourlyPoll) {
        if (this.knownDevices && Object.keys(this.knownDevices).length > 0) {
          this.log(`${this.getName()} storing known devices to storage`);
          await this.setStoreValue('knownDevices', this.knownDevices);
        }
        const sysInfo = await this.router.getStaticRouterInfo();
        await this.updateSysInfo(sysInfo);
        this.lastQuarterHourlyPollTm = now;
      }
      // get new status and update the devicestate
      const { routerInfo, attachedDevices } = await this.router.getRouterStatus();
      await this.driver.aggregateAttachedDevices(this, attachedDevices);
      await this.updateHomeyDeviceState({ ...routerInfo });
      this.setAvailable().catch(() => null);
      this.watchDogCounter = 10;
      this.busy = false;
    } catch (error) {
      this.watchDogCounter -= 1;
      this.busy = false;
      this.error('Poll error', error.message);
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

  /**
   * Calculates network speed based on traffic stats difference.
   * @param {object} newstats - New router info stats.
   * @param {object} oldstats - Previous router info stats.
   * @returns {object} Object containing wanDs and wanUs in kbps.
   * @example
   * {
   *   wanDs: 1500.5, // Download speed in kbps
   *   wanUs: 500.2   // Upload speed in kbps
   * }
   */
  calculateSpeed(newstats, oldstats) {
    try {
      if (!oldstats) return {};
      // calculate speeds
      const t1 = newstats?.localtime ? newstats.localtime.getTime() : 0;
      const t2 = oldstats?.localtime ? oldstats.localtime.getTime() : 0;
      const deltaTime = t1 - t2; // milliseconds
      if (deltaTime <= 0) return {};

      const newRx = newstats?.wan?.stats?.rxBytes || 0;
      const oldRx = oldstats?.wan?.stats?.rxBytes || 0;
      const newTx = newstats?.wan?.stats?.txBytes || 0;
      const oldTx = oldstats?.wan?.stats?.txBytes || 0;

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
      return {};
    }
  }

  /**
   * Formats uptime in seconds to a readable string (dd hh mm).
   * @param {number} uptime - Uptime in seconds.
   * @returns {string} Formatted uptime string.
   * @example
   * '12d 5h 30m'
   */
  parseUptime(uptime) {
    if (!uptime) return '';
    const d = Math.floor(uptime / (3600 * 24));
    const h = Math.floor((uptime % (3600 * 24)) / 3600);
    const m = Math.floor((uptime % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  }

  /**
   * Updates system information settings if changed.
   * @param {object} sysInfo - System information object.
   */
  async updateSysInfo(sysInfo) {
    const currentSettings = { ...this.getSettings() };
    const newSysInfo = Object.fromEntries(Object.entries(sysInfo).map(([key, value]) => [key, typeof value === 'boolean' ? value : String(value)]));
    let sysInfoChanged = false;
    Object.entries(newSysInfo).forEach((entry) => {
      if (currentSettings[entry[0]] && (currentSettings[entry[0]] !== entry[1])) {
        this.log(`${this.getName()} updating sysInfo`, entry[0], entry[1]);
        sysInfoChanged = true;
      }
    });
    if (sysInfoChanged) {
      this.setSettings(newSysInfo).catch(this.error);
      this.restartDevice(2 * 1000).catch(this.error);
    }
  }

  /**
   * Updates the Homey device capabilities based on router info.
   * @param {object} data
   * @param {object} data.routerInfo - Current router information.
   * @param {Array} data.attachedDevices - List of attached devices.
   */
  async updateHomeyDeviceState(routerInfo) {
    try {
      // Update history for speed calculation (avg over min 30s)
      const now = routerInfo.localtime ? routerInfo.localtime.getTime() : Date.now();
      const currentStat = {
        localtime: routerInfo.localtime,
        wan: { stats: routerInfo.wan?.stats },
      };
      this.routerStatsHistory.push(currentStat);

      // Find comparison stats (at least 30s ago)
      let oldStat = null;
      for (let i = this.routerStatsHistory.length - 2; i >= 0; i--) {
        const stat = this.routerStatsHistory[i];
        const statTime = stat.localtime ? stat.localtime.getTime() : 0;
        if (now - statTime >= 30000) {
          oldStat = stat;
          break;
        }
      }

      // Fallback to oldest if no stat >= 30s is found
      if (!oldStat && this.routerStatsHistory.length > 1) {
        oldStat = this.routerStatsHistory[0];
      }

      // Prune history (keep max 60s)
      this.routerStatsHistory = this.routerStatsHistory.filter((s) => {
        const t = s.localtime ? s.localtime.getTime() : 0;
        return now - t < 60000;
      });

      const commonStates = {
        uptime: this.parseUptime(routerInfo?.uptime),
        measure_temperature: routerInfo?.temperature || null,
        measure_cpu_utilization: routerInfo?.cpuUsage || 0,
        measure_mem_utilization: routerInfo?.memory?.usage || 0,
      };
      const dhcpStates = {
        measure_attached_devices: routerInfo.totalClientCount || null,
      };
      const speeds = this.calculateSpeed(routerInfo, oldStat);
      const routerStates = {
        alarm_connectivity: !routerInfo?.wan?.up,
        measure_download_speed: speeds.wanDs || 0,
        measure_upload_speed: speeds.wanUs || 0,
      };
      const wifi24 = routerInfo.wifi.find((wifi) => wifi.frequency < 2500);
      const wifiStates24 = {
        'measure_attached_devices.wifi_2_4': wifi24?.clientCount || 0,
        'measure_data_rate.2_4': (wifi24?.bitrate || 0) / 1000,
        'measure_signal_strength.tx_2_4': wifi24?.txPower ?? null,
        'measure_signal_strength.noise_2_4': wifi24?.noise ?? null,
        'measure_signal_strength.snr_2_4': wifi24?.snr ?? null,
      };
      const wifi5 = routerInfo.wifi.find((wifi) => wifi.frequency > 5000 && wifi.frequency < 5900);
      const wifiStates5 = {
        'measure_attached_devices.wifi_5': wifi5?.clientCount || 0,
        'measure_data_rate.5': (wifi5?.bitrate || 0) / 1000,
        'measure_signal_strength.tx_5': wifi5?.txPower ?? null,
        'measure_signal_strength.noise_5': wifi5?.noise ?? null,
        'measure_signal_strength.snr_5': wifi5?.snr ?? null,
      };
      const capabilityStates = {
        ...commonStates,
        ...dhcpStates,
        ...routerStates,
        ...wifiStates24,
        ...wifiStates5,
      };
      // set the capabilities
      Object.entries(capabilityStates).forEach((entry) => {
        this.setCapability(entry[0], entry[1]).catch(this.error);
      });
    } catch (error) {
      this.error(error);
    }
  }

  // trigger flows

  // condition flow card helpers

  // // commands to rpi
  // async executeCommand(args, source) {
  //   try {
  //     if (!this.rpi) throw Error('Rpi not ready');
  //     this.log(`${this.getName()} Executing ${args.command} by ${source}`);
  //     const resp = await this.rpi.execute(args.command);
  //     const tokens = { response: JSON.stringify(resp) };
  //     return tokens;
  //   } catch (error) {
  //     this.error(`${this.getName()}`, error && error.message);
  //     return Promise.reject(error);
  //   }
  // }

  /**
   * Reboots the router.
   * @param {object} args - Flow arguments.
   * @param {object} source - Source of the command.
   * @returns {Promise<boolean>} True if command sent.
   */
  async reboot(args, source) {
    try {
      if (!this.router) throw Error('Router not ready');
      this.log(`${this.getName()} reboot command sent by ${source}`);
      await this.router.reboot();
      return true;
    } catch (error) {
      this.error(`${this.getName()}`, error && error.message);
      return Promise.reject(error);
    }
  }

  // homey device listeners
  /**
   * Registers capability listeners.
   */
  async registerListeners() {
    if (this.listenersSet) return;
    this.onKnownDevicesChanged = (knownDevices) => {
      this.knownDevices = {};
      for (const d of knownDevices) {
        this.knownDevices[d.mac] = d;
      }
    };
    this.driver.on('knownDevices', this.onKnownDevicesChanged);
    this.listenersSet = true;
    this.log(`${this.getName()} ready setting up listeners`);
  }

  // remove listeners NEEDS TO BE ADAPTED
  /**
   * Destroys listeners and logs out from the router.
   */
  async destroyListeners() {
    try {
      this.log('removing listeners', this.getName());
      if (this.router) await this.router.logout();
      if (this.onKnownDevicesChanged) {
        this.driver.removeListener('knownDevices', this.onKnownDevicesChanged);
      }
    } catch (error) {
      this.error(error);
    }
  }

}

module.exports = RouterDevice;
