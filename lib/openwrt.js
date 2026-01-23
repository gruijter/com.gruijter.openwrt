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

const os = require('os');
const https = require('https');
const http = require('http');
const { Client } = require('ssh2');
const dns = require('dns').promises;
const net = require('net');
const dgram = require('dgram');

async function resolveHostname(ip, timeoutMs = 700) {
  try {
    const p = dns.reverse(ip).then((names) => (names && names[0] ? names[0].split('.')[0] : null)).catch(() => null);
    const t = new Promise((resolve) => { // eslint-disable-next-line homey-app/global-timers
      setTimeout(() => resolve(null), timeoutMs);
    });
    return await Promise.race([p, t]);
  } catch (_) {
    return null;
  }
}

class OpenWRTRouter {
  #host;
  #username;
  #password;
  #timeout;
  #deviceCache;
  #deviceCacheTTL;
  #sshConnection;
  #sshCommandQueue;
  #sshConnecting;
  #sshStatus;
  #sshConfig;
  #cpuStatsCache;
  #staticRouterInfo;
  #pingCheck;
  #customDeviceTTLs;

  static #multiRouterCache = {};
  static #persistentMacCache = {};
  static #knownDevices = [];
  static #lastMacCacheCleanup = 0;
  static #startupTime = Date.now();
  static #routerTTLs = new Map();

  // 1. LIFECYCLE
  /**
   * Creates an instance of OpenWRTRouter.
   * @param {object} options
   * @param {string} [options.host='192.168.1.1'] - Router IP address or hostname.
   * @param {string} [options.username='root'] - SSH username.
   * @param {string} [options.password=''] - SSH password.
   * @param {number} [options.timeout=5000] - Connection timeout in milliseconds.
   * @param {number} [options.sshPort=22] - SSH port.
   * @param {number} [options.deviceCacheTTL=60] - Device cache TTL in seconds.
   * @param {boolean} [options.pingCheck=true] - Enable active pinging for presence detection.
   * @param {string} [options.id] - Unique Router ID (MAC address), required for per-router settings like TTL.
   * @param {number} [options.knownDevicesCacheTTL=30] - Known devices cache TTL in days.
   */
  constructor(options) {
    this.#host = options.host || '192.168.1.1';
    this.#username = options.username || 'root';
    this.#password = options.password || '';
    this.#timeout = options.timeout || 5000;

    this.#sshConfig = {
      host: this.#host,
      port: options.sshPort || 22,
      username: this.#username,
      password: this.#password,
      readyTimeout: this.#timeout,
    };

    this.#deviceCache = new Map();
    this.#deviceCacheTTL = (typeof options.deviceCacheTTL === 'number') ? options.deviceCacheTTL : 60;
    this.#pingCheck = options.pingCheck !== false;
    this.#customDeviceTTLs = new Map();

    this.#sshConnection = null;
    this.#sshCommandQueue = Promise.resolve();
    this.#sshConnecting = false;
    this.#sshStatus = 'logged_out';
    this.#cpuStatsCache = null;
    this.#staticRouterInfo = null;

    if (options.id && options.knownDevicesCacheTTL !== undefined) {
      OpenWRTRouter.#routerTTLs.set(options.id, Number(options.knownDevicesCacheTTL) || 30);
    }
  }

  /**
   * Updates the router options.
   * @param {object} options
   * @param {string} [options.host] - Router IP address or hostname.
   * @param {string} [options.username] - SSH username.
   * @param {string} [options.password] - SSH password.
   * @param {number} [options.timeout] - Connection timeout in milliseconds.
   * @param {number} [options.sshPort] - SSH port.
   * @param {number} [options.deviceCacheTTL] - Device cache TTL in seconds.
   * @param {boolean} [options.pingCheck] - Enable active pinging for presence detection.
   * @param {string} [options.id] - Unique Router ID (MAC address), required for per-router settings like TTL.
   * @param {number} [options.knownDevicesCacheTTL] - Known devices cache TTL in days.
   */
  updateOptions(options) {
    let connectionParamsChanged = false;

    if (options.host && options.host !== this.#host) {
      this.#host = options.host;
      connectionParamsChanged = true;
    }
    if (options.username && options.username !== this.#username) {
      this.#username = options.username;
      connectionParamsChanged = true;
    }
    if (options.password !== undefined && options.password !== this.#password) {
      this.#password = options.password;
      connectionParamsChanged = true;
    }
    if (options.timeout && options.timeout !== this.#timeout) {
      this.#timeout = options.timeout;
      connectionParamsChanged = true;
    }

    const currentPort = this.#sshConfig.port;
    const newPort = options.sshPort;
    if (newPort && newPort !== currentPort) {
      connectionParamsChanged = true;
    }

    if (typeof options.deviceCacheTTL === 'number') {
      this.#deviceCacheTTL = options.deviceCacheTTL;
    }

    if (options.pingCheck !== undefined) {
      this.#pingCheck = options.pingCheck;
    }

    if (options.id && options.knownDevicesCacheTTL !== undefined) {
      OpenWRTRouter.#routerTTLs.set(options.id, Number(options.knownDevicesCacheTTL) || 30);
    }

    if (connectionParamsChanged) {
      this.#sshConfig = {
        host: this.#host,
        port: newPort || currentPort,
        username: this.#username,
        password: this.#password,
        readyTimeout: this.#timeout,
      };

      if (this.#sshConnection || this.#sshConnecting) {
        this.logout().catch(() => {});
      }
    }
  }

  // 2. STATIC PUBLIC
  /**
   * Discovers OpenWrt routers on the local network.
   * @param {object} [options]
   * @param {number} [options.timeout=1500] - Timeout for each probe in ms.
   * @param {number} [options.concurrency=100] - Number of concurrent probes.
   * @param {boolean} [options.silent=false] - Suppress console output.
   * @param {boolean} [options.debug=false] - Enable debug logging.
   * @returns {Promise<Array<{ip: string, hostname: string|null, luciVersion: string|null, luciPort: number|null, sshPort: number|null}>>} List of discovered routers.
   * @example
   * [
   *   {
   *     ip: '192.168.1.1',
   *     hostname: 'OpenWrt',
   *     luciVersion: 'git-21.284.67084-e4d24f0',
   *     luciPort: 80,
   *     sshPort: 22
   *   }
   * ]
   */
  static async discover({
    timeout = 1500, concurrency = 100, silent = false, debug = false,
  } = {}) {
    const allFoundRouters = new Map();
    const checkedIps = new Set();

    const makeRpcCall = (ip, protocol, object = 'session', method = 'access', params = {}) => {
      return new Promise((resolve) => {
        const postData = JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'call',
          params: ['00000000000000000000000000000000', object, method, params],
        });
        const client = protocol === 'https' ? https : http;
        const options = {
          hostname: ip,
          path: '/ubus',
          method: 'POST',
          timeout,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
          agent: protocol === 'https' ? new https.Agent({ rejectUnauthorized: false }) : undefined,
        };

        const req = client.request(options, (res) => {
          let rawData = '';
          res.on('data', (chunk) => {
            rawData += chunk;
          });
          res.on('end', () => {
            try {
              const json = JSON.parse(rawData);
              resolve(json.result ? (json.result[1] || json.result) : null);
            } catch (e) {
              resolve(null);
            }
          });
        }).on('error', (e) => {
          if (debug) console.log(`[discover] makeRpcCall to ${ip} (${protocol}) failed: ${e.message}`); // eslint-disable-line no-console
          resolve(null);
        });
        req.on('timeout', () => {
          req.destroy();
          resolve(null);
        });
        req.on('error', (e) => {
          resolve(null);
        }).write(postData);
        req.end(); // eslint-disable-line no-sequences
      });
    };

    const getHostnameFromLuci = async (ip) => {

      const parseTitleAndVersion = (html) => {
        const result = { hostname: null, luciVersion: null };

        const titleMatch = html.match(/<title>(.+)<\/title>/i);
        if (titleMatch && titleMatch[1]) {
          result.hostname = titleMatch[1].split(' - ')[0].trim() || null;
        }

        const versionMatch = html.match(/\/luci-static\/[^\s'"]+\?v=([^"']+)/);
        if (versionMatch && versionMatch[1]) {
          result.luciVersion = versionMatch[1];
        }

        // Only return an object if we found a hostname, otherwise return null
        return result.hostname ? result : null;
      };

      const tryProtocol = (protocol) => {
        return new Promise((resolve) => {
          const client = protocol === 'https' ? https : http;
          const options = {
            hostname: ip,
            path: '/',
            method: 'GET',
            timeout: 2000,
            agent: protocol === 'https' ? new https.Agent({ rejectUnauthorized: false }) : undefined,
          };

          const req = client.request(options, (res) => {
            // Handle 3xx server-side redirect
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              let newUrl;
              try {
                newUrl = new URL(res.headers.location, `${protocol}://${ip}`);
              } catch (e) {
                resolve(null);
                return;
              }

              const newClient = newUrl.protocol === 'https:' ? https : http;
              newClient.get(newUrl, { agent: options.agent, rejectUnauthorized: false }, (res2) => {
                let rawData = '';
                res2.on('data', (chunk) => {
                  rawData += chunk;
                });
                res2.on('end', () => {
                  resolve(parseTitleAndVersion(rawData));
                });
              }).on('error', () => resolve(null));
              return;
            }

            // Handle 200 OK, which might contain a client-side redirect or the title
            let rawData = '';
            res.on('data', (chunk) => {
              rawData += chunk;
            });
            res.on('end', () => {
              const metaRefreshMatch = rawData.match(/<meta http-equiv="refresh".*?url=([^"]+)/i);

              if (metaRefreshMatch && metaRefreshMatch[1]) {
                const refreshUrl = metaRefreshMatch[1].replace(/&amp;/g, '&');
                let newUrl;
                try {
                  newUrl = new URL(refreshUrl, `${protocol}://${ip}`);
                } catch (e) {
                  resolve(null);
                  return;
                }

                const newClient = newUrl.protocol === 'https:' ? https : http;
                newClient.get(newUrl, { agent: options.agent, rejectUnauthorized: false }, (res2) => {
                  let rawData2 = '';
                  res2.on('data', (chunk) => {
                    rawData2 += chunk;
                  });
                  res2.on('end', () => {
                    resolve(parseTitleAndVersion(rawData2));
                  });
                }).on('error', () => resolve(null));
              } else {
                // No redirect, just parse the title from the current page
                resolve(parseTitleAndVersion(rawData));
              }
            });
          });
          req.on('timeout', () => {
            req.destroy();
            resolve(null);
          });
          req.on('error', () => {
            req.destroy();
            resolve(null);
          });
          req.end();
        });
      };

      const resultHttps = await tryProtocol('https');
      if (resultHttps) {
        return { ...resultHttps, luciProtocol: 'https' };
      }

      const resultHttp = await tryProtocol('http');
      if (resultHttp) {
        return { ...resultHttp, luciProtocol: 'http' };
      }

      return null;
    };

    const detectSshPort = (ip, timeout = 1000) => {
      return new Promise((resolve) => {
        const port = 22; // Common port
        const socket = new (net.Socket)();
        socket.setTimeout(timeout);
        socket.on('connect', () => {
          socket.destroy();
          resolve(port);
        });
        socket.on('error', (err) => {
          socket.destroy();
          resolve(null);
        });
        socket.on('timeout', () => {
          socket.destroy();
          resolve(null);
        });
        socket.connect(port, ip);
      });
    };

    const checkIpAndAdd = async (ip, { hostname: discoveredHostname, sshPort: discoveredSshPort } = {}) => {
      if (!ip || checkedIps.has(ip)) return;
      if (allFoundRouters.has(ip)) return;
      checkedIps.add(ip);
      if (debug) console.log(`[discover] Checking IP: ${ip}`); // eslint-disable-line no-console

      // Try https and http ubus endpoints in parallel
      const ubusProbes = await Promise.all([
        makeRpcCall(ip, 'https', 'session', 'access', {}),
        makeRpcCall(ip, 'http', 'session', 'access', {}),
      ]);

      const session = ubusProbes.find((s) => s);

      if (session) {
        if (allFoundRouters.has(ip)) return;

        // Run subsequent probes in parallel
        const [sshPort, luciResult, resolvedHostname] = await Promise.all([
          discoveredSshPort ? Promise.resolve(discoveredSshPort) : detectSshPort(ip),
          discoveredHostname ? Promise.resolve(null) : getHostnameFromLuci(ip),
          discoveredHostname ? Promise.resolve(null) : resolveHostname(ip),
        ]);

        const finalHostname = discoveredHostname || luciResult?.hostname || resolvedHostname;
        const luciVersion = luciResult?.luciVersion || null;
        let luciPort = null;
        if (luciResult) {
          luciPort = luciResult.luciProtocol === 'https' ? 443 : 80;
        }

        if (!silent) {
          console.log(`[discover] Found OpenWrt router at ${ip} (Hostname: ${finalHostname || 'N/A'})`); // eslint-disable-line no-console
        }
        allFoundRouters.set(ip, {
          ip, hostname: finalHostname, luciVersion, luciPort, sshPort,
        });
      }
    };

    try {
      await new Promise((resolve) => { // eslint-disable-next-line homey-app/global-timers
        setTimeout(resolve, 500);
      });
      if (!silent) {
        console.log('[discover] Scanning local network...'); // eslint-disable-line no-console
      }

      const ipsToTest = new Set();
      const ipToLong = (ip) => ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      const longToIp = (long) => [(long >>> 24), (long >>> 16) & 255, (long >>> 8) & 255, long & 255].join('.');

      const interfaces = os.networkInterfaces();
      for (const ifaceList of Object.values(interfaces)) {
        for (const iface of ifaceList) {
          if (iface.family === 'IPv4' && !iface.internal) {
            if (debug) console.log(`[discover] Found network interface: ${iface.address}/${iface.netmask}`); // eslint-disable-line no-console
            const ipLong = ipToLong(iface.address);
            const maskLong = ipToLong(iface.netmask);
            const networkAddressLong = ipLong & maskLong;
            const broadcastAddressLong = networkAddressLong + ((-1 >>> 0) - maskLong);
            for (let i = networkAddressLong + 1; i < broadcastAddressLong; i++) {
              ipsToTest.add(longToIp(i));
            }
          }
        }
      }

      const ipArray = Array.from(ipsToTest);
      if (debug) console.log(`[discover] Starting scan of ${ipArray.length} IPs with concurrency ${concurrency}...`); // eslint-disable-line no-console
      let index = 0;
      const worker = async () => {
        while (index < ipArray.length) {
          const ip = ipArray[index++];
          await checkIpAndAdd(ip); // eslint-disable-line no-await-in-loop
        }
      }; // eslint-disable-line consistent-return

      const concurrencyLimit = Math.min(concurrency, ipArray.length);
      await Promise.all(Array.from({ length: concurrencyLimit }).map(worker));
    } catch (err) {
      if (!silent || debug) {
        // console.error('Error during network scan:', err.message);
      }
    }

    if (!silent) {
      console.log(`[discover] Discovery finished. Found ${allFoundRouters.size} total router(s).`); // eslint-disable-line no-console
    }

    const discoveredRouters = Array.from(allFoundRouters.values());

    // Helper to convert IP string to a number for correct sorting
    const ipToNumber = (ip) => {
      if (typeof ip !== 'string') return Infinity;
      return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
    };

    discoveredRouters.sort((a, b) => ipToNumber(a.ip) - ipToNumber(b.ip));
    return discoveredRouters;
  }

  /**
   * Sets the initial persistent MAC cache.
   * Useful for restoring state after a restart.
   * @param {object} cache - The cache object (mac -> device info).
   */
  static setPersistentMacCache(cache) {
    if (cache) {
      this.#persistentMacCache = { ...cache };
    }
  }

  /**
   * Aggregates attached devices from multiple routers.
   * Maintains a static cache of devices across all router instances.
   * @param {object} routerInfo - Information about the reporting router.
   * @param {string} routerInfo.routerId - Unique ID of the router.
   * @param {string} routerInfo.routerName - Name of the router.
   * @param {boolean} routerInfo.isInternetRouter - Whether this is the main internet gateway.
   * @param {Array<object>} attachedDevices - List of devices attached to the reporting router.
   * @param {Array<string>} [registeredRouterIds=[]] - List of currently registered router IDs to filter stale caches.
   * @returns {Array<object>} Aggregated list of known devices.
   */
  static aggregateDevices(routerInfo, attachedDevices, registeredRouterIds = []) {
    const { routerId, routerName, isInternetRouter } = routerInfo;
    const now = Date.now();

    // Update cache for the calling router
    if (routerId && Array.isArray(attachedDevices)) {
      // Ensure routerName/Id is set on devices
      attachedDevices.forEach((d) => {
        d.routerName = routerName;
        d.routerId = routerId;
      });
      this.#multiRouterCache[routerId] = {
        timestamp: now,
        devices: attachedDevices,
        isInternetRouter: !!isInternetRouter,
      };
    }

    // Collect devices from all non-stale caches (max 3 minutes old)
    const allDevicesMap = new Map();
    for (const [id, cache] of Object.entries(this.#multiRouterCache)) {
      // Filter out caches from routers that are no longer registered
      if (registeredRouterIds.length > 0 && !registeredRouterIds.includes(id)) {
        delete this.#multiRouterCache[id];
        continue;
      }

      if (now - cache.timestamp > 180000) {
        delete this.#multiRouterCache[id];
        continue;
      }
      for (const device of cache.devices) {
        if (!device.mac) continue;
        if (!allDevicesMap.has(device.mac)) allDevicesMap.set(device.mac, []);
        allDevicesMap.get(device.mac).push({ device, timestamp: cache.timestamp });
      }
    }

    // Cleanup old macCache entries (older than 24 hours) - run once per hour
    const cacheCleanupInterval = 3600000;

    if (!this.#lastMacCacheCleanup || now - this.#lastMacCacheCleanup > cacheCleanupInterval) {
      this.#lastMacCacheCleanup = now;
      for (const [mac, entry] of Object.entries(this.#persistentMacCache)) {
        const ttlDays = (entry.routerId && this.#routerTTLs.get(entry.routerId)) || 30;
        const maxOfflineDuration = ttlDays * 24 * 60 * 60 * 1000;
        if (now - entry.lastSeen > maxOfflineDuration) {
          delete this.#persistentMacCache[mac];
        }
      }
    }

    const aggregatedDevices = Array.from(allDevicesMap.values()).map((records) => {
      const device = this.#processDeviceRecords(records, now);
      if (!device) return null;

      device.connected = true;
      return device;
    }).filter((d) => d !== null);

    // Add offline devices from cache
    const onlineMacs = new Set(aggregatedDevices.map((d) => d.mac));
    const registeredRouterIdsSet = new Set(registeredRouterIds);

    for (const [mac, device] of Object.entries(this.#persistentMacCache)) {
      if (!onlineMacs.has(mac)) {
        let isConnected = false;
        let { connectedVia } = device;

        // During startup (first 2 mins), if the router responsible for this device hasn't reported yet,
        // preserve the last known state to prevent false disconnect triggers.
        const isStartup = (now - this.#startupTime) < 120000;
        const routerHasReported = this.#multiRouterCache[device.routerId];
        const routerExists = registeredRouterIdsSet.has(device.routerId);

        if (isStartup && routerExists && !routerHasReported) {
          isConnected = device.connected;
        } else {
          connectedVia = 'disconnected';
        }
        aggregatedDevices.push({ ...device, connected: isConnected, connectedVia });
      }
    }

    aggregatedDevices.sort((a, b) => b.lastSeen - a.lastSeen);
    this.#knownDevices = aggregatedDevices;
    return this.#knownDevices;
  }

  // 3. CONNECTION
  /**
   * Checks if the SSH session is currently logged in.
   * @returns {boolean} True if logged in.
   */
  get loggedIn() {
    return this.#sshStatus === 'logged_in';
  }

  /**
   * Establishes an SSH connection to the router.
   * @returns {Promise<void>}
   * @throws {Error} If login fails.
   */
  async login() {
    try {
      await this._connectSsh();
      await this._execSsh('echo "Login successful"');
    } catch (e) {
      throw new Error(`SSH login failed: ${e.message}`);
    }
  }

  /**
   * Closes the SSH connection.
   * @returns {Promise<void>}
   */
  async logout() {
    return this._disconnectSsh();
  }

  // 4. CORE INFO
  /**
   * Retrieves static or semi-static router information.
   * This includes hardware info, LAN configuration, and WiFi topology.
   * @returns {Promise<object>} Static router information object.
   * @example
   * {
   *   uniqueId: '00:11:22:33:44:55',
   *   ip: '192.168.1.1',
   *   mac: '00:11:22:33:44:55',
   *   isInternetRouter: true,
   *   isDhcpServer: true,
   *   isFirewall: true,
   *   isAp: true,
   *   isNlbwmonInstalled: true,
   *   model: 'Linksys WRT3200ACM',
   *   firmwareVersion: '21.02.0',
   *   luciVersion: 'git-21.284.67084-e4d24f0',
   *   architecture: 'ARMv7 Processor rev 1 (v7l)',
   *   kernelVersion: '5.4.143',
   *   hostname: 'OpenWrt',
   *   totalMemory: 512000,
   *   totalMemoryMB: '500',
   *   wan: {
   *     up: null,
   *     uptime: null,
   *     ipAddress: '203.0.113.1',
   *     macAddress: '00:11:22:33:44:56',
   *     protocol: 'dhcp',
   *     gateway: '203.0.113.254',
   *     dnsServers: ['8.8.8.8', '1.1.1.1'],
   *     bridge: null,
   *     stats: null
   *   },
   *   networks: {
   *     lan: {
   *       ipAddress: '192.168.1.1',
   *       macAddress: '00:11:22:33:44:55',
   *       gateway: null,
   *       dnsServers: [],
   *       device: 'br-lan',
   *       protocol: 'static',
   *       up: true,
   *       ports: ['eth0', 'wlan0']
   *     }
   *   },
   *   wifi: [
   *     {
   *       radio: 'radio0',
   *       channel: 36,
   *       country: 'US',
   *       frequency: 5180,
   *       tx_power: 20,
   *       noise: -90,
   *       snr: null,
   *       bitrate: null,
   *       clientCount: 0,
   *       interfaces: [
   *         {
   *           interface: 'wlan0',
   *           ssid: 'MyWiFi',
   *           mode: 'Master',
   *           disabled: false,
   *           bssid: null,
   *           signal: null,
   *           snr: null,
   *           bitrate: null,
   *           clientCount: 0,
   *           network: ['lan'],
   *           bridge: 'br-lan'
   *         }
   *       ]
   *     }
   *   ],
   *   port: {
   *     clientCount: 0,
   *     'eth0': {
   *       type: 'ethernet',
   *       macAddress: '00:11:22:33:44:55',
   *       duplex: 'full',
   *       connectedDevices: [],
   *       clientCount: 0,
   *       bridge: 'br-lan',
   *       ipAddresses: [],
   *       ip6Addresses: []
   *     }
   *   }
   * }
   */
  async getStaticRouterInfo() {
    const SEP = '___SEP___';
    const cmd = [
      `echo "${SEP}BOARD"`, 'ubus call system board || true',
      `echo "${SEP}UCI_LAN"`, "ubus call uci get '{\"config\":\"network\",\"section\":\"lan\"}' || true",
      `echo "${SEP}UCI_NET"`, "ubus call uci get '{\"config\":\"network\"}' || true",
      `echo "${SEP}IP_ROUTE_GET"`, 'ip route get 1 2>/dev/null; ip addr show br-lan 2>/dev/null || true',
      `echo "${SEP}UCI_WIFI"`, "ubus call uci get '{\"config\":\"wireless\"}' || true",
      `echo "${SEP}ETH0_MAC"`, 'cat /sys/class/net/eth0/address || true',
      `echo "${SEP}UCI_DHCP"`, "ubus call uci get '{\"config\":\"dhcp\"}' || true",
      `echo "${SEP}UCI_FW"`, "ubus call uci get '{\"config\":\"firewall\"}' || true",
      `echo "${SEP}FW_STATUS"`, '/etc/init.d/firewall status || true',
      `echo "${SEP}IW_DEVS"`, 'ubus call iwinfo devices || true',
      `echo "${SEP}NET_WIFI"`, 'ubus call network.wireless status || true',
      `echo "${SEP}NET_DUMP"`, 'ubus call network.interface dump || true',
      `echo "${SEP}SYS_INFO"`, 'ubus call system info || true',
      `echo "${SEP}OPKG"`, '(opkg list-installed luci-base luci-app-nlbwmon nlbwmon || apk list -I luci-base luci-app-nlbwmon nlbwmon) 2>/dev/null || true;'
      + ' test -x /usr/sbin/nlbw && echo "nlbwmon_exec" || true',
      `echo "${SEP}ETHERWAKE"`, '(opkg list-installed etherwake || apk list -I etherwake) 2>/dev/null || true;'
      + ' (command -v ether-wake || which ether-wake || test -x /usr/bin/ether-wake || test -x /usr/sbin/ether-wake) && echo "etherwake_exec" || true',
      `echo "${SEP}LAN_DEVS"`, 'for d in /sys/class/net/*; do echo "DEV:$(basename $d)"; cat $d/address 2>/dev/null || echo "";'
      + ' echo "SPEED"; cat $d/speed 2>/dev/null || echo ""; echo "DUPLEX"; cat $d/duplex 2>/dev/null || echo ""; done',
      `echo "${SEP}BR_PORTS"`, 'grep . /sys/class/net/*/brif/*/port_no 2>/dev/null || true',
      `echo "${SEP}BRIDGE_VLAN"`, 'bridge vlan show 2>/dev/null || /usr/sbin/bridge vlan show 2>/dev/null || /sbin/bridge vlan show 2>/dev/null || true',
      `echo "${SEP}BRIDGE_FDB"`, 'bridge fdb show 2>/dev/null || /usr/sbin/bridge fdb show 2>/dev/null || true',
      `echo "${SEP}IP_ROUTE_DEF"`, 'ip route show default 2>/dev/null || true',
      `echo "${SEP}IP_NEIGH"`, 'ip neigh show 2>/dev/null || true',
      `echo "${SEP}HOSTS"`, 'cat /etc/hosts || true',
    ].join('; ');

    let output = '';
    try {
      output = await this._execSsh(cmd);
    } catch (e) {
      // ignore
    }

    const sections = {};
    const parts = output.split(SEP);
    for (const part of parts) {
      const newlineIdx = part.indexOf('\n');
      if (newlineIdx !== -1) {
        const key = part.substring(0, newlineIdx).trim();
        const content = part.substring(newlineIdx + 1);
        if (key) sections[key] = content;
      }
    }

    const board = JSON.parse(sections.BOARD || '{}');
    const lanConfig = JSON.parse(sections.UCI_LAN || '{}');
    const uciNetwork = JSON.parse(sections.UCI_NET || '{}');
    const ipAddrOutput = sections.IP_ROUTE_GET || '';
    const wirelessConfig = JSON.parse(sections.UCI_WIFI || '{}');
    const eth0MacOutput = sections.ETH0_MAC || '';
    const dhcpConfig = JSON.parse(sections.UCI_DHCP || '{}');
    const uciFirewall = JSON.parse(sections.UCI_FW || '{}');
    const firewallStatusOutput = sections.FW_STATUS || '';
    const iwinfoDevices = JSON.parse(sections.IW_DEVS || '{}');
    const wirelessStatus = JSON.parse(sections.NET_WIFI || '{}');
    const interfaceDump = JSON.parse(sections.NET_DUMP || '{}');
    const systemInfo = JSON.parse(sections.SYS_INFO || '{}');
    const luciOutput = sections.OPKG || '';
    const etherwakeOutput = sections.ETHERWAKE || '';
    const bridgeVlanOutput = sections.BRIDGE_VLAN || '';
    const hostsMap = this._parseHosts(sections.HOSTS);
    const fdbOutput = sections.BRIDGE_FDB || '';
    const neighOutput = sections.IP_NEIGH || '';

    let lanIp = lanConfig.values?.ipaddr;
    let lanMac;

    const macMatch = ipAddrOutput.match(/link\/ether (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})/);
    if (macMatch) {
      lanMac = macMatch[1].toUpperCase();
    }

    // Fallbacks
    if (!lanMac) lanMac = lanConfig.values?.macaddr;
    if (!lanMac) lanMac = board.network?.lan?.mac;
    if (!lanMac && eth0MacOutput) lanMac = eth0MacOutput.trim().toUpperCase();

    // Fallback for LAN IP (e.g. if DHCP client)
    if (!lanIp && interfaceDump && interfaceDump.interface) {
      const lanIface = interfaceDump.interface.find((iface) => iface.interface === 'lan');
      if (lanIface && lanIface['ipv4-address'] && lanIface['ipv4-address'].length > 0) {
        lanIp = lanIface['ipv4-address'][0].address;
      }
    }
    if (!lanIp && ipAddrOutput) {
      const srcMatch = ipAddrOutput.match(/src\s+([0-9.]+)/);
      if (srcMatch) {
        lanIp = srcMatch[1];
      } else {
        const ipMatch = ipAddrOutput.match(/inet\s+([0-9.]+)\//);
        if (ipMatch) lanIp = ipMatch[1];
      }
    }

    let isDHCPserver = false;
    if (dhcpConfig && dhcpConfig.values) {
      for (const section of Object.values(dhcpConfig.values)) {
        if (section['.type'] === 'dhcp' && section.ignore !== '1') {
          isDHCPserver = true;
          break;
        }
      }
    }
    const isFirewall = /\bactive\b/.test(firewallStatusOutput);

    let wan = {};
    if (interfaceDump && interfaceDump.interface) {
      wan = interfaceDump.interface.find((iface) => iface.interface === 'wan') || {};
    }
    const wanInterfaces = [];
    if (wan.device) wanInterfaces.push(wan.device);
    if (wan.l3_device) wanInterfaces.push(wan.l3_device);
    const isInternetRouter = !!(wan?.up && wan?.route?.[0]?.nexthop);
    const wanIp = wan['ipv4-address']?.[0]?.address;
    const wanMac = wan?.macaddr;
    const wanProto = wan?.proto;
    const wanDns = wan['dns-server'];
    const totalMemory = systemInfo.memory?.total;
    const totalMemoryMB = totalMemory ? Math.round(totalMemory / 1048576).toString() : null;

    let luciVersion = null;
    if (luciOutput) {
      const matchOpkg = luciOutput.match(/luci-base\s+-\s+(.+)/);
      const matchApk = luciOutput.match(/luci-base-([^\s]+)/);
      if (matchOpkg) {
        luciVersion = matchOpkg[1].trim();
      } else if (matchApk) {
        luciVersion = matchApk[1].trim();
      }
    }
    const isNlbwmonInstalled = luciOutput.includes('nlbwmon') || luciOutput.includes('nlbwmon_exec');
    const isEtherWakeInstalled = etherwakeOutput.includes('etherwake') || etherwakeOutput.includes('etherwake_exec');

    const ifaceToRadio = new Map();
    const ifaceToNetwork = new Map();
    if (wirelessStatus) {
      Object.entries(wirelessStatus).forEach(([radio, status]) => {
        if (status.interfaces) {
          status.interfaces.forEach((iface) => {
            if (iface.ifname) {
              ifaceToRadio.set(iface.ifname, radio);
              if (iface.config && iface.config.network) ifaceToNetwork.set(iface.ifname, iface.config.network);
            }
          });
        }
      });
    }

    let isAP = false;
    const disabledRadios = [];
    if (wirelessConfig && wirelessConfig.values) {
      for (const section of Object.values(wirelessConfig.values)) {
        if (section['.type'] === 'wifi-iface') {
          if (section.mode === 'ap') isAP = true;
          if (section.disabled === '1') {
            disabledRadios.push({
              interface: section.device,
              radio: section.device,
              ssid: section.ssid,
              mode: section.mode,
              disabled: true,
              network: section.network,
            });
          }
        }
      }
    }

    const wifiInterfaces = iwinfoDevices.devices || [];

    const radioInfos = [];
    if (wifiInterfaces.length > 0) {
      const separator = '___SEP___';
      const cmd = wifiInterfaces.map((iface) => `echo "IFACE:${iface}"; ubus call iwinfo info '{"device":"${iface}"}' || true`).join(`; echo "${separator}"; `);

      try {
        const output = await this._execSsh(cmd);
        const parts = output.split(separator);
        for (const part of parts) {
          const trimmed = part.trim();
          if (!trimmed) continue;
          const match = trimmed.match(/^IFACE:(.+?)\s+([\s\S]*)$/);
          if (match) {
            const iface = match[1].trim();
            const jsonStr = match[2].trim();
            try {
              const info = JSON.parse(jsonStr);
              radioInfos.push({ ...info, device: iface });
            } catch (e) {
              // ignore
            }
          }
        }
      } catch (e) {
        // ignore
      }
    }

    if (!isAP && radioInfos.length > 0) {
      const apModes = ['Master', 'ap'];
      if (radioInfos.some((r) => apModes.includes(r.mode))) {
        isAP = true;
      }
    }

    const radioGroups = new Map();
    const getRadioGroup = (name) => {
      if (!radioGroups.has(name)) {
        radioGroups.set(name, {
          radio: name,
          channel: null,
          country: null,
          frequency: null,
          tx_power: null,
          noise: null,
          snr: null,
          bitrate: null,
          clientCount: 0,
          interfaces: [],
        });
      }
      return radioGroups.get(name);
    };

    const portToBridge = this._parseBridgePorts(sections.BR_PORTS || '');

    for (const r of radioInfos) {
      const radioName = ifaceToRadio.get(r.device) || 'unknown';
      const group = getRadioGroup(radioName);

      if (r.channel != null) group.channel = r.channel;
      if (r.country) group.country = r.country;
      if (r.frequency != null) group.frequency = r.frequency;
      if (r.txpower != null) group.txPower = r.txpower;
      if (r.noise != null) group.noise = r.noise;

      group.interfaces.push({
        interface: r.device,
        ssid: r.ssid,
        bssid: r.bssid,
        mode: r.mode,
        signal: null,
        snr: null,
        bitrate: null,
        clientCount: 0,
        connectedDevices: [],
        network: ifaceToNetwork.get(r.device) || null,
        bridge: portToBridge.get(r.device) || null,
        disabled: false,
      });
    }

    for (const d of disabledRadios) {
      const group = getRadioGroup(d.radio);
      group.interfaces.push({
        interface: d.interface,
        ssid: d.ssid,
        mode: d.mode,
        disabled: true,
        bssid: null,
        signal: null,
        snr: null,
        bitrate: null,
        clientCount: 0,
        connectedDevices: [],
        network: d.network,
        bridge: portToBridge.get(d.interface) || null,
      });
    }

    const wifi = Array.from(radioGroups.values());

    const networks = this._parseNetworks(interfaceDump, portToBridge, wifi, bridgeVlanOutput, uciNetwork);

    const capabilities = {
      hasIpNeigh: neighOutput.includes('lladdr'),
      hasBridgeFdb: fdbOutput.includes('dev') || fdbOutput.includes('master') || fdbOutput.includes('self'),
    };

    const broadcastIps = [];
    for (const net of Object.values(networks)) {
      const bcast = this._calculateBroadcast(net.ipAddress, net.mask);
      if (bcast) broadcastIps.push(bcast);
    }

    if (this.#pingCheck && !isDHCPserver && broadcastIps.length > 0) {
      const pingCmd = broadcastIps.map((ip) => `ping -c 1 -W 1 -b ${ip} >/dev/null 2>&1 &`).join('; ');
      await this._execSsh(pingCmd).catch(() => {});
    }

    const networkToZone = {};
    if (uciFirewall && uciFirewall.values) {
      for (const section of Object.values(uciFirewall.values)) {
        if (section['.type'] === 'zone' && section.name && section.network) {
          const nets = Array.isArray(section.network) ? section.network : section.network.split(/\s+/);
          for (const net of nets) {
            if (net) networkToZone[net] = section.name;
          }
        }
      }
    }

    // --- Build Static LAN Info ---
    const staticLanInfo = {};
    const lanDevsOutput = sections.LAN_DEVS || '';
    const brPortsOutput = sections.BR_PORTS || '';
    const routeDefOutput = sections.IP_ROUTE_DEF || '';

    // Identify Gateway for Uplink detection
    let gatewayMac = null;
    let gatewayIface = null;
    let gatewayIp = null;
    const routeMatch = routeDefOutput.match(/default via ([0-9.]+)(?: dev ([^\s]+))?/);
    if (routeMatch) {
      gatewayIp = routeMatch[1];
      gatewayIface = routeMatch[2];
      // Find gateway MAC in neigh output
      const neighLines = neighOutput.split('\n');
      for (const line of neighLines) {
        if (line.startsWith(gatewayIp)) {
          const neighMatch = line.match(/lladdr\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})/);
          if (neighMatch) gatewayMac = neighMatch[1].toUpperCase();
          break;
        }
      }
    }

    const devParts = lanDevsOutput.split('DEV:');
    for (const part of devParts) {
      const lines = part.trim().split('\n');
      if (lines.length >= 1) {
        const deviceName = lines[0].trim();
        if (!deviceName) continue;
        const macAddress = lines[1] ? lines[1].trim().toUpperCase() : null;
        const speedLineIdx = lines.indexOf('SPEED');
        let speed = null;
        if (speedLineIdx !== -1 && lines[speedLineIdx + 1]) {
          const s = parseInt(lines[speedLineIdx + 1].trim(), 10);
          if (!Number.isNaN(s) && s > 0) speed = s;
        }

        const duplexLineIdx = lines.indexOf('DUPLEX');
        let duplex = null;
        if (duplexLineIdx !== -1 && lines[duplexLineIdx + 1]) {
          const d = lines[duplexLineIdx + 1].trim();
          if (d) duplex = d;
        }

        staticLanInfo[deviceName] = {
          macAddress,
          speed,
          duplex,
        };
      }
    }

    // Calculate initial LAN Info
    const lanInfo = this._parseLanInfo({
      staticLanInfo,
      gatewayMac,
      gatewayIface,
      interfaceDump,
      wifiInterfaces,
      wanInterfaces,
      brPortsOutput,
      networks,
      portToBridge,
    });

    this.#staticRouterInfo = {
      uniqueId: lanMac,
      ip: lanIp,
      mac: lanMac,
      isInternetRouter,
      isDhcpServer: isDHCPserver,
      isFirewall,
      isAp: isAP,
      isNlbwmonInstalled,
      isEtherWakeInstalled,
      model: board?.model,
      firmwareVersion: board?.release?.version,
      luciVersion,
      architecture: board?.system,
      kernelVersion: board?.kernel,
      hostname: board?.hostname,
      uptime: null,
      localtime: null,
      loadAverage: null,
      temperature: null,
      cpuUsage: null,
      totalMemory,
      totalMemoryMB,
      memory: {
        free: null,
        available: null,
        usage: null,
      },
      wan: {
        up: null,
        uptime: null,
        ipAddress: wanIp,
        macAddress: wanMac?.toUpperCase(),
        protocol: wanProto,
        gateway: wan?.route?.[0]?.nexthop,
        dnsServers: wanDns,
        stats: null,
        bridge: portToBridge.get(wan.device) || null,
      },
      networks,
      wifi,
      ...lanInfo,
      staticLanInfo,
      gatewayMac,
      gatewayIface,
      gatewayIp,
      portToBridge,
      brPortsOutput,
      bridgeVlanOutput,
      wifiInterfaces,
      uciNetwork,
      hostsMap,
      capabilities,
      wanInterfaces,
      broadcastIps,
      networkToZone,
    };

    return this.#staticRouterInfo;
  }

  /**
   * Retrieves general router information including system stats, network status, and hardware info.
   * @returns {Promise<object>} Router information object.
   * @example
   * {
   *   uniqueId: '00:11:22:33:44:55',
   *   ip: '192.168.1.1',
   *   mac: '00:11:22:33:44:55',
   *   isInternetRouter: true,
   *   isDhcpServer: true,
   *   isFirewall: true,
   *   isAp: true,
   *   model: 'Linksys WRT3200ACM',
   *   firmwareVersion: '21.02.0',
   *   luciVersion: 'git-21.284.67084-e4d24f0',
   *   architecture: 'ARMv7 Processor rev 1 (v7l)',
   *   kernelVersion: '5.4.143',
   *   hostname: 'OpenWrt',
   *   uptime: 12345,
   *   localtime: 2023-10-27T10:00:00.000Z, // Date object
   *   loadAverage: [6553, 3200, 1024], // Raw load values
   *   temperature: 45.5,
   *   cpuUsage: 12,
   *   totalMemory: 512000,
   *   totalMemoryMB: '500',
   *   memory: {
   *     free: 200000,
   *     available: 250000,
   *     usage: 51
   *   },
   *   wan: {
   *     up: true,
   *     uptime: 12300,
   *     ipAddress: '203.0.113.1',
   *     macAddress: '00:11:22:33:44:56',
   *     protocol: 'dhcp',
   *     gateway: '203.0.113.254',
   *     dnsServers: ['8.8.8.8', '1.1.1.1'],
   *     bridge: null,
   *     stats: {
   *       rxBytes: 123456789,
   *       txBytes: 987654321
   *     }
   *   },
   *   networks: {
   *     lan: {
   *       ipAddress: '192.168.1.1',
   *       macAddress: '00:11:22:33:44:55',
   *       gateway: null,
   *       dnsServers: [],
   *       device: 'br-lan',
   *       protocol: 'static',
   *       up: true,
   *       ports: ['eth0', 'wlan0']
   *     }
   *   },
   *   wifi: [
   *     {
   *       radio: 'radio0',
   *       channel: 36,
   *       country: 'US',
   *       frequency: 5180,
   *       txPower: 20,
   *       noise: -90,
   *       snr: 40,
   *       bitrate: 1200,
   *       clientCount: 5,
   *       interfaces: [
   *         {
   *           interface: 'wlan0',
   *           ssid: 'MyWiFi',
   *           bssid: '00:11:22:33:44:55',
   *           mode: 'Master',
   *           signal: -50,
   *           snr: 40,
   *           bitrate: 1200,
   *           disabled: false,
   *           clientCount: 5,
   *           network: ['lan'],
   *           bridge: 'br-lan'
   *         }
   *       ]
   *     }
   *   ],
   *   port: {
   *     clientCount: 0,
   *     'eth0': {
   *       type: 'ethernet',
   *       macAddress: '00:11:22:33:44:55',
   *       connectedDevices: [],
   *       clientCount: 0,
   *       bridge: 'br-lan',
   *       ipAddresses: [],
   *       ip6Addresses: []
   *     }
   *   }
   * }
   */
  async getRouterInfo() {
    if (!this.#staticRouterInfo) await this.getStaticRouterInfo();
    const {
      uniqueId, ip: staticIp, mac: staticMac, wifi: staticWifi, wan: staticWan, staticLanInfo, gatewayMac, gatewayIface,
      isDhcpServer, isFirewall, isAp,
      model, firmwareVersion, architecture, kernelVersion, hostname, totalMemory, totalMemoryMB, luciVersion,
    } = this.#staticRouterInfo;
    const staticSystem = {
      model,
      firmwareVersion,
      luciVersion,
      architecture,
      kernelVersion,
      hostname,
    };

    const ifaceToRadio = new Map();
    const ifaceToNetwork = new Map();
    const wifiInterfaces = [];
    const disabledRadios = [];

    for (const group of staticWifi) {
      for (const iface of group.interfaces) {
        if (iface.interface) {
          ifaceToRadio.set(iface.interface, group.radio);
          if (iface.network) ifaceToNetwork.set(iface.interface, iface.network);
        }
        if (iface.disabled) {
          disabledRadios.push({
            interface: iface.interface,
            radio: group.radio,
            ssid: iface.ssid,
            mode: iface.mode,
            disabled: true,
            network: iface.network,
          });
        } else {
          wifiInterfaces.push(iface.interface);
        }
      }
    }

    const SEP = '___SEP___';
    const commands = [
      `echo "${SEP}SYS"`, 'ubus call system info || true',
      `echo "${SEP}NET"`, 'ubus call network.interface dump || true',
      `echo "${SEP}TEMP"`, 'cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || true',
      `echo "${SEP}CPU"`, "grep '^cpu ' /proc/stat || true",
      `echo "${SEP}TRAFFIC"`, 'cat /proc/net/dev || true',
      `echo "${SEP}BRIDGE_FDB"`, 'bridge fdb show 2>/dev/null || /usr/sbin/bridge fdb show 2>/dev/null || true',
      `echo "${SEP}BRCTL_MACS"`, 'for b in /sys/class/net/br-*; do echo "BR:$b"; brctl showmacs $(basename $b) 2>/dev/null || true; done',
    ];

    if (wifiInterfaces.length > 0) {
      wifiInterfaces.forEach((iface) => {
        commands.push(`echo "${SEP}WIFI:${iface}"`);
        commands.push(`ubus call iwinfo info '{"device":"${iface}"}' || true`);
        if (isAp) {
          commands.push(`echo "${SEP}WIFI_ASSOC:${iface}"`);
          commands.push(`ubus call iwinfo assoclist '{"device":"${iface}"}' || true`);
        }
      });
    }

    const cmd = commands.join('; ');

    let output = '';
    try {
      output = await this._execSsh(cmd);
    } catch (e) {
      // ignore
    }

    const sections = {};
    const parts = output.split(SEP);
    for (const part of parts) {
      const newlineIdx = part.indexOf('\n');
      if (newlineIdx !== -1) {
        const key = part.substring(0, newlineIdx).trim();
        const content = part.substring(newlineIdx + 1);
        if (key) sections[key] = content;
      }
    }

    const system = JSON.parse(sections.SYS || '{}');
    const interfaceDump = JSON.parse(sections.NET || '{}');
    const tempOutput = sections.TEMP || '';
    const cpuOutput = sections.CPU || '';
    const trafficOutput = sections.TRAFFIC || '';
    const fdbOutput = sections.BRIDGE_FDB || '';
    const brctlOutput = sections.BRCTL_MACS || '';

    const { portToBridge, brPortsOutput, bridgeVlanOutput } = this.#staticRouterInfo;

    let wan = {};
    if (interfaceDump && interfaceDump.interface) {
      wan = interfaceDump.interface.find((iface) => iface.interface === 'wan') || {};
    }
    const wanInterfaces = [];
    if (wan.device) wanInterfaces.push(wan.device);
    if (wan.l3_device) wanInterfaces.push(wan.l3_device);

    const wifiData = new Map();
    for (const [key, content] of Object.entries(sections)) {
      if (key.startsWith('WIFI:')) {
        const iface = key.substring(5);
        if (!wifiData.has(iface)) wifiData.set(iface, {});
        try {
          wifiData.get(iface).info = JSON.parse(content);
        } catch (e) { /* ignore */ }
      } else if (key.startsWith('WIFI_ASSOC:')) {
        const iface = key.substring(11);
        if (!wifiData.has(iface)) wifiData.set(iface, {});
        try {
          wifiData.get(iface).assoc = JSON.parse(content);
        } catch (e) { /* ignore */ }
      }
    }

    const radioInfos = [];
    for (const [iface, data] of wifiData) {
      if (data.info) {
        const clientCount = data.assoc?.results?.length || 0;
        const connectedDevices = data.assoc?.results?.map((c) => c.mac) || [];
        radioInfos.push({
          ...data.info, device: iface, clientCount, connectedDevices,
        });
      }
    }

    const trafficStats = this._parseProcNetDev(trafficOutput);

    const routerInfo = await this._buildRouterInfoObject({
      system,
      interfaceDump,
      tempOutput,
      cpuOutput,
      trafficStats,
      radioInfos,
      disabledRadios,
      ifaceToRadio,
      ifaceToNetwork,
      staticSystem,
      staticIp,
      staticMac,
      staticWan,
      uniqueId,
      isDhcpServer,
      isFirewall,
      isAp,
      totalMemory,
      totalMemoryMB,
      portToBridge,
      bridgeVlanOutput,
      uciNetwork: this.#staticRouterInfo.uciNetwork,
    });

    // Build LAN Info
    const lanInfo = this._parseLanInfo({
      staticLanInfo,
      gatewayMac,
      gatewayIface,
      fdbOutput,
      portToBridge,
      brPortsOutput,
      brctlOutput,
      interfaceDump,
      trafficStats,
      wifiInterfaces,
      wanInterfaces,
      networks: routerInfo.networks,
    });
    Object.assign(routerInfo, lanInfo);

    let totalClientCount = 0;
    if (routerInfo.wifi) {
      for (const radio of routerInfo.wifi) {
        totalClientCount += radio.clientCount;
      }
    }
    if (routerInfo.port) {
      totalClientCount += routerInfo.port.clientCount;
    }
    if (routerInfo.bridge) {
      totalClientCount += routerInfo.bridge.clientCount;
    }
    routerInfo.totalClientCount = totalClientCount;

    return routerInfo;
  }

  /**
   * Retrieves a list of devices currently attached to the router.
   * Combines DHCP leases, ARP table, wireless clients, and nlbwmon traffic data.
   * @returns {Promise<Array<object>>} List of device objects.
   * @example
   * [
   *   {
   *     routerId: '00:11:22:33:44:55',
   *     routerName: 'OpenWrt',
   *     ip: '192.168.1.150',
   *     mac: 'AA:BB:CC:DD:EE:FF',
   *     name: 'MyPhone',
   *     onlineSince: 1698410000000,
   *     onlineForSeconds: 3600,
   *     lastSeen: 1698413600000,
   *     source: 'arp+iwinfo',
   *     interface: 'wlan0',
   *     linkSpeed: null,
   *     connectedVia: 'wifi',
   *     network: ['lan'],
   *     bridge: 'br-lan',
   *     port: 'MyHomeWiFi',
   *     wifi: {
   *       ssid: 'MyHomeWiFi',
   *       signal: -55,
   *       noise: -95,
   *       snr: 40,
   *       inactiveTime: 120,
   *       rxRate: 866600,
   *       rxMcs: 9,
   *       rxChannelWidth: 80,
   *       rxPackets: 15000,
   *       txRate: 866600,
   *       txMcs: 9,
   *       txChannelWidth: 80,
   *       txPackets: 12000,
   *       txShortGi: 1
   *     },
   *     traffic: {
   *       rxBytes: 10485760,
   *       txBytes: 5242880,
   *       connections: {
   *         total: 15,
   *         https: 10,
   *         dns: 5
   *       }
   *     }
   *   }
   * ]
   */
  async getAttachedDevices() {
    if (!this.#staticRouterInfo) await this.getStaticRouterInfo();
    const {
      isDhcpServer, isNlbwmonInstalled, capabilities, isAp, staticWifi, wanInterfaces, gatewayIp,
    } = this.#staticRouterInfo;

    const wifiInterfaces = [];
    if (staticWifi) {
      for (const group of staticWifi) {
        for (const iface of group.interfaces) {
          if (!iface.disabled && iface.interface) {
            wifiInterfaces.push(iface.interface);
          }
        }
      }
    } else {
      wifiInterfaces.push(...(this.#staticRouterInfo.wifiInterfaces || []));
    }

    const SEP = '___SEP___';
    const commands = [];

    if (isDhcpServer) {
      commands.push(`echo "${SEP}DHCP"`, 'cat /tmp/dhcp.leases || true');
    }
    if (isNlbwmonInstalled) {
      commands.push(`echo "${SEP}NLBW"`, '/usr/sbin/nlbw -c json || nlbw -c json || true');
    }

    commands.push(
      `echo "${SEP}ARP_NEIGH"`, 'ip neigh || true',
      `echo "${SEP}BRIDGE_FDB"`, 'bridge fdb show 2>/dev/null || /usr/sbin/bridge fdb show 2>/dev/null || true',
    );

    if (!capabilities?.hasIpNeigh) {
      commands.push(`echo "${SEP}ARP_PROC"`, 'cat /proc/net/arp || true');
    }
    if (!capabilities?.hasBridgeFdb) {
      commands.push(`echo "${SEP}BRCTL_MACS"`, 'for b in /sys/class/net/br-*; do echo "BR:$b"; brctl showmacs $(basename $b) 2>/dev/null || true; done');
    }

    if (wifiInterfaces.length > 0) {
      wifiInterfaces.forEach((iface) => {
        commands.push(`echo "${SEP}WIFI:${iface}"`);
        commands.push(`ubus call iwinfo info '{"device":"${iface}"}' || true`);
        if (isAp) {
          commands.push(`echo "${SEP}WIFI_ASSOC:${iface}"`);
          commands.push(`ubus call iwinfo assoclist '{"device":"${iface}"}' || true`);
        }
      });
    }

    const cmd = commands.join('; ');

    let output = '';
    try {
      output = await this._execSsh(cmd);
    } catch (e) {
      // console.warn('Failed to fetch attached devices data', e);
    }

    const sections = {};
    const parts = output.split(SEP);
    for (const part of parts) {
      const newlineIdx = part.indexOf('\n');
      if (newlineIdx !== -1) {
        const key = part.substring(0, newlineIdx).trim();
        const content = part.substring(newlineIdx + 1);
        if (key) sections[key] = content;
      }
    }

    const fdbOutput = sections.BRIDGE_FDB || '';
    const brctlOutput = sections.BRCTL_MACS || '';
    const { hostsMap } = this.#staticRouterInfo;
    const leaseMap = this._parseDhcpLeases(sections.DHCP);
    const {
      nlbwData,
      connData,
    } = this._parseNlbwmonData(sections.NLBW);

    const wifiInterfaceSsidMap = new Map();

    const now = Date.now();
    const seenThisRun = new Map(); // mac -> { ip, mac, name, source }

    const wifiData = new Map(); // iface -> { info, assoc }
    for (const [key, content] of Object.entries(sections)) {
      if (key.startsWith('WIFI:')) {
        const iface = key.substring(5);
        if (!wifiData.has(iface)) wifiData.set(iface, {});
        try {
          wifiData.get(iface).info = JSON.parse(content);
        } catch (e) { /* ignore */ }
      } else if (key.startsWith('WIFI_ASSOC:')) {
        const iface = key.substring(11);
        if (!wifiData.has(iface)) wifiData.set(iface, {});
        try {
          wifiData.get(iface).assoc = JSON.parse(content);
        } catch (e) { /* ignore */ }
      }
    }

    for (const [iface, data] of wifiData) {
      this._processWirelessClientData(iface, data.info, data.assoc, seenThisRun, leaseMap, hostsMap, wifiInterfaceSsidMap);
    }

    // ARP
    this._parseArpTable(sections.ARP_NEIGH, sections.ARP_PROC, seenThisRun, leaseMap, hostsMap);

    // Refresh Gateway MAC from ARP if possible to improve uplink detection
    let { gatewayMac } = this.#staticRouterInfo;
    if (gatewayIp && sections.ARP_NEIGH) {
      const lines = sections.ARP_NEIGH.trim().split('\n');
      for (const line of lines) {
        if (line.startsWith(gatewayIp)) {
          const match = line.match(/lladdr\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})/);
          if (match) {
            gatewayMac = match[1].toUpperCase();
            break;
          }
        }
      }
    }

    // FDB (Bridge Forwarding Database) - for wired clients on dumb switches/APs
    const fdbMacs = this._parseFdbForDevices(fdbOutput, brctlOutput);

    // 3.5) Try to resolve hostnames via reverse DNS
    const resolutionPromises = [];
    for (const device of seenThisRun.values()) {
      if (device.name === 'unknown' && device.ip !== 'unknown') {
        resolutionPromises.push(
          resolveHostname(device.ip).then((name) => {
            if (name) {
              device.name = name.split('.')[0];
            }
          }),
        );
      }
    }
    if (resolutionPromises.length > 0) {
      await Promise.all(resolutionPromises);
    }

    // Add nlbwmon data to devices
    for (const [mac, device] of seenThisRun) {
      if (nlbwData.has(mac)) {
        const traffic = nlbwData.get(mac);
        device.rxBytes = traffic.rxBytes;
        device.txBytes = traffic.txBytes;
        if (device.ip === 'unknown' && traffic.ip) {
          device.ip = traffic.ip;
        }
      }
      if (connData.has(mac)) {
        device.connections = connData.get(mac);
      }
    }

    // 4) Update cache & 5) Build result list
    const attachedDevices = this._updateDeviceCacheAndBuildList(seenThisRun, now, wifiInterfaceSsidMap, fdbMacs, wifiInterfaces);

    // Build dynamic LAN Info for enrichment (to map wired devices to ports correctly)
    const lanInfo = this._parseLanInfo({
      staticLanInfo: this.#staticRouterInfo.staticLanInfo,
      gatewayMac,
      gatewayIface: this.#staticRouterInfo.gatewayIface,
      fdbOutput,
      portToBridge: this.#staticRouterInfo.portToBridge,
      brPortsOutput: this.#staticRouterInfo.brPortsOutput,
      brctlOutput,
      wifiInterfaces,
      wanInterfaces: wanInterfaces || [],
      networks: this.#staticRouterInfo.networks,
    });

    lanInfo.wifi = this.#staticRouterInfo.wifi;
    lanInfo.networks = this.#staticRouterInfo.networks;
    this._enrichDevicesWithLanInfo(attachedDevices, lanInfo);

    // Filter out upstream devices (always safe to hide uplink/gateway devices)
    return attachedDevices.filter((d) => d.connectedVia !== 'uplink');
  }

  /**
   * Retrieves both router info and attached devices in a single optimized call.
   * @returns {Promise<{routerInfo: object, attachedDevices: Array<object>}>} routerInfo matches getRouterInfo() structure
   * @example
   * {
   *   routerInfo: { ... }, // see getRouterInfo()
   *   attachedDevices: [ ... ] // see getAttachedDevices()
   * }
   */
  async getRouterStatus() {
    if (!this.#staticRouterInfo) await this.getStaticRouterInfo();
    const {
      uniqueId, ip: staticIp, mac: staticMac, wifi: staticWifi, wan: staticWan, staticLanInfo, gatewayMac, gatewayIface, gatewayIp,
      isDhcpServer, isFirewall, isAp, isNlbwmonInstalled, capabilities,
      model, firmwareVersion, architecture, kernelVersion, hostname, totalMemory, totalMemoryMB, luciVersion,
    } = this.#staticRouterInfo;

    const staticSystem = {
      model,
      firmwareVersion,
      luciVersion,
      architecture,
      kernelVersion,
      hostname,
    };

    // --- Wifi Batch (Combined) ---
    const wifiInterfaces = [];
    const disabledRadios = [];
    const ifaceToRadio = new Map();
    const ifaceToNetwork = new Map();

    for (const group of staticWifi) {
      for (const iface of group.interfaces) {
        if (iface.interface) {
          ifaceToRadio.set(iface.interface, group.radio);
          if (iface.network) ifaceToNetwork.set(iface.interface, iface.network);
        }
        if (iface.disabled) {
          disabledRadios.push({
            interface: iface.interface,
            radio: group.radio,
            ssid: iface.ssid,
            mode: iface.mode,
            disabled: true,
            network: iface.network,
          });
        } else {
          wifiInterfaces.push(iface.interface);
        }
      }
    }

    const SEP = '___SEP___';
    const commands = [
      `echo "${SEP}SYS"`, 'ubus call system info || true',
      `echo "${SEP}NET"`, 'ubus call network.interface dump || true',
      `echo "${SEP}TEMP"`, 'cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || true',
      `echo "${SEP}CPU"`, "grep '^cpu ' /proc/stat || true",
      `echo "${SEP}TRAFFIC"`, 'cat /proc/net/dev || true',
      `echo "${SEP}BRIDGE_FDB"`, 'bridge fdb show 2>/dev/null || /usr/sbin/bridge fdb show 2>/dev/null || true',
    ];

    if (isDhcpServer) {
      commands.push(`echo "${SEP}DHCP"`, 'cat /tmp/dhcp.leases || true');
    }
    if (isNlbwmonInstalled) {
      commands.push(`echo "${SEP}NLBW"`, '/usr/sbin/nlbw -c json || nlbw -c json || true');
    }

    if (!capabilities?.hasBridgeFdb) {
      commands.push(`echo "${SEP}BRCTL_MACS"`, 'for b in /sys/class/net/br-*; do echo "BR:$b"; brctl showmacs $(basename $b) 2>/dev/null || true; done');
    }

    commands.push(
      `echo "${SEP}ARP_NEIGH"`, 'ip neigh || true',
    );
    if (!capabilities?.hasIpNeigh) {
      commands.push(`echo "${SEP}ARP_PROC"`, 'cat /proc/net/arp || true');
    }

    if (wifiInterfaces.length > 0) {
      wifiInterfaces.forEach((iface) => {
        commands.push(`echo "${SEP}WIFI:${iface}"`);
        commands.push(`ubus call iwinfo info '{"device":"${iface}"}' || true`);
        if (isAp) {
          commands.push(`echo "${SEP}WIFI_ASSOC:${iface}"`);
          commands.push(`ubus call iwinfo assoclist '{"device":"${iface}"}' || true`);
        }
      });
    }

    const cmd = commands.join('; ');

    let output = '';
    try {
      output = await this._execSsh(cmd);
    } catch (e) {
      // ignore
    }

    const sections = {};
    const parts = output.split(SEP);
    for (const part of parts) {
      const newlineIdx = part.indexOf('\n');
      if (newlineIdx !== -1) {
        const key = part.substring(0, newlineIdx).trim();
        const content = part.substring(newlineIdx + 1);
        if (key) sections[key] = content;
      }
    }

    // --- Process Router Info parts ---
    const system = JSON.parse(sections.SYS || '{}');
    const interfaceDump = JSON.parse(sections.NET || '{}');
    const tempOutput = sections.TEMP || '';
    const cpuOutput = sections.CPU || '';
    const trafficOutput = sections.TRAFFIC || '';
    const fdbOutput = sections.BRIDGE_FDB || '';
    const brctlOutput = sections.BRCTL_MACS || '';

    const { portToBridge, brPortsOutput, bridgeVlanOutput } = this.#staticRouterInfo;

    let wan = {};
    if (interfaceDump && interfaceDump.interface) {
      wan = interfaceDump.interface.find((iface) => iface.interface === 'wan') || {};
    }
    const wanInterfaces = [];
    if (wan.device) wanInterfaces.push(wan.device);
    if (wan.l3_device) wanInterfaces.push(wan.l3_device);

    // --- Process Attached Devices parts ---
    const leaseMap = this._parseDhcpLeases(sections.DHCP);
    const { hostsMap } = this.#staticRouterInfo;
    const {
      nlbwData,
      connData,
    } = this._parseNlbwmonData(sections.NLBW);

    const radioInfos = [];
    const wifiInterfaceSsidMap = new Map();
    const seenThisRun = new Map();
    const now = Date.now();

    const wifiData = new Map(); // iface -> { info, assoc }
    for (const [key, content] of Object.entries(sections)) {
      if (key.startsWith('WIFI:')) {
        const iface = key.substring(5);
        if (!wifiData.has(iface)) wifiData.set(iface, {});
        try {
          wifiData.get(iface).info = JSON.parse(content);
        } catch (e) { /* ignore */ }
      } else if (key.startsWith('WIFI_ASSOC:')) {
        const iface = key.substring(11);
        if (!wifiData.has(iface)) wifiData.set(iface, {});
        try {
          wifiData.get(iface).assoc = JSON.parse(content);
        } catch (e) { /* ignore */ }
      }
    }

    for (const [iface, data] of wifiData) {
      this._processWirelessClientData(iface, data.info, data.assoc, seenThisRun, leaseMap, hostsMap, wifiInterfaceSsidMap);
      if (data.info) {
        const clientCount = data.assoc?.results?.length || 0;
        const connectedDevices = data.assoc?.results?.map((c) => c.mac) || [];
        radioInfos.push({
          ...data.info, device: iface, clientCount, connectedDevices,
        });
      }
    }

    // --- Build Router Info Object ---
    // Reuse logic for WAN, CPU, Memory, Traffic Stats
    const trafficStats = this._parseProcNetDev(trafficOutput);

    const routerInfo = await this._buildRouterInfoObject({
      system,
      interfaceDump,
      tempOutput,
      cpuOutput,
      trafficStats,
      radioInfos,
      disabledRadios,
      ifaceToRadio,
      ifaceToNetwork,
      staticSystem,
      staticIp,
      staticMac,
      staticWan,
      uniqueId,
      isDhcpServer,
      isFirewall,
      isAp,
      totalMemory,
      totalMemoryMB,
      portToBridge,
      bridgeVlanOutput,
      uciNetwork: this.#staticRouterInfo.uciNetwork,
    });

    // Refresh Gateway MAC
    let currentGatewayMac = gatewayMac;
    if (gatewayIp && sections.ARP_NEIGH) {
      const lines = sections.ARP_NEIGH.trim().split('\n');
      for (const line of lines) {
        if (line.startsWith(gatewayIp)) {
          const match = line.match(/lladdr\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})/);
          if (match) {
            currentGatewayMac = match[1].toUpperCase();
            break;
          }
        }
      }
    }

    // Build LAN Info
    const lanInfo = this._parseLanInfo({
      staticLanInfo,
      gatewayMac: currentGatewayMac,
      gatewayIface,
      fdbOutput,
      portToBridge,
      brPortsOutput,
      brctlOutput,
      interfaceDump,
      trafficStats,
      wifiInterfaces,
      wanInterfaces,
      networks: routerInfo.networks,
    });
    Object.assign(routerInfo, lanInfo);

    // --- Build Attached Devices List ---
    this._parseArpTable(sections.ARP_NEIGH, sections.ARP_PROC, seenThisRun, leaseMap, hostsMap);

    const fdbMacs = this._parseFdbForDevices(sections.BRIDGE_FDB, sections.BRCTL_MACS);

    const resolutionPromises = [];
    for (const device of seenThisRun.values()) {
      if (device.name === 'unknown' && device.ip !== 'unknown') {
        resolutionPromises.push(
          resolveHostname(device.ip).then((name) => {
            if (name) {
              device.name = name.split('.')[0];
            }
          }),
        );
      }
    }
    if (resolutionPromises.length > 0) {
      await Promise.all(resolutionPromises);
    }

    for (const [mac, device] of seenThisRun) {
      if (nlbwData.has(mac)) {
        const traffic = nlbwData.get(mac);
        device.rxBytes = traffic.rxBytes;
        device.txBytes = traffic.txBytes;
        if (device.ip === 'unknown' && traffic.ip) {
          device.ip = traffic.ip;
        }
      }
      if (connData.has(mac)) {
        device.connections = connData.get(mac);
      }
    }

    const attachedDevices = this._updateDeviceCacheAndBuildList(seenThisRun, now, wifiInterfaceSsidMap, fdbMacs, wifiInterfaces);
    this._enrichDevicesWithLanInfo(attachedDevices, routerInfo);

    // Filter out upstream devices (always safe to hide uplink/gateway devices)
    const finalDevices = attachedDevices.filter((d) => d.connectedVia !== 'uplink');
    routerInfo.totalClientCount = finalDevices.length;

    return { routerInfo, attachedDevices: finalDevices };
  }

  // 5. ACTIONS & MANAGEMENT
  /**
   * Checks if nlbwmon is installed.
   * @returns {boolean} True if installed.
   */
  get isNlbwmonInstalled() {
    return !!this.#staticRouterInfo?.isNlbwmonInstalled;
  }

  /**
   * Checks if etherwake is installed.
   * @returns {boolean} True if installed.
   */
  get isEtherWakeInstalled() {
    return !!this.#staticRouterInfo?.isEtherWakeInstalled;
  }

  /**
   * Installs the 'luci-app-nlbwmon' package on the router.
   * @returns {Promise<boolean>} True if installed or already present.
   * @throws {Error} If installation fails.
   */
  async installNlbwmon() {
    try {
      let hasApk = false;
      try {
        await this._execSsh('command -v apk');
        hasApk = true;
      } catch (e) {
        // Ignore
      }

      if (hasApk) {
        await this._execSsh('apk update');
        await this._execSsh('apk add luci-app-nlbwmon');
        return true;
      }

      await this._execSsh('opkg update');
      const installOutput = await this._execSsh('opkg install luci-app-nlbwmon');
      if (installOutput.includes('is already installed') || installOutput.includes('is up to date')) {
        // console.log('luci-app-nlbwmon is already installed.');
        return true;
      }
      // console.log('luci-app-nlbwmon installation completed successfully.');
      return true;
    } catch (e) {
      // #execSsh rejects on non-zero exit code, which indicates an error for opkg install
      const errorMessage = `Failed to install luci-app-nlbwmon. Reason: ${e.message}`;
      throw new Error(errorMessage);
    }
  }

  /**
   * Installs the 'etherwake' package on the router.
   * @returns {Promise<boolean>} True if installed or already present.
   * @throws {Error} If installation fails.
   */
  async installEtherWake() {
    try {
      let hasApk = false;
      try {
        await this._execSsh('command -v apk');
        hasApk = true;
      } catch (e) {
        // Ignore
      }

      if (hasApk) {
        await this._execSsh('apk update');
        await this._execSsh('apk add etherwake');
        return true;
      }

      await this._execSsh('opkg update');
      const installOutput = await this._execSsh('opkg install etherwake');
      if (installOutput.includes('is already installed') || installOutput.includes('is up to date')) {
        return true;
      }
      return true;
    } catch (e) {
      const errorMessage = `Failed to install etherwake. Reason: ${e.message}`;
      throw new Error(errorMessage);
    }
  }

  /**
   * Sends a Wake-on-LAN packet to a device.
   * @param {string} mac - MAC address of the device.
   * @param {string} [password] - SecureOn password (optional).
   * @returns {Promise<void>}
   */
  async wakeOnLan(mac, password) {
    if (!mac) throw new Error('MAC address is required');

    // Validate MAC
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    if (!macRegex.test(mac)) {
      throw new Error('Invalid MAC address format');
    }

    let cmd = `/usr/bin/ether-wake -b ${mac}`;

    if (password && password !== '00:00:00:00:00:00') {
      if (!macRegex.test(password)) {
        throw new Error('Invalid password format');
      }
      cmd += ` -p ${password}`;
    }

    try {
      await this._execSsh(cmd);
    } catch (e) {
      await this._sendWolNative(mac, password);
    }
  }

  /**
   * Sends a Wake-on-LAN magic packet natively from Homey.
   * Note: This only works if the target device is on the same subnet as Homey.
   * @param {string} mac - MAC address.
   * @param {string} [password] - SecureOn password.
   * @returns {Promise<boolean>}
   */
  _sendWolNative(mac, password) {
    return new Promise((resolve, reject) => {
      try {
        const macParts = mac.replace(/[^0-9a-fA-F]/g, '').match(/.{1,2}/g);
        if (!macParts || macParts.length !== 6) throw new Error('Invalid MAC address');

        // Magic packet structure: 6x FF, 16x MAC, Optional Password (6 bytes)
        const pwdParts = (password && password !== '00:00:00:00:00:00')
          ? password.replace(/[^0-9a-fA-F]/g, '').match(/.{1,2}/g)
          : null;

        const bufferSize = 6 + 16 * 6 + (pwdParts ? 6 : 0);
        const buffer = Buffer.alloc(bufferSize);

        // Header
        buffer.fill(0xff, 0, 6);

        // MAC repetitions
        for (let i = 0; i < 16; i += 1) {
          for (let j = 0; j < 6; j += 1) {
            buffer[6 + i * 6 + j] = parseInt(macParts[j], 16);
          }
        }

        // Password
        if (pwdParts && pwdParts.length === 6) {
          const offset = 6 + 16 * 6;
          for (let j = 0; j < 6; j += 1) {
            buffer[offset + j] = parseInt(pwdParts[j], 16);
          }
        }

        const socket = dgram.createSocket('udp4');
        socket.on('error', (err) => {
          socket.close();
          reject(err);
        });

        socket.bind(() => {
          socket.setBroadcast(true);
          socket.send(buffer, 0, buffer.length, 9, '255.255.255.255', (err) => {
            socket.close();
            if (err) reject(err);
            else resolve(true);
          });
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Enables or disables a WiFi interface by SSID.
   * @param {string} ssid - The SSID of the interface.
   * @param {boolean} enabled - True to enable, false to disable.
   * @param {string} [radioDevice] - Optional radio device name (e.g. radio0).
   * @returns {Promise<void>}
   */
  async setWifiState(ssid, enabled, radioDevice) {
    if (!ssid) throw new Error('SSID is required');

    // Get current config
    const wirelessConfig = await this._ubusSsh('uci', 'get', { config: 'wireless' });

    if (!wirelessConfig || !wirelessConfig.values) {
      throw new Error('Failed to retrieve wireless config');
    }

    const sectionsToUpdate = [];
    const radiosToCheck = new Set();

    for (const [sectionId, section] of Object.entries(wirelessConfig.values)) {
      if (section['.type'] === 'wifi-iface' && section.ssid === ssid) {
        if (radioDevice && section.device !== radioDevice) continue;
        sectionsToUpdate.push(sectionId);
        if (enabled && section.device) {
          radiosToCheck.add(section.device);
        }
      }
    }

    if (sectionsToUpdate.length === 0) {
      const msg = radioDevice
        ? `No WiFi interface found with SSID '${ssid}' on radio '${radioDevice}'`
        : `No WiFi interface found with SSID '${ssid}'`;
      throw new Error(msg);
    }

    // If enabling SSID, ensure the radio is also enabled
    if (enabled) {
      for (const radioName of radiosToCheck) {
        const radioSection = wirelessConfig.values[radioName];
        if (radioSection && radioSection['.type'] === 'wifi-device' && radioSection.disabled === '1') {
          await this._execSsh(`uci set wireless.${radioName}.disabled='0'`);
        }
      }
    }

    for (const sectionId of sectionsToUpdate) {
      const val = enabled ? '0' : '1';
      await this._execSsh(`uci set wireless.${sectionId}.disabled='${val}'`);
    }

    await this._execSsh('uci commit wireless');
    await this._execSsh('wifi reload');
  }

  /**
   * Enables or disables a WiFi radio.
   * @param {string} radio - The radio device name (e.g. radio0).
   * @param {boolean} enabled - True to enable, false to disable.
   * @returns {Promise<void>}
   */
  async setRadioState(radio, enabled) {
    if (!radio) throw new Error('Radio device is required');

    // Get current config
    const wirelessConfig = await this._ubusSsh('uci', 'get', { config: 'wireless' });

    if (!wirelessConfig || !wirelessConfig.values) {
      throw new Error('Failed to retrieve wireless config');
    }

    const section = wirelessConfig.values[radio];
    if (!section || section['.type'] !== 'wifi-device') {
      throw new Error(`Radio '${radio}' not found`);
    }

    const isDisabled = section.disabled === '1';
    const shouldDisable = !enabled;

    if (isDisabled === shouldDisable) return;

    const val = shouldDisable ? '1' : '0';
    await this._execSsh(`uci set wireless.${radio}.disabled='${val}'`);
    await this._execSsh('uci commit wireless');
    await this._execSsh('wifi reload');
  }

  /**
   * Reboots the router.
   * @returns {Promise<void>}
   */
  async reboot() {
    // console.log(`Rebooting router ${this.#host}...`);
    try {
      await this._execSsh('reboot');
      // The SSH connection will be terminated as the router reboots.
      // We can explicitly clear the connection state here.
      this.#sshConnection = null;
      this.#sshStatus = 'logged_out';
      // console.log(`Router ${this.#host} sent reboot command.`);
    } catch (e) {
      // A common error here is 'Disconnected: No more authentication methods available'
      // or 'Client network socket disconnected before secure connection was established'
      // which is expected during a reboot. We'll only log unexpected errors.
      if (!e.message.includes('Disconnected') && !e.message.includes('socket disconnected')) {
        throw new Error(`Failed to send reboot command to ${this.#host}: ${e.message}`);
      }
      // console.log(`Router ${this.#host} sent reboot command (SSH connection expected to drop).`);
      this.#sshConnection = null;
      this.#sshStatus = 'logged_out';
    }
  }

  /**
   * Sets a custom TTL for a specific device.
   * @param {string} mac - MAC address of the device.
   * @param {number} ttl - TTL in seconds.
   */
  setDeviceTTL(mac, ttl) {
    if (!mac) return;
    if (typeof ttl === 'number' && ttl > 0) {
      this.#customDeviceTTLs.set(mac.toUpperCase(), ttl);
    } else {
      this.#customDeviceTTLs.delete(mac.toUpperCase());
    }
  }

  /**
   * Sets access for a device (block or allow).
   * @param {string} mac - MAC address of the device.
   * @param {string} state - 'block' or 'allow'.
   * @param {string} [blockType='wan'] - 'wan', 'lan', or 'all'.
   * @returns {Promise<void>}
   */
  async setDevice(mac, state, blockType = 'wan') {
    if (!mac) {
      throw new Error('MAC address is required.');
    }
    if (state !== 'block' && state !== 'allow') {
      throw new Error('State must be "block" or "allow".');
    }

    const macLower = mac.toLowerCase();
    const macClean = macLower.replace(/:/g, '');
    const dests = (blockType === 'all') ? ['wan', 'lan'] : [blockType];

    // Determine source zones
    let srcZones = ['lan'];
    if (this.#staticRouterInfo && this.#staticRouterInfo.networkToZone) {
      const zones = new Set(Object.values(this.#staticRouterInfo.networkToZone));
      srcZones = Array.from(zones);
    }

    for (const dest of dests) {
      const baseRuleName = `block_${dest}_${macClean}`;

      // 1. Find and delete ALL existing rules for this MAC/Dest (cleanup)
      let existingRules = '';
      try {
        // Search for any rule name starting with the base name
        existingRules = await this._execSsh(`uci show firewall | grep "name='${baseRuleName}"`);
      } catch (e) {
        // grep returns non-zero exit code if no match is found
      }

      if (existingRules) {
        const lines = existingRules.trim().split('\n');
        const ruleIds = new Set();
        for (const line of lines) {
          const match = line.match(/^firewall\.([^.]+)\./);
          if (match) {
            ruleIds.add(match[1]);
          }
        }
        const sortedIds = Array.from(ruleIds).sort((a, b) => {
          const aMatch = a.match(/@rule\[(\d+)\]/);
          const bMatch = b.match(/@rule\[(\d+)\]/);
          if (aMatch && bMatch) {
            return parseInt(bMatch[1], 10) - parseInt(aMatch[1], 10);
          }
          return 0;
        });
        for (const ruleId of sortedIds) {
          try {
            await this._execSsh(`uci delete firewall.${ruleId}`);
          } catch (e) {
            // Ignore
          }
        }
      }

      if (state === 'block') {
        for (const src of srcZones) {
          if (src === dest) continue;

          const ruleName = `${baseRuleName}_src_${src}`;
          const addRuleOutput = await this._execSsh('uci add firewall rule');
          const ruleId = addRuleOutput.trim();

          await this._execSsh(`uci set firewall.${ruleId}.name='${ruleName}'`);
          await this._execSsh(`uci set firewall.${ruleId}.src='${src}'`);
          await this._execSsh(`uci set firewall.${ruleId}.src_mac='${macLower}'`);
          await this._execSsh(`uci set firewall.${ruleId}.dest='${dest}'`);
          await this._execSsh(`uci set firewall.${ruleId}.target='REJECT'`);
          await this._execSsh(`uci set firewall.${ruleId}.enabled='1'`);
        }
      }
    }

    await this._execSsh('uci commit firewall');
    await this._execSsh('/etc/init.d/firewall reload');
  }

  /**
   * Checks if a device is currently blocked.
   * @param {string} mac - MAC address of the device.
   * @returns {Promise<string|boolean>} 'wan', 'lan', 'all', or false.
   */
  async isDeviceBlocked(mac) {
    if (!mac) {
      throw new Error('MAC address is required.');
    }
    const macClean = mac.toLowerCase().replace(/:/g, '');

    try {
      const firewallConfig = await this._ubusSsh('uci', 'get', { config: 'firewall' });
      if (!firewallConfig || !firewallConfig.values) return false;

      let wanBlocked = false;
      let lanBlocked = false;

      for (const section of Object.values(firewallConfig.values)) {
        if (section['.type'] === 'rule' && section.name) {
          if (section.name.startsWith(`block_wan_${macClean}`)) {
            if (section.enabled === '1' || section.enabled === undefined) {
              wanBlocked = true;
            }
          }
          if (section.name.startsWith(`block_lan_${macClean}`)) {
            if (section.enabled === '1' || section.enabled === undefined) {
              lanBlocked = true;
            }
          }
        }
      }

      if (wanBlocked && lanBlocked) return 'all';
      if (wanBlocked) return 'wan';
      if (lanBlocked) return 'lan';
      return false;
    } catch (e) {
      return false;
    }
  }

  // 6. INTERNAL SSH HELPERS
  async _connectSsh() {
    if (this.#sshStatus === 'logged_in' && this.#sshConnection) {
      return Promise.resolve();
    }

    if (this.#sshConnecting) {
      // Wait for the connection to be established
      return new Promise((resolve, reject) => {
        // eslint-disable-next-line homey-app/global-timers
        const checkInterval = setInterval(() => {
          if (this.#sshStatus === 'logged_in') {
            clearInterval(checkInterval);
            resolve();
          } if (this.#sshStatus === 'logged_out' && !this.#sshConnecting) {
            clearInterval(checkInterval);
            reject(new Error('SSH connection failed'));
          }
        }, 100);
      });
    }

    this.#sshConnecting = true;
    this.#sshStatus = 'logging_in';

    return new Promise((resolve, reject) => {
      this.#sshConnection = new Client();
      this.#sshConnection.on('ready', () => {
        this.#sshStatus = 'logged_in';
        this.#sshConnecting = false;
        resolve();
      }).on('error', (err) => {
        this.#sshStatus = 'logged_out';
        this.#sshConnecting = false;
        this.#sshConnection = null;
        reject(err);
      }).connect(this.#sshConfig);
    });
  }

  async _disconnectSsh() {
    return new Promise((resolve) => {
      if (this.#sshConnection) {
        this.#sshConnection.on('close', () => {
          this.#sshStatus = 'logged_out';
          this.#sshConnection = null;
          resolve();
        });
        this.#sshConnection.end();
      } else {
        resolve();
      }
    });
  }

  async _execSsh(command) {
    // New method with promise queue and persistent connection
    const commandPromise = async () => {
      await this._connectSsh();
      return new Promise((resolve, reject) => {
        let stdout = '';
        let stderr = '';
        this.#sshConnection.exec(command, { pty: false }, (err, stream) => {
          if (err) return reject(err);
          stream.on('data', (data) => {
            stdout += data.toString();
          });
          stream.stderr.on('data', (data) => {
            stderr += data.toString();
          });
          stream.on('close', (code) => {
            if (code === 0 || stdout.length > 0) {
              resolve(stdout);
            } else {
              reject(new Error(stderr || `SSH exit code ${code}`));
            }
          });
          return true;
        });
      });
    };

    this.#sshCommandQueue = this.#sshCommandQueue.then(commandPromise, commandPromise);
    return this.#sshCommandQueue;
  }

  async _ubusSsh(object, method, params = {}) {
    const command = `ubus call ${object} ${method} '${JSON.stringify(params)}'`;
    const result = await this._execSsh(command);
    try {
      return JSON.parse(result);
    } catch (e) {
      // ubus call might return non-json on error
      throw new Error(`Failed to parse ubus output for ${object}.${method}: ${result}`);
    }
  }

  // 7. PARSING HELPERS
  async _buildRouterInfoObject({
    system, interfaceDump, tempOutput, cpuOutput, trafficStats, radioInfos, disabledRadios, ifaceToRadio, ifaceToNetwork,
    staticSystem, staticIp, staticMac, uniqueId, staticWan,
    isDhcpServer, isFirewall, isAp, totalMemory, totalMemoryMB, portToBridge, bridgeVlanOutput,
    uciNetwork,
  }) {
    let wan = {};
    if (interfaceDump && interfaceDump.interface) {
      wan = interfaceDump.interface.find((iface) => iface.interface === 'wan') || {};
    }

    const wanIp = wan['ipv4-address']?.[0]?.address || staticWan?.ipAddress;
    const wanMac = wan?.macaddr || staticWan?.macAddress;
    const wanProto = wan?.proto || staticWan?.protocol;
    const wanDns = wan['dns-server'] || staticWan?.dnsServers;
    const wanGateway = wan?.route?.[0]?.nexthop || staticWan?.gateway;
    const isInternetRouter = !!(wan?.up && wan?.route?.[0]?.nexthop);

    let temperature = null;
    if (tempOutput) {
      const tempVal = parseInt(tempOutput.trim(), 10);
      if (!Number.isNaN(tempVal)) {
        temperature = tempVal / 1000;
      }
    }

    let cpuUsage = null;
    if (cpuOutput) {
      const parts = cpuOutput.trim().split(/\s+/);
      if (parts.length >= 5 && parts[0] === 'cpu') {
        const user = parseInt(parts[1], 10) || 0;
        const nice = parseInt(parts[2], 10) || 0;
        const systemVal = parseInt(parts[3], 10) || 0;
        const idle = parseInt(parts[4], 10) || 0;
        const iowait = parseInt(parts[5], 10) || 0;
        const irq = parseInt(parts[6], 10) || 0;
        const softirq = parseInt(parts[7], 10) || 0;
        const steal = parseInt(parts[8], 10) || 0;
        const totalIdle = idle;
        const total = idle + iowait + user + nice + systemVal + irq + softirq + steal;
        if (this.#cpuStatsCache) {
          const prev = this.#cpuStatsCache;
          const totalDiff = total - prev.total;
          const idleDiff = totalIdle - prev.totalIdle;
          if (totalDiff > 0) {
            cpuUsage = Math.round(((totalDiff - idleDiff) / totalDiff) * 100);
          }
        }
        this.#cpuStatsCache = { total, totalIdle };
      }
    }

    let memoryUsage = null;
    if (system?.memory?.total) {
      const used = system.memory.total - (system.memory.available || system.memory.free || 0);
      memoryUsage = Math.round((used / system.memory.total) * 100);
    }

    const radioGroups = new Map();
    const getRadioGroup = (name) => {
      if (!radioGroups.has(name)) {
        radioGroups.set(name, {
          radio: name,
          channel: null,
          country: null,
          frequency: null,
          tx_power: null,
          noise: null,
          snr: null,
          bitrate: null,
          _snrSum: 0,
          _snrCount: 0,
          _bitrateSum: 0,
          _bitrateCount: 0,
          interfaces: [],
        });
      }
      return radioGroups.get(name);
    };

    // First pass: gather common radio properties
    for (const r of radioInfos) {
      const radioName = ifaceToRadio.get(r.device) || 'unknown';
      const group = getRadioGroup(radioName);

      if (r.channel != null) group.channel = r.channel;
      if (r.country) group.country = r.country;
      if (r.frequency != null) group.frequency = r.frequency;
      if (r.txpower != null) group.txPower = r.txpower;
      if (r.noise != null) group.noise = r.noise;
    }

    // Second pass: build interfaces and calculate SNR
    for (const r of radioInfos) {
      const radioName = ifaceToRadio.get(r.device) || 'unknown';
      const group = getRadioGroup(radioName);

      const noise = (typeof r.noise === 'number') ? r.noise : group.noise;
      const snr = (typeof r.signal === 'number' && typeof noise === 'number') ? r.signal - noise : null;

      if (snr !== null) {
        group._snrSum += snr;
        group._snrCount += 1;
      }

      if (typeof r.bitrate === 'number') {
        group._bitrateSum += r.bitrate;
        group._bitrateCount += 1;
      }

      group.interfaces.push({
        interface: r.device,
        ssid: r.ssid,
        bssid: r.bssid,
        mode: r.mode,
        signal: r.signal ?? null,
        snr,
        bitrate: r.bitrate ?? null,
        clientCount: r.clientCount || 0,
        connectedDevices: r.connectedDevices || [],
        disabled: false,
        network: ifaceToNetwork ? (ifaceToNetwork.get(r.device) || null) : null,
        bridge: portToBridge ? (portToBridge.get(r.device) || null) : null,
      });
      group.clientCount = (group.clientCount || 0) + (r.clientCount || 0);
    }

    for (const d of disabledRadios) {
      const group = getRadioGroup(d.radio);
      group.interfaces.push({
        interface: d.interface,
        ssid: d.ssid,
        mode: d.mode,
        disabled: true,
        bssid: null,
        signal: null,
        snr: null,
        bitrate: null,
        clientCount: 0,
        connectedDevices: [],
        network: d.network,
        bridge: portToBridge.get(d.interface) || null,
      });
    }

    for (const group of radioGroups.values()) {
      if (group._snrCount > 0) {
        group.snr = Math.round(group._snrSum / group._snrCount);
      }
      delete group._snrSum;
      delete group._snrCount;

      if (group._bitrateCount > 0) {
        group.bitrate = Math.round(group._bitrateSum / group._bitrateCount);
      }
      delete group._bitrateSum;
      delete group._bitrateCount;
    }

    const wifi = Array.from(radioGroups.values());
    const networks = this._parseNetworks(interfaceDump, portToBridge, wifi, bridgeVlanOutput, uciNetwork);

    const broadcastIps = [];
    for (const net of Object.values(networks)) {
      const bcast = this._calculateBroadcast(net.ipAddress, net.mask);
      if (bcast) broadcastIps.push(bcast);
    }

    return {
      uniqueId,
      ip: staticIp,
      mac: staticMac,
      isInternetRouter,
      isDhcpServer,
      isFirewall,
      isAp,
      totalClientCount: 0,
      model: staticSystem.model,
      firmwareVersion: staticSystem.firmwareVersion,
      luciVersion: staticSystem.luciVersion,
      architecture: staticSystem.architecture,
      kernelVersion: staticSystem.kernelVersion,
      hostname: staticSystem.hostname || system?.hostname,
      uptime: system?.uptime,
      localtime: system?.localtime ? new Date(system.localtime * 1000) : undefined,
      loadAverage: system?.load,
      temperature,
      cpuUsage,
      totalMemory: totalMemory || system?.memory?.total || null,
      totalMemoryMB: totalMemoryMB || (system?.memory?.total ? Math.round(system.memory.total / 1048576).toString() : null),
      memory: {
        free: system?.memory?.free,
        available: system?.memory?.available,
        usage: memoryUsage,
      },
      wan: {
        up: wan?.up,
        uptime: wan?.uptime,
        ipAddress: wanIp,
        macAddress: wanMac?.toUpperCase(),
        protocol: wanProto,
        gateway: wanGateway,
        dnsServers: wanDns,
        stats: trafficStats ? (trafficStats.get(wan.l3_device || wan.device) || null) : null,
        bridge: (portToBridge && wan.device) ? (portToBridge.get(wan.device) || null) : (staticWan?.bridge || null),
      },
      networks,
      wifi,
      broadcastIps,
    };
  }

  _parseLanInfo({
    staticLanInfo, gatewayMac, gatewayIface, fdbOutput = '', portToBridge, brPortsOutput = '', brctlOutput = '', interfaceDump, trafficStats,
    wifiInterfaces = [], wanInterfaces = [], networks = {},
  }) {
    const bridgeFdbMap = new Map();
    const bridgeMasterMap = new Map();
    const excludedDevices = new Set([...wifiInterfaces, ...wanInterfaces]);

    // Ensure portToBridge is available
    const p2b = portToBridge || new Map();

    // Build reverse map: bridge -> ports
    const bridgeToPorts = new Map();
    for (const [port, bridge] of p2b) {
      if (!bridgeToPorts.has(bridge)) bridgeToPorts.set(bridge, []);
      bridgeToPorts.get(bridge).push(port);
    }

    // Map devices to networks
    const deviceToNetworks = new Map();
    if (networks) {
      for (const [netName, netInfo] of Object.entries(networks)) {
        const mapDev = (d) => {
          if (!d) return;
          if (!deviceToNetworks.has(d)) deviceToNetworks.set(d, []);
          if (!deviceToNetworks.get(d).includes(netName)) deviceToNetworks.get(d).push(netName);
          if (d.includes('.')) {
            const base = d.split('.')[0];
            if (!deviceToNetworks.has(base)) deviceToNetworks.set(base, []);
            if (!deviceToNetworks.get(base).includes(netName)) deviceToNetworks.get(base).push(netName);
          }
        };
        mapDev(netInfo.device);
        mapDev(netInfo.l3Device);

        if (netInfo.ports) {
          for (const port of netInfo.ports) {
            if (!deviceToNetworks.has(port)) deviceToNetworks.set(port, []);
            if (!deviceToNetworks.get(port).includes(netName)) deviceToNetworks.get(port).push(netName);
          }
        }
      }
    }

    // Parse FDB
    const lines = fdbOutput.trim().split('\n');
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const mac = parts[0];
        if (mac.includes(':')) {
          // Filter multicast/broadcast MACs (LSB of first byte is 1)
          const firstByte = parseInt(mac.substring(0, 2), 16);
          if (!Number.isNaN(firstByte) && (firstByte & 1) === 1) continue;

          const devIdx = parts.indexOf('dev');
          const masterIdx = parts.indexOf('master');
          if (!line.includes('self') && !line.includes('permanent')) {
            if (devIdx !== -1 && devIdx + 1 < parts.length) {
              const devName = parts[devIdx + 1];
              if (!bridgeFdbMap.has(devName)) bridgeFdbMap.set(devName, new Set());
              bridgeFdbMap.get(devName).add(mac.toUpperCase());
            }
            if (masterIdx !== -1 && masterIdx + 1 < parts.length) {
              const masterName = parts[masterIdx + 1];
              if (!bridgeMasterMap.has(masterName)) bridgeMasterMap.set(masterName, new Set());
              bridgeMasterMap.get(masterName).add(mac.toUpperCase());
            }
          }
        }
      }
    }

    // Also parse brctl as fallback or supplement
    const portMap = new Map(); // bridge -> portNo -> iface
    const portLines = brPortsOutput.trim().split('\n');
    for (const line of portLines) {
      // /sys/class/net/br-lan/brif/lan1/port_no:1
      const match = line.match(/\/sys\/class\/net\/([^/]+)\/brif\/([^/]+)\/port_no:(.+)$/);
      if (match) {
        const br = match[1];
        const iface = match[2];
        const portNo = Number(match[3].trim());
        if (!Number.isNaN(portNo)) {
          if (!portMap.has(br)) portMap.set(br, new Map());
          portMap.get(br).set(portNo, iface);
        }
      }
    }

    const brParts = brctlOutput.split('BR:');
    for (const part of brParts) {
      const brLines = part.trim().split('\n');
      if (brLines.length > 1) {
        const brPath = brLines[0].trim(); // /sys/class/net/br-lan
        const brName = brPath.split('/').pop();
        const brPortMap = portMap.get(brName);

        for (let i = 1; i < brLines.length; i++) {
          const parts = brLines[i].trim().split(/\s+/);
          if (parts.length >= 3) {
            const port = parseInt(parts[0], 10);
            const mac = parts[1];
            // Filter multicast/broadcast MACs
            const firstByte = parseInt(mac.substring(0, 2), 16);
            if (!Number.isNaN(firstByte) && (firstByte & 1) === 1) continue;

            const isLocal = parts[2];
            if (isLocal === 'no') {
              if (!bridgeMasterMap.has(brName)) bridgeMasterMap.set(brName, new Set());
              bridgeMasterMap.get(brName).add(mac.toUpperCase());

              if (brPortMap && brPortMap.has(port)) {
                const devName = brPortMap.get(port);
                if (!bridgeFdbMap.has(devName)) bridgeFdbMap.set(devName, new Set());
                bridgeFdbMap.get(devName).add(mac.toUpperCase());
              }
            }
          }
        }
      }
    }

    // Identify WiFi devices to exclude from LAN list
    // We don't have iwinfo output here directly, but we can infer from static info if needed.
    // However, getLanInfo logic filtered them out.
    // For now, we assume all devices in staticLanInfo are valid candidates,
    // but we might want to filter if they are wifi.
    // staticLanInfo doesn't explicitly flag wifi, but we can check if they are in wireless config.
    // A simpler check: if type is 'other' and not in bridgeFdbMap, it might be wifi or disconnected.

    const result = {};
    const allDevices = Object.keys(staticLanInfo || {});

    // Pre-calculate MACs assigned to specific ports to avoid duplication on the bridge
    const assignedMacs = new Set();
    for (const [devName, macs] of bridgeFdbMap) {
      if (!bridgeMasterMap.has(devName)) {
        for (const mac of macs) assignedMacs.add(mac);
      }
    }

    for (const deviceName of allDevices) {
      if (excludedDevices.has(deviceName)) continue;
      const staticData = staticLanInfo[deviceName];

      const deviceData = {
        type: (() => {
          if (deviceName.startsWith('eth') || deviceName.startsWith('lan')) return 'ethernet';
          if (deviceName.startsWith('br-')) return 'bridge';
          return 'other';
        })(),
        stats: {
          rxBytes: null,
          txBytes: null,
          rxPackets: null,
          txPackets: null,
        },
        macAddress: staticData.macAddress,
        speed: staticData.speed,
        duplex: staticData.duplex,
        group: 'internal',
        network: deviceToNetworks.get(deviceName) || null,
        connectedDevices: [],
        clientCount: 0,
        bridge: null,
        ipAddresses: [],
        ip6Addresses: [],
      };

      if (p2b.has(deviceName)) {
        deviceData.bridge = p2b.get(deviceName);
      }

      // Fallback: If bridge has no network, try to inherit from its ports
      if (deviceData.type === 'bridge' && !deviceData.network) {
        const ports = bridgeToPorts.get(deviceName);
        if (ports) {
          const nets = new Set();
          for (const port of ports) {
            const portNets = deviceToNetworks.get(port);
            if (portNets) {
              for (const net of portNets) nets.add(net);
            }
          }
          if (nets.size > 0) {
            deviceData.network = Array.from(nets).sort();
          }
        }
      }

      // Get stats
      const stats = trafficStats ? trafficStats.get(deviceName) : null;
      if (stats) {
        deviceData.stats = {
          rxBytes: stats.rxBytes,
          txBytes: stats.txBytes,
          rxPackets: stats.rxPackets,
          txPackets: stats.txPackets,
        };
      }

      // Get connected devices from FDB (for switch ports)
      if (bridgeFdbMap.has(deviceName)) {
        const macs = Array.from(bridgeFdbMap.get(deviceName)).sort();
        deviceData.connectedDevices = macs;
        deviceData.clientCount = macs.length;
      } else if (bridgeMasterMap.has(deviceName)) {
        const macs = Array.from(bridgeMasterMap.get(deviceName)).sort();
        const filteredMacs = macs.filter((m) => !assignedMacs.has(m));
        deviceData.connectedDevices = filteredMacs;
        deviceData.clientCount = filteredMacs.length;
      }

      // Determine Port Group (Uplink vs Local)
      if (deviceData.type === 'bridge') {
        deviceData.group = 'bridge';
      } else if (deviceName === 'lo') {
        deviceData.group = 'internal';
      } else if ((gatewayIface && deviceName === gatewayIface)
        || (gatewayMac && deviceData.connectedDevices && deviceData.connectedDevices.includes(gatewayMac))) {
        deviceData.group = 'uplink';
      } else if (deviceData.type === 'ethernet' || deviceData.type === 'other') {
        deviceData.group = 'port';
      }

      result[deviceName] = deviceData;
    }

    // 4. Add logical interface info (IP addresses)
    if (interfaceDump && interfaceDump.interface) {
      for (const iface of interfaceDump.interface) {
        if (iface.device && result[iface.device]) {
          const dev = result[iface.device];
          if (iface['ipv4-address']) {
            dev.ipAddresses.push(...iface['ipv4-address'].map((a) => `${a.address}/${a.mask}`));
          }
          if (iface['ipv6-address']) {
            dev.ip6Addresses.push(...iface['ipv6-address'].map((a) => `${a.address}/${a.mask}`));
          }
        }
      }
    }

    // Group the results
    const groupedResult = {};
    Object.keys(result).sort().forEach((key) => {
      const dev = result[key];
      const group = dev.group || 'other';
      delete dev.group;
      if (!groupedResult[group]) {
        groupedResult[group] = { clientCount: 0 };
      }
      groupedResult[group][key] = dev;
      if (dev.clientCount) {
        groupedResult[group].clientCount += dev.clientCount;
      }
    });

    return groupedResult;
  }

  _parseHosts(hostsContent) {
    const hostsMap = new Map();
    try {
      const lines = (hostsContent || '').toString().trim().split('\n');
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2 && !line.trim().startsWith('#')) {
          const ip = parts[0];
          const name = parts[1];
          if (ip && name) hostsMap.set(ip, name);
        }
      }
    } catch (e) {}
    return hostsMap;
  }

  _parseDhcpLeases(leaseContent) {
    const leaseMap = new Map();
    try {
      const lines = (leaseContent || '').toString().trim().split('\n').filter((l) => l.trim());
      for (const line of lines) {
        const parts = line.trim().split(/\s+/).filter((p) => p);
        if (parts.length >= 4) {
          const mac = parts[1].toLowerCase();
          const ip = parts[2];
          const name = parts[3] !== '*' ? parts[3] : 'unknown';

          if (!leaseMap.has(mac)) {
            leaseMap.set(mac, { name, ip });
          } else if (name !== 'unknown') {
            const entry = leaseMap.get(mac);
            if (entry.name === 'unknown') {
              entry.name = name;
              entry.ip = ip;
            }
          }
        }
      }
    } catch (e) {
      // console.warn(`[WARN] Failed to get DHCP leases for names: ${e.message}`);
    }
    return leaseMap;
  }

  _processWirelessClientData(iface, info, clientsData, seenThisRun, leaseMap, hostsMap, wifiInterfaceSsidMap) {
    if (info && info.ssid) {
      wifiInterfaceSsidMap.set(iface, info.ssid);
    }

    if (clientsData && clientsData.results) {
      for (const client of clientsData.results) {
        const macLower = client.mac.toLowerCase();
        const entry = seenThisRun.get(macLower);
        if (entry) {
          entry.source = entry.source.includes('iwinfo') ? entry.source : `${entry.source}+iwinfo`;
          entry.interface = iface;
          entry.signal = client.signal ?? null;
          entry.noise = client.noise ?? null;
          entry.snr = (client.signal != null && client.noise != null) ? (client.signal - client.noise) : null;
          entry.inactiveTime = client.inactive ?? null;
          entry.rxRate = client.rx?.rate ?? null;
          entry.rxMcs = client.rx?.mcs ?? null;
          entry.rxChannelWidth = client.rx?.mhz ?? null;
          entry.rxPackets = client.rx?.packets ?? null;
          entry.txRate = client.tx?.rate ?? null;
          entry.txMcs = client.tx?.mcs ?? null;
          entry.txChannelWidth = client.tx?.mhz ?? null;
          entry.txPackets = client.tx?.packets ?? null;
          entry.txShortGi = client.tx?.short_gi ?? null;
        } else {
          const leaseInfo = leaseMap.get(macLower);
          let name = leaseInfo?.name || 'unknown';
          const ip = leaseInfo?.ip || 'unknown';
          if (name === 'unknown' && ip !== 'unknown' && hostsMap) {
            name = hostsMap.get(ip) || 'unknown';
          }
          seenThisRun.set(macLower, {
            mac: client.mac,
            ip,
            name,
            source: 'iwinfo',
            interface: iface,
            signal: client.signal ?? null,
            noise: client.noise ?? null,
            snr: (client.signal != null && client.noise != null) ? (client.signal - client.noise) : null,
            inactiveTime: client.inactive ?? null,
            rxRate: client.rx?.rate ?? null,
            rxMcs: client.rx?.mcs ?? null,
            rxChannelWidth: client.rx?.mhz ?? null,
            rxPackets: client.rx?.packets ?? null,
            txRate: client.tx?.rate ?? null,
            txMcs: client.tx?.mcs ?? null,
            txChannelWidth: client.tx?.mhz ?? null,
            txPackets: client.tx?.packets ?? null,
            txShortGi: client.tx?.short_gi ?? null,
          });
        }
      }
    }
  }

  _parseArpTable(neighContent, arpContent, seenThisRun, leaseMap, hostsMap) {
    let usedNeigh = false;
    if (neighContent) {
      const lines = neighContent.trim().split('\n');
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        const lladdrIndex = parts.indexOf('lladdr');
        if (lladdrIndex !== -1 && lladdrIndex + 1 < parts.length) {
          usedNeigh = true;
          const ip = parts[0];
          if (ip.includes(':')) continue; // Skip IPv6 to match /proc/net/arp behavior

          const mac = parts[lladdrIndex + 1];
          const state = parts[parts.length - 1];
          // Only consider active states to update lastSeen.
          // Consider more states as "present" to handle sleeping devices
          const activeStates = ['REACHABLE', 'PERMANENT', 'DELAY', 'STALE', 'PROBE'];

          if (activeStates.includes(state.toUpperCase()) && mac !== '00:00:00:00:00:00') {
            const macLower = mac.toLowerCase();
            const entry = seenThisRun.get(macLower);
            if (entry) {
              entry.ip = ip;
              entry.source = entry.source.includes('arp') ? entry.source : `${entry.source}+arp`;
              entry.arpState = state.toUpperCase();
            } else {
              const leaseInfo = leaseMap.get(macLower);
              let name = leaseInfo?.name || 'unknown';
              if (name === 'unknown' && hostsMap) {
                name = hostsMap.get(ip) || 'unknown';
              }
              const devIndex = parts.indexOf('dev');
              const iface = (devIndex !== -1 && devIndex + 1 < parts.length) ? parts[devIndex + 1] : 'unknown';
              seenThisRun.set(macLower, {
                mac,
                ip,
                name,
                source: 'arp',
                interface: iface,
                arpState: state.toUpperCase(),
              });
            }
          }
        }
      }
    }

    if (usedNeigh) return;

    if (arpContent) {
      const lines = arpContent.trim().split('\n').slice(1); // slice(1) to skip header
      for (const line of lines) {
        const parts = line.trim().split(/\s+/).filter((p) => p);
        if (parts.length >= 4 && parts[3] !== '00:00:00:00:00:00') {
          const ip = parts[0];
          const macLower = parts[3].toLowerCase();
          const entry = seenThisRun.get(macLower);
          if (entry) {
            entry.ip = ip;
            entry.source = entry.source.includes('arp') ? entry.source : `${entry.source}+arp`;
          } else {
            const leaseInfo = leaseMap.get(macLower);
            let name = leaseInfo?.name || 'unknown';
            if (name === 'unknown' && hostsMap) {
              name = hostsMap.get(ip) || 'unknown';
            }
            seenThisRun.set(macLower, {
              mac: parts[3],
              ip,
              name,
              source: 'arp',
              interface: parts[5] || 'unknown',
            });
          }
        }
      }
    }
  }

  _parseNlbwmonData(nlbwOutput) {
    const nlbwData = new Map(); // mac -> { rx_bytes, tx_bytes }
    const connData = new Map(); // mac -> { total: count, <proto1>: count, ... }
    try {
      if (!nlbwOutput) return { nlbwData, connData };
      const nlbwJson = JSON.parse(nlbwOutput);

      if (nlbwJson && nlbwJson.columns && nlbwJson.data) {
        const cols = nlbwJson.columns.map((c) => c.toLowerCase());
        const macIndex = cols.indexOf('mac');
        const ipIndex = cols.indexOf('ip');
        const rxBytesIndex = cols.indexOf('rx_bytes');
        const txBytesIndex = cols.indexOf('tx_bytes');
        const layer7Index = cols.indexOf('layer7');

        if (macIndex !== -1 && rxBytesIndex !== -1 && txBytesIndex !== -1) {
          for (const entry of nlbwJson.data) {
            const mac = entry[macIndex] ? entry[macIndex].toLowerCase() : null;
            const ip = (ipIndex !== -1 && entry[ipIndex]) ? entry[ipIndex] : null;
            const proto = layer7Index !== -1 && entry[layer7Index] ? entry[layer7Index].toString() : null;
            const inBytes = Number(entry[rxBytesIndex]);
            const outBytes = Number(entry[txBytesIndex]);

            if (mac && !Number.isNaN(inBytes) && !Number.isNaN(outBytes)) {
              const traffic = nlbwData.get(mac) || { rxBytes: 0, txBytes: 0, ip: null };
              traffic.rxBytes += inBytes;
              traffic.txBytes += outBytes;
              if (ip && !traffic.ip) traffic.ip = ip;
              nlbwData.set(mac, traffic);

              if (proto) {
                const connections = connData.get(mac) || { total: 0 };
                connections.total++;
                connections[proto] = (connections[proto] || 0) + 1;
                connData.set(mac, connections);
              }
            }
          }
        }
      }
    } catch (e) {
      // console.warn(`[WARN] nlbw: CLI call failed. Is nlbwmon running? Error: ${e.message}`);
    }
    return { nlbwData, connData };
  }

  _parseFdbForDevices(fdbOutput, brctlOutput) {
    const fdbMap = new Map();
    if (fdbOutput) {
      const lines = fdbOutput.trim().split('\n');
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) {
          const mac = parts[0];
          if (mac.includes(':') && !line.includes('00:00:00:00:00:00')) {
            const devIdx = parts.indexOf('dev');
            let iface = null;
            if (devIdx !== -1 && devIdx + 1 < parts.length) {
              iface = parts[devIdx + 1];
            }
            fdbMap.set(mac.toLowerCase(), iface);
          }
        }
      }
    }
    // Also parse brctl as fallback or supplement
    if (brctlOutput) {
      const matches = brctlOutput.matchAll(/^\s*\d+\s+([0-9a-fA-F:]+)\s+no/gm);
      for (const match of matches) {
        fdbMap.set(match[1].toLowerCase(), null);
      }
    }
    return fdbMap;
  }

  async _probeIp(ip, timeoutMs = 700) {
    try {
      const waitSec = Math.max(1, Math.ceil(timeoutMs / 1000));
      // -c 1 send single, -W wait timeout in seconds
      const out = await this._execSsh(`ping -c 1 -W ${waitSec} ${ip} || true`);
      return /1 packets transmitted.*1 received|1 received/.test(out);
    } catch (_) {
      return false;
    }
  }

  _calculateBroadcast(ip, mask) {
    if (!ip || mask === undefined || mask === null) return null;

    const ipParts = ip.split('.').map((o) => parseInt(o, 10));
    if (ipParts.length !== 4 || ipParts.some(Number.isNaN)) return null;
    // eslint-disable-next-line no-bitwise
    const ipLong = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;

    let maskLong = 0;
    if (typeof mask === 'number' || (typeof mask === 'string' && !mask.includes('.'))) {
      const cidr = parseInt(mask, 10);
      if (Number.isNaN(cidr) || cidr < 0 || cidr > 32) return null;
      // eslint-disable-next-line no-bitwise
      maskLong = (-1 << (32 - cidr)) >>> 0;
    } else {
      const mParts = mask.split('.').map((o) => parseInt(o, 10));
      if (mParts.length !== 4 || mParts.some(Number.isNaN)) return null;
      // eslint-disable-next-line no-bitwise
      maskLong = ((mParts[0] << 24) | (mParts[1] << 16) | (mParts[2] << 8) | mParts[3]) >>> 0;
    }

    // eslint-disable-next-line no-bitwise
    const bcastLong = (ipLong | (~maskLong)) >>> 0;
    // eslint-disable-next-line no-bitwise
    return [(bcastLong >>> 24) & 255, (bcastLong >>> 16) & 255, (bcastLong >>> 8) & 255, bcastLong & 255].join('.');
  }

  _updateDeviceCacheAndBuildList(seenThisRun, now, wifiInterfaceSsidMap, fdbMacs, wifiInterfaces) {
    // 4) Update cache
    for (const [mac, device] of seenThisRun) {
      const existing = this.#deviceCache.get(mac);

      // Only update lastSeen if the device is active (WiFi associated or ARP reachable)
      // STALE ARP entries should not update lastSeen if pingCheck is enabled,
      // allowing the TTL to eventually expire if the device doesn't become reachable again.
      const isArpStale = device.arpState === 'STALE';
      const isWifi = device.source.includes('iwinfo');
      const isFdbPresent = fdbMacs && fdbMacs.has(mac);
      const fdbInterface = fdbMacs ? fdbMacs.get(mac) : undefined;

      let isActive = true;
      if (isArpStale && !isWifi) {
        if (this.#pingCheck) {
          isActive = false;
        } else if (!isFdbPresent) {
          isActive = false;
        } else if (wifiInterfaces && fdbInterface && wifiInterfaces.includes(fdbInterface)) {
          isActive = false;
        }
      }

      // WiFi Disconnect Logic:
      // If device was previously on WiFi (iwinfo) but is now only seen in ARP,
      // it implies a WiFi disconnection. We should treat it as inactive immediately
      // (so lastSeen stops updating) UNLESS it is seen on the bridge (FDB),
      // which would imply it roamed to a wired AP.
      if (existing && existing.source.includes('iwinfo') && !isWifi && !isFdbPresent) {
        isActive = false;
        // Preserve source to maintain "WiFi device" status for subsequent runs
        // so we don't fall back to treating it as a wired device (which would stay active via ARP).
        device.source = existing.source;
      }

      if (existing) {
        if (device.ip === 'unknown' && existing.ip && existing.ip !== 'unknown') {
          device.ip = existing.ip;
        }

        if (isActive) {
          Object.assign(existing, device, { lastSeen: now });
        } else {
          Object.assign(existing, device);
        }

        if (device.name !== 'unknown' && existing.name === 'unknown') {
          existing.name = device.name;
        }
      } else if (isActive) {
        this.#deviceCache.set(mac, {
          ...device,
          firstSeen: now,
          lastSeen: now,
        });
      }
    }

    // 5) Build result list and clean up old entries
    const resultList = [];
    const ipsToPing = [];
    for (const [mac, device] of this.#deviceCache.entries()) {
      const ttl = this.#customDeviceTTLs.get(mac) || this.#deviceCacheTTL;
      if (now - device.lastSeen < ttl * 1000) {
        const isWifi = wifiInterfaceSsidMap.has(device.interface) || (device.signal != null || device.rxRate != null);

        const resultDevice = {
          routerId: this.#staticRouterInfo?.uniqueId,
          routerName: this.#staticRouterInfo?.hostname,
          ip: device.ip,
          mac: device.mac.toUpperCase(),
          name: device.name,
          onlineSince: device.firstSeen,
          onlineForSeconds: Math.floor((now - device.firstSeen) / 1000),
          lastSeen: device.lastSeen,
          source: device.source,
          interface: device.interface,
          linkSpeed: null,
          connectedVia: isWifi ? 'wifi' : 'unknown',
          wifi: null,
          traffic: null,
          network: null,
          bridge: null,
          port: null,
        };

        if (isWifi) {
          resultDevice.wifi = {
            ssid: wifiInterfaceSsidMap.get(device.interface) || null,
            signal: device.signal ?? null,
            noise: device.noise ?? null,
            snr: device.snr ?? null,
            inactiveTime: device.inactiveTime ?? null,
            rxRate: device.rxRate ?? null,
            rxMcs: device.rxMcs ?? null,
            rxChannelWidth: device.rxChannelWidth ?? null,
            rxPackets: device.rxPackets ?? null,
            txRate: device.txRate ?? null,
            txMcs: device.txMcs ?? null,
            txChannelWidth: device.txChannelWidth ?? null,
            txPackets: device.txPackets ?? null,
            txShortGi: device.txShortGi ?? null,
          };
          if (device.rxRate) {
            resultDevice.linkSpeed = Math.round(device.rxRate / 1000);
          }
        }

        resultDevice.traffic = {
          rxBytes: device.rxBytes ?? null,
          txBytes: device.txBytes ?? null,
          connections: device.connections ?? null,
        };

        resultList.push(resultDevice);

        // If device is missing for > 25s, try to ping it to refresh ARP table
        if (this.#pingCheck) {
          let shouldPing = false;
          if (device.lastSeen !== now && now - device.lastSeen > 25000) shouldPing = true;
          if (device.arpState === 'STALE') shouldPing = true;

          if (shouldPing && device.ip && device.ip !== 'unknown') {
            ipsToPing.push(device.ip);
          }
        }
      } else {
        this.#deviceCache.delete(mac);
      }
    }

    if (ipsToPing.length > 0) {
      const cmd = ipsToPing.slice(0, 50).map((ip) => `ping -c 2 -W 1 ${ip} >/dev/null 2>&1 &`).join(' ');
      this._execSsh(cmd).catch(() => {});
    }

    const ipToNumber = (ip) => {
      if (typeof ip !== 'string' || ip === 'unknown') {
        return Infinity;
      }
      return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
    };

    resultList.sort((a, b) => ipToNumber(a.ip) - ipToNumber(b.ip));

    return resultList;
  }

  _parseProcNetDev(output) {
    const stats = new Map();
    if (!output) return stats;
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes(':')) {
        const [iface, data] = line.split(':');
        const values = data.trim().split(/\s+/);
        if (values.length >= 10) {
          stats.set(iface.trim(), {
            rxBytes: parseInt(values[0], 10),
            rxPackets: parseInt(values[1], 10),
            txBytes: parseInt(values[8], 10),
            txPackets: parseInt(values[9], 10),
          });
        }
      }
    }
    return stats;
  }

  _enrichDevicesWithLanInfo(devices, lanInfo) {
    if (!devices || !lanInfo) return;

    const ipToLong = (ip) => {
      if (!ip || ip === 'unknown') return 0;
      const parts = ip.split('.');
      if (parts.length !== 4) return 0;
      return ((parseInt(parts[0], 10) << 24) | (parseInt(parts[1], 10) << 16) | (parseInt(parts[2], 10) << 8) | parseInt(parts[3], 10)) >>> 0;
    };

    const inSubnet = (ip, netIp, mask) => {
      const ipL = ipToLong(ip);
      const netIpL = ipToLong(netIp);
      let maskL = 0;
      if (typeof mask === 'number') {
        maskL = -1 << (32 - mask);
      } else if (typeof mask === 'string' && mask.includes('.')) {
        maskL = ipToLong(mask);
      } else {
        maskL = -1 << (32 - parseInt(mask, 10));
      }
      return (ipL & maskL) === (netIpL & maskL);
    };

    const macMap = new Map();
    const wifiNetworkMap = new Map();
    const wifiBridgeMap = new Map();

    if (lanInfo.wifi) {
      for (const radio of lanInfo.wifi) {
        if (radio.interfaces) {
          for (const iface of radio.interfaces) {
            if (iface.interface && iface.network) {
              wifiNetworkMap.set(iface.interface, iface.network);
            }
            if (iface.interface && iface.bridge) {
              wifiBridgeMap.set(iface.interface, iface.bridge);
            }
          }
        }
      }
    }

    // Helper to process groups
    const processGroup = (groupName, group) => {
      if (!group) return;
      for (const [ifaceName, ifaceData] of Object.entries(group)) {
        if (ifaceName === 'clientCount') continue;
        if (ifaceData.connectedDevices && Array.isArray(ifaceData.connectedDevices)) {
          let effectiveGroup = groupName;
          // Distinguish direct vs shared local connections
          // Note: We cannot reliably distinguish between a dumb switch and a secondary AP
          // because a dumb switch is transparent (no MAC), and an AP appears as just another
          // device alongside its clients. Both result in multiple MACs on one port.
          if (groupName === 'port' && ifaceData.connectedDevices.length > 1) {
            effectiveGroup = 'shared-port';
          }
          for (const mac of ifaceData.connectedDevices) {
            macMap.set(mac, {
              interface: ifaceName,
              speed: ifaceData.speed,
              group: effectiveGroup,
              network: ifaceData.network,
              bridge: ifaceData.bridge,
            });
          }
        }
      }
    };

    // Process in order of specificity (Local overwrites Bridge)
    processGroup('bridge', lanInfo.bridge);
    processGroup('uplink', lanInfo.uplink);
    processGroup('port', lanInfo.port);

    for (const device of devices) {
      // Skip if device is WiFi (we trust wifi info more for interface name)
      if (device.wifi) {
        const net = wifiNetworkMap.get(device.interface);
        if (net) {
          device.network = net;
        }
        const br = wifiBridgeMap.get(device.interface);
        if (br) {
          device.bridge = br;
        }
        device.port = device.wifi.ssid;
      } else {
        const info = macMap.get(device.mac);
        if (info) {
          device.interface = info.interface;
          device.connectedVia = info.group;
          if (info.speed) {
            device.linkSpeed = info.speed;
          }
          if (info.network) {
            device.network = info.network;
          }
          if (info.bridge) {
            device.bridge = info.bridge;
          }
          if (!device.bridge && info.group === 'bridge') {
            device.bridge = info.interface;
          }
          if (info.group === 'port' || info.group === 'shared-port') {
            device.port = info.interface;
          }
        }
      }

      // Fallback: If network is missing, try to find it via IP subnet matching
      if ((!device.network || device.network.length === 0) && device.ip && device.ip !== 'unknown' && lanInfo.networks) {
        const matchedNetworks = [];
        for (const [netName, netInfo] of Object.entries(lanInfo.networks)) {
          if (netInfo.ipAddress && netInfo.mask) {
            if (inSubnet(device.ip, netInfo.ipAddress, netInfo.mask)) {
              matchedNetworks.push(netName);
            }
          }
        }
        if (matchedNetworks.length > 0) {
          device.network = matchedNetworks;
        }
      }

      // Filter network based on IP if multiple networks are assigned
      if (device.ip && device.ip !== 'unknown' && Array.isArray(device.network) && device.network.length > 1 && lanInfo.networks) {
        const matching = device.network.filter((netName) => {
          const net = lanInfo.networks[netName];
          if (net && net.ipAddress && net.mask) {
            return inSubnet(device.ip, net.ipAddress, net.mask);
          }
          return false;
        });
        if (matching.length > 0) {
          device.network = matching;
        }
      }

      // Add Firewall Zones
      if (device.network && this.#staticRouterInfo?.networkToZone) {
        const zones = new Set();
        const networks = Array.isArray(device.network) ? device.network : [device.network];
        for (const net of networks) {
          const zone = this.#staticRouterInfo.networkToZone[net];
          if (zone) zones.add(zone);
        }
        if (zones.size > 0) {
          device.firewallZones = Array.from(zones).sort();
          device.firewallZone = device.firewallZones[0];
        }
      }
    }
  }

  _parseNetworks(interfaceDump, portToBridge, wifi, bridgeVlanOutput, uciNetwork) {
    const networks = {};
    if (!interfaceDump || !interfaceDump.interface) return networks;

    const bridgeToPorts = new Map();
    if (portToBridge) {
      for (const [port, bridge] of portToBridge) {
        if (!bridgeToPorts.has(bridge)) bridgeToPorts.set(bridge, []);
        bridgeToPorts.get(bridge).push(port);
      }
    }

    const portVlans = new Map();
    if (bridgeVlanOutput) {
      const lines = bridgeVlanOutput.split('\n');
      let currentPort = null;
      for (const line of lines) {
        if (!line.trim() || line.startsWith('port')) continue;
        const isContinuation = line.startsWith('\t') || line.startsWith('    ');
        const parts = line.trim().split(/\s+/);

        let vlanIdStr;
        if (!isContinuation) {
          currentPort = parts[0];
          vlanIdStr = parts[1];
        } else {
          vlanIdStr = parts[0];
        }

        if (currentPort && vlanIdStr) {
          const vlanId = parseInt(vlanIdStr, 10);
          if (!Number.isNaN(vlanId)) {
            if (!portVlans.has(currentPort)) portVlans.set(currentPort, new Set());
            portVlans.get(currentPort).add(vlanId);
          }
        }
      }
    }

    // Fallback to UCI if runtime VLAN info is missing
    if (portVlans.size === 0 && uciNetwork && uciNetwork.values) {
      for (const section of Object.values(uciNetwork.values)) {
        if (section['.type'] === 'bridge-vlan' && section.vlan && section.ports) {
          const vlanId = parseInt(section.vlan, 10);
          if (!Number.isNaN(vlanId)) {
            const ports = Array.isArray(section.ports) ? section.ports : [section.ports];
            for (const p of ports) {
              const portName = p.split(':')[0];
              if (!portVlans.has(portName)) portVlans.set(portName, new Set());
              portVlans.get(portName).add(vlanId);
            }
          }
        }
      }
    }

    for (const iface of interfaceDump.interface) {
      const name = iface.interface;
      const { device, l3_device: l3Device } = iface;

      const netInfo = {
        ipAddress: iface['ipv4-address']?.[0]?.address || null,
        mask: iface['ipv4-address']?.[0]?.mask || null,
        macAddress: iface.macaddr,
        gateway: iface.route?.[0]?.nexthop || null,
        dnsServers: iface['dns-server'] || [],
        device,
        l3Device,
        protocol: iface.proto,
        up: iface.up,
        ports: [],
      };

      const addPorts = (dev) => {
        if (!dev) return;
        if (bridgeToPorts.has(dev)) {
          netInfo.ports.push(...bridgeToPorts.get(dev));
        } else if (dev.includes('.')) {
          const [base, vlanIdStr] = dev.split('.');
          const vlanId = parseInt(vlanIdStr, 10);
          if (bridgeToPorts.has(base)) {
            const ports = bridgeToPorts.get(base);
            if (portVlans.size > 0 && !Number.isNaN(vlanId)) {
              const filtered = ports.filter((p) => portVlans.has(p) && portVlans.get(p).has(vlanId));
              netInfo.ports.push(...filtered);
            }
          }
        }
        if (dev.startsWith('eth') || dev.startsWith('lan') || dev.startsWith('wlan')) {
          netInfo.ports.push(dev);
        }
      };

      addPorts(device);
      addPorts(l3Device);

      if (wifi) {
        for (const radio of wifi) {
          for (const wif of radio.interfaces) {
            if (wif.network) {
              const nets = Array.isArray(wif.network) ? wif.network : [wif.network];
              if (nets.includes(name)) {
                netInfo.ports.push(wif.interface);
              }
            }
          }
        }
      }

      netInfo.ports = [...new Set(netInfo.ports)].sort();
      networks[name] = netInfo;
    }
    return networks;
  }

  _parseBridgePorts(brPortsOutput) {
    const portToBridge = new Map();
    if (brPortsOutput) {
      const lines = brPortsOutput.trim().split('\n');
      for (const line of lines) {
        const match = line.match(/\/sys\/class\/net\/([^/]+)\/brif\/([^/]+)\/port_no/);
        if (match) {
          portToBridge.set(match[2], match[1]);
        }
      }
    }
    return portToBridge;
  }

  // 8. STATIC PRIVATE HELPERS
  static #processDeviceRecords(records, now) {
    const { mac } = records[0].device;
    this.#persistentMacCache[mac] = this.#persistentMacCache[mac] || {};

    // Find best record
    const directRecords = records.filter((r) => r.device.wifi || r.device.connectedVia === 'port');
    const candidates = directRecords.length > 0 ? directRecords : [...records];
    candidates.sort((a, b) => {
      // Prioritize WiFi
      if (!!a.device.wifi !== !!b.device.wifi) {
        return a.device.wifi ? -1 : 1;
      }

      // Prioritize 'port' over 'shared-port'
      if (a.device.connectedVia === 'port' && b.device.connectedVia !== 'port') return -1;
      if (b.device.connectedVia === 'port' && a.device.connectedVia !== 'port') return 1;

      // Prioritize downstream routers (APs) over the main internet router
      const aIsGw = this.#multiRouterCache[a.device.routerId]?.isInternetRouter || false;
      const bIsGw = this.#multiRouterCache[b.device.routerId]?.isInternetRouter || false;
      if (aIsGw !== bIsGw) {
        return aIsGw ? 1 : -1; // Prefer non-gateway (AP)
      }

      return b.timestamp - a.timestamp;
    });
    const bestRecord = candidates[0];

    const result = { ...bestRecord.device };

    // Enrich from other records
    for (const record of records) {
      if (record === bestRecord) continue;
      this.#enrichRecord(result, record.device);
    }

    // Enrich from persistent cache
    this.#enrichFromCache(result, this.#persistentMacCache[mac]);

    // Anti-Flap: WiFi -> Wired on Gateway
    if (this.#persistentMacCache[mac]?.connectedVia === 'wifi' && (result.connectedVia === 'port' || result.connectedVia === 'shared-port')) {
      const isGateway = this.#multiRouterCache[result.routerId]?.isInternetRouter || false;

      if (isGateway) {
        const probationStart = this.#persistentMacCache[mac].probationStart || now;
        if (now - probationStart < 120000) { // 2 minutes probation
          this.#persistentMacCache[mac].probationStart = probationStart;
          return null; // Drop this record
        }
      }
    }
    if (this.#persistentMacCache[mac]) delete this.#persistentMacCache[mac].probationStart;

    // Preserve WiFi state if device degrades to Unknown or Ghost Wired (Port) and is Stale
    const isStale = (now - result.lastSeen) > 30000;
    const isDegraded = result.connectedVia === 'unknown' || result.connectedVia === 'port' || result.connectedVia === 'shared-port';
    if (this.#persistentMacCache[mac]?.connectedVia === 'wifi' && isDegraded && isStale) {
      result.connectedVia = 'wifi';
      result.wifi = this.#persistentMacCache[mac].wifi;
    }

    // Update persistent cache with full result
    this.#persistentMacCache[mac] = { ...this.#persistentMacCache[mac], ...result, lastSeen: result.lastSeen || now };

    return result;
  }

  static #enrichRecord(result, other) {
    if (other.name && other.name !== 'unknown' && other.name !== other.mac) {
      if (!result.name || result.name === 'unknown' || result.name === result.mac) {
        result.name = other.name;
      }
    }
    if (other.ip && other.ip !== 'unknown') {
      if (!result.ip || result.ip === 'unknown') {
        result.ip = other.ip;
      }
    }
    const resultHasTraffic = result.traffic && (result.traffic.rxBytes !== null || result.traffic.txBytes !== null);
    const otherHasTraffic = other.traffic && (other.traffic.rxBytes !== null || other.traffic.txBytes !== null);
    if (!resultHasTraffic && otherHasTraffic) {
      result.traffic = other.traffic;
    }
    if (!result.wifi && other.wifi) {
      result.wifi = other.wifi;
      result.connectedVia = 'wifi';
    }
    if (!result.firewallZones && other.firewallZones) {
      result.firewallZones = other.firewallZones;
    }
    if (!result.firewallZone && other.firewallZone) {
      result.firewallZone = other.firewallZone;
    }
  }

  static #enrichFromCache(result, cached) {
    if (!cached) return;
    if ((!result.name || result.name === 'unknown' || result.name === result.mac) && cached.name) {
      result.name = cached.name;
    }
    if ((!result.ip || result.ip === 'unknown') && cached.ip) {
      result.ip = cached.ip;
    }
    const resultHasTraffic = result.traffic && (result.traffic.rxBytes !== null || result.traffic.txBytes !== null);
    if (!resultHasTraffic && cached.traffic) {
      result.traffic = cached.traffic;
    }
    if (!result.firewallZones && cached.firewallZones) {
      result.firewallZones = cached.firewallZones;
    }
    if (!result.firewallZone && cached.firewallZone) {
      result.firewallZone = cached.firewallZone;
    }
  }
}

module.exports = OpenWRTRouter;
