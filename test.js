'use strict';

const OpenWRTRouter = require('./lib/openwrt');

// Optional: Load environment variables from env.json if it exists
try {
  const env = require('./zzz_creds.json');
  Object.assign(process.env, env);
} catch (err) {
  // ignore if file doesn't exist
}

// Configuration - Replace with your router details or set via ENV variables
const baseConfig = {
  username: process.env.ROUTER_USER || 'root',
  password: process.env.ROUTER_PASSWORD || '', // Leave empty if using key agent or no password
  timeout: 10000,
  debug: true, // Set to true for verbose logging
  pingCheck: true, // Enable active pinging
};

async function runTest() {
  // 0. Test Discovery
  console.log('--- 0. Network Discovery ---');
  let discovered = [];
  try {
    discovered = await OpenWRTRouter.discover({ timeout: 2000, silent: false });
    console.log(`Discovered ${discovered.length} OpenWRT routers:`);
    discovered.forEach((r) => console.log(` - ${r.ip} (${r.hostname || 'N/A'})`));
  } catch (e) {
    console.error('Discovery failed:', e.message);
    return;
  }

  if (discovered.length === 0) {
    console.log('No routers found. Exiting.');
    return;
  }

  const routerInstances = []; // Store objects { router, staticInfo, ip }

  console.log('\n--- 1. Connecting and Fetching Static Data ---');

  for (const discRouter of discovered) {
    console.log(`\nProcessing ${discRouter.ip} (${discRouter.hostname})...`);
    const config = { ...baseConfig, host: discRouter.ip };
    const router = new OpenWRTRouter(config);
    routerInstances.push(router);

    try {
      // 1. Test Login
      await router.login();
      console.log(`[${discRouter.ip}] Login successful.`);

      // 2. Test Static Router Info (Hardware, Firmware, Interfaces)
      // console.log('\n--- 1. Fetching Static Router Info ---');
      console.time(`[${discRouter.ip}] getStaticRouterInfo`);
      const staticInfo = await router.getStaticRouterInfo();
      console.timeEnd(`[${discRouter.ip}] getStaticRouterInfo`);
      console.log(`[${discRouter.ip}] Model: ${staticInfo.model}, FW: ${staticInfo.firmwareVersion}, LuCI: ${staticInfo.luciVersion}`);
      console.log(`[${discRouter.ip}] Roles: DHCP=${staticInfo.isDhcpServer}, Firewall=${staticInfo.isFirewall}, Router=${staticInfo.isInternetRouter}, AP=${staticInfo.isAp}`);

      if (baseConfig.debug && staticInfo.cpuMaxFreq) console.log(`[${discRouter.ip}] Max Frequencies: ${staticInfo.cpuMaxFreq.join('/')} MHz`);

      // 3. Package Status
      console.log(`[${discRouter.ip}] Packages: nlbwmon=${router.isNlbwmonInstalled} (DB on RAM: ${staticInfo.nlbwmonDbOnRam}), etherwake=${router.isEtherWakeInstalled}`);

      // 4. WiFi & Radio Info (Static)
      if (staticInfo.wifi && staticInfo.wifi.length > 0) {
        staticInfo.wifi.forEach((radio) => {
          console.log(`[${discRouter.ip}] Radio ${radio.radio}: Ch ${radio.channel}, Ifaces: ${radio.interfaces.length}`);
        });
      }

      // 5. Update Options
      router.updateOptions({ timeout: 12000 });

      // Store for polling loop
      // We need to replace the router instance in the array with the object containing metadata
      routerInstances.pop();
      routerInstances.push({ router, staticInfo, ip: discRouter.ip });

    } catch (e) {
      console.error(`[${discRouter.ip}] Failed: ${e.message}`);
    }
  }

  if (routerInstances.length === 0) {
    console.log('No routers connected. Exiting.');
    return;
  }

  console.log('\n--- 2. Starting Polling Loop (5 iterations, 15s interval) ---');

  const lastDeviceTraffic = new Map(); // mac -> protocolTraffic

  for (let i = 1; i <= 5; i++) {
    console.log(`\n=== Poll #${i} ===`);
    const routerData = [];

    for (const instance of routerInstances) {
      const { router, staticInfo, ip } = instance;
      try {
        console.time(`[${ip}] getRouterStatus`);
        const status = await router.getRouterStatus();
        console.timeEnd(`[${ip}] getRouterStatus`);

        const cpuFreq = status.routerInfo.cpuFreq && status.routerInfo.cpuFreq.length ? ` (${status.routerInfo.cpuFreq.join('/')} MHz)` : '';
        const cpuScaling = status.routerInfo.cpuScaling !== null ? ` [${status.routerInfo.cpuScaling}%]` : '';
        const cpuUsage = status.routerInfo.cpuUsage !== null ? `${status.routerInfo.cpuUsage}%` : 'calc...';
        const currentErrors = (status.routerInfo.wan?.stats?.rxErrors || 0)
          + (status.routerInfo.wan?.stats?.rxDrops || 0)
          + (status.routerInfo.wan?.stats?.txErrors || 0)
          + (status.routerInfo.wan?.stats?.txDrops || 0);

        let errorRate = 0;
        const routerTime = status.routerInfo.timestamp || (status.routerInfo.localtime ? status.routerInfo.localtime.getTime() : Date.now());
        if (instance.lastStats && (routerTime - instance.lastStats.time > 0)) {
          errorRate = Math.round((currentErrors - instance.lastStats.errors) * (60000 / (routerTime - instance.lastStats.time)));
        }
        instance.lastStats = { time: routerTime, errors: currentErrors };

        // eslint-disable-next-line max-len
        console.log(`[${ip}] Clients: ${status.routerInfo.totalClientCount}, CPU: ${cpuUsage}${cpuFreq}${cpuScaling}, Mem: ${status.routerInfo.memory.usage}%, PktErr: ${errorRate}/min, Ts: ${routerTime}`);

        // Firewall Check (Sample on first run)
        if (i === 1 && status.attachedDevices.length > 0) {
          const testMac = status.attachedDevices[0].mac;
          const isBlocked = await router.isDeviceBlocked(testMac);
          console.log(`[${ip}] Firewall check (${testMac}): ${isBlocked}`);
        }

        if (baseConfig.debug && i === 1) {
          console.log(`[${ip}] Raw Status Object Keys:`, Object.keys(status));
        }

        routerData.push({
          routerInfo: {
            routerId: staticInfo.uniqueId,
            routerName: staticInfo.hostname,
            isInternetRouter: staticInfo.isInternetRouter,
          },
          attachedDevices: status.attachedDevices,
        });
      } catch (e) {
        console.error(`[${ip}] Poll failed: ${e.message}`);
      }
    }

    // Aggregation
    const registeredRouterIds = routerData.map((d) => d.routerInfo.routerId);
    let aggregatedDevices = [];
    for (const data of routerData) {
      aggregatedDevices = OpenWRTRouter.aggregateDevices(data.routerInfo, data.attachedDevices, registeredRouterIds);
    }

    console.log(`Total Aggregated Devices: ${aggregatedDevices.length}`);

    // Update history and calculate display strings for all devices
    aggregatedDevices.forEach((d) => {
      d._displayProtocol = '';

      if (d.protocolTraffic) {
        const trafficToUse = {};
        // Initialize with 0 rate for all protocols present
        for (const p of Object.keys(d.protocolTraffic)) {
          trafficToUse[p] = { rx: 0, tx: 0 };
        }

        const previousTraffic = lastDeviceTraffic.get(d.mac);
        if (previousTraffic) {
          const deltaTime = d.deviceTimestamp && previousTraffic.deviceTimestamp
            ? d.deviceTimestamp - previousTraffic.deviceTimestamp
            : d.lastSeen - previousTraffic.lastSeen;
          const seconds = deltaTime / 1000;
          if (seconds > 0) {
            for (const [p, stats] of Object.entries(d.protocolTraffic)) {
              const old = previousTraffic.protocolTraffic[p] || { rx: 0, tx: 0, count: 0 };
              let rx = stats.rx - old.rx;
              let tx = stats.tx - old.tx;
              if (rx < 0) rx = stats.rx;
              if (tx < 0) tx = stats.tx;
              const rxMbps = (rx * 8) / (seconds * 1000000);
              const txMbps = (tx * 8) / (seconds * 1000000);
              trafficToUse[p] = { rx: rxMbps, tx: txMbps, delta: rx + tx };
            }
          }
        }
        lastDeviceTraffic.set(d.mac, { lastSeen: d.lastSeen, deviceTimestamp: d.deviceTimestamp, protocolTraffic: d.protocolTraffic });

        const protos = Object.entries(trafficToUse);
        protos.sort((a, b) => {
          const rateA = a[1].rx + a[1].tx;
          const rateB = b[1].rx + b[1].tx;
          if (Math.abs(rateA - rateB) > 0.001) return rateB - rateA;

          const totalA = d.protocolTraffic[a[0]].rx + d.protocolTraffic[a[0]].tx;
          const totalB = d.protocolTraffic[b[0]].rx + d.protocolTraffic[b[0]].tx;
          return totalB - totalA;
        });

        const topProtos = protos.slice(0, 5).map((p) => {
          const mbps = (p[1].rx + p[1].tx).toFixed(2);
          const totalBytes = d.protocolTraffic[p[0]].rx + d.protocolTraffic[p[0]].tx;
          const totalMB = (totalBytes / 1024 / 1024).toFixed(1);
          const delta = trafficToUse[p[0]]?.delta || 0;
          const deltaStr = delta > 0 ? ` +${(delta / 1024).toFixed(1)}KB` : '';
          return `${p[0]}: ${mbps}Mbps (${totalMB}MB${deltaStr})`;
        }).join(', ');

        const maxRate = protos.length > 0 ? (protos[0][1].rx + protos[0][1].tx) : 0;
        const threshold = maxRate * 0.1;

        const generic = [
          'tcp', 'udp', 'http', 'https', 'quic', 'tls', 'ssl', 'unknown',
          'google-cloud-messaging', 'google cloud messaging',
          'apple push service', 'apple-push-service', 'imaps', 'imap', 'mdns', 'icmp',
          'xmpp', 'dns', 'dns-over-tls',
        ];

        const specific = protos.find((p) => {
          const rate = p[1].rx + p[1].tx;
          return !generic.includes(p[0].toLowerCase()) && rate > threshold;
        });
        const p = specific || protos[0];
        d._displayProtocol = ` [Dominant: ${p ? p[0] : 'None'}] [All: ${topProtos}]`;
      } else if (d.traffic?.connections) {
        const conns = { ...d.traffic.connections };
        delete conns.total;
        const sorted = Object.entries(conns).sort((a, b) => b[1] - a[1]);

        const maxConns = sorted.length > 0 ? sorted[0][1] : 0;
        const threshold = maxConns * 0.1;

        const generic = [
          'tcp', 'udp', 'http', 'https', 'quic', 'tls', 'ssl', 'unknown',
          'google-cloud-messaging', 'google cloud messaging',
          'apple push service', 'apple-push-service', 'imaps', 'imap', 'mdns', 'icmp',
          'xmpp', 'dns', 'dns-over-tls',
        ];

        const specific = sorted.find((p) => !generic.includes(p[0].toLowerCase()) && p[1] > threshold);
        if (specific) d._displayProtocol = ` [Proto: ${specific[0]}]`;
        else if (sorted.length > 0) d._displayProtocol = ` [Proto: ${sorted[0][0]}]`;
      }
    });

    // Print full list on last poll
    if (i === 5) {
      aggregatedDevices.sort((a, b) => {
        const ipA = a.ip === 'unknown' ? '0.0.0.0' : a.ip;
        const ipB = b.ip === 'unknown' ? '0.0.0.0' : b.ip;
        return ipA.localeCompare(ipB, undefined, { numeric: true });
      });

      aggregatedDevices.forEach((d) => {
        let extra = '';
        if (d.wifi) {
          extra += ` [WiFi: ${d.wifi.ssid} ${d.wifi.signal}dBm`;
          if (d.wifi.frequency) extra += `, ${d.wifi.frequency}MHz`;
          if (d.wifi.rxChannelWidth) extra += `, ${d.wifi.rxChannelWidth}MHz`;
          if (d.wifi.rxMcs !== null) extra += `, MCS${d.wifi.rxMcs}`;
          if (d.wifi.inactiveTime) extra += `, Inactive: ${Math.round(d.wifi.inactiveTime / 60000)}m`;
          extra += ']';
        }
        if (d.connectedVia === 'uplink') extra += ' [UPLINK]';

        console.log(`- [${d.mac}] ${d.name} (${d.ip})`);
        console.log(`    Via: ${d.connectedVia} on ${d.routerName} (${d.interface || 'N/A'})${extra}${d._displayProtocol || ''}`);
      });
    }

    if (i < 5) {
      // console.log('Waiting 15s...');
      await new Promise((resolve) => setTimeout(resolve, 15000));
    }
  }

  console.log('\n--- 3. Cleanup ---');
  for (const { router } of routerInstances) {
    try {
      await router.logout();
    } catch (e) { }
  }
  console.log('\nLogging out...');
  console.log('Done.');
  process.exit(0);
}

runTest();
