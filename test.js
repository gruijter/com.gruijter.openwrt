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
      console.log(`[${discRouter.ip}] Packages: nlbwmon=${router.isNlbwmonInstalled}, etherwake=${router.isEtherWakeInstalled}`);

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

  console.log('\n--- 2. Starting Polling Loop (5 iterations, 10s interval) ---');

  for (let i = 1; i <= 5; i++) {
    console.log(`\n=== Poll #${i} ===`);
    const routerData = [];

    for (const { router, staticInfo, ip } of routerInstances) {
      try {
        console.time(`[${ip}] getRouterStatus`);
        const status = await router.getRouterStatus();
        console.timeEnd(`[${ip}] getRouterStatus`);

        const cpuFreq = status.routerInfo.cpuFreq && status.routerInfo.cpuFreq.length ? ` (${status.routerInfo.cpuFreq.join('/')} MHz)` : '';
        const cpuScaling = status.routerInfo.cpuScaling !== null ? ` [${status.routerInfo.cpuScaling}%]` : '';
        const cpuUsage = status.routerInfo.cpuUsage !== null ? `${status.routerInfo.cpuUsage}%` : 'calc...';

        console.log(`[${ip}] Clients: ${status.routerInfo.totalClientCount}, CPU: ${cpuUsage}${cpuFreq}${cpuScaling}, Mem: ${status.routerInfo.memory.usage}%`);

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

    // Print full list on last poll
    if (i === 5) {
      aggregatedDevices.sort((a, b) => {
        const ipA = a.ip === 'unknown' ? '0.0.0.0' : a.ip;
        const ipB = b.ip === 'unknown' ? '0.0.0.0' : b.ip;
        return ipA.localeCompare(ipB, undefined, { numeric: true });
      });

      aggregatedDevices.forEach((d) => {
        let extra = '';
        if (d.wifi) extra += ` [WiFi: ${d.wifi.ssid} ${d.wifi.signal}dBm]`;
        if (d.connectedVia === 'uplink') extra += ' [UPLINK]';

        console.log(`- [${d.mac}] ${d.name} (${d.ip})`);
        console.log(`    Via: ${d.connectedVia} on ${d.routerName} (${d.interface || 'N/A'})${extra}`);
      });
    }

    if (i < 5) {
      // console.log('Waiting 10s...');
      await new Promise((resolve) => setTimeout(resolve, 10000));
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
