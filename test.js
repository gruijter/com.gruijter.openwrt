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
  debug: false,
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

  const routerInstances = [];
  const routerData = [];

  console.log('\n--- 1. Connecting and Fetching Data from All Routers ---');

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
      const staticInfo = await router.getStaticRouterInfo();
      console.log(`[${discRouter.ip}] Model: ${staticInfo.model}, FW: ${staticInfo.firmwareVersion}`);
      console.log(`[${discRouter.ip}] Roles: DHCP=${staticInfo.isDhcpServer}, Firewall=${staticInfo.isFirewall}, Router=${staticInfo.isInternetRouter}, AP=${staticInfo.isAp}`);

      // 3. Package Status
      console.log(`[${discRouter.ip}] Packages: nlbwmon=${router.isNlbwmonInstalled}, etherwake=${router.isEtherWakeInstalled}`);

      // 4. Test Router Status (Live stats)
      // console.log('\n--- 3. Fetching Router Status ---');
      let status = await router.getRouterStatus();

      // CPU usage requires two samples to calculate load.
      if (status.routerInfo.cpuUsage === null) {
        console.log(`[${discRouter.ip}] Waiting 2s for CPU stats...`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
        status = await router.getRouterStatus();
      }

      console.log(`[${discRouter.ip}] Clients: ${status.routerInfo.totalClientCount}, CPU: ${status.routerInfo.cpuUsage}%, Mem: ${status.routerInfo.memory.usage}%`);

      // 5. Firewall Check
      if (status.attachedDevices.length > 0) {
        const testMac = status.attachedDevices[0].mac;
        const isBlocked = await router.isDeviceBlocked(testMac);
        console.log(`[${discRouter.ip}] Firewall check (${testMac}): ${isBlocked}`);
      }

      // 6. WiFi & Radio Info
      if (staticInfo.wifi && staticInfo.wifi.length > 0) {
        staticInfo.wifi.forEach((radio) => {
          console.log(`[${discRouter.ip}] Radio ${radio.radio}: Ch ${radio.channel}, Ifaces: ${radio.interfaces.length}`);
        });
      }

      // 7. Update Options
      router.updateOptions({ timeout: 12000 });

      routerData.push({
        routerInfo: {
          routerId: staticInfo.uniqueId,
          routerName: staticInfo.hostname,
          isInternetRouter: staticInfo.isInternetRouter,
        },
        attachedDevices: status.attachedDevices,
      });
    } catch (e) {
      console.error(`[${discRouter.ip}] Failed: ${e.message}`);
    }
  }

  console.log('\n--- 2. Aggregating Devices ---');

  const registeredRouterIds = routerData.map((d) => d.routerInfo.routerId);
  let aggregatedDevices = [];

  // Simulate updates from each router
  for (const data of routerData) {
    aggregatedDevices = OpenWRTRouter.aggregateDevices(data.routerInfo, data.attachedDevices, registeredRouterIds);
  }

  console.log(`Total Aggregated Devices: ${aggregatedDevices.length}`);

  // Sort by IP for easier reading
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

  console.log('\n--- 3. Cleanup ---');
  for (const router of routerInstances) {
    try {
      await router.logout();
    } catch (e) { }
  }
  console.log('\nLogging out...');
  console.log('Done.');
  process.exit(0);
}

runTest();
