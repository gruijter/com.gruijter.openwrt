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
const config = {
  host: process.env.ROUTER_HOST || '192.168.1.1',
  username: process.env.ROUTER_USER || 'root',
  password: process.env.ROUTER_PASSWORD || '', // Leave empty if using key agent or no password
  timeout: 10000,
  debug: true,
};

async function runTest() {
  console.log(`Connecting to router at ${config.host}...`);
  const router = new OpenWRTRouter(config);

  try {
    // 1. Test Login
    await router.login();
    console.log('Login successful.');

    // 2. Test Static Router Info (Hardware, Firmware, Interfaces)
    console.log('\n--- Fetching Static Router Info ---');
    const staticInfo = await router.getStaticRouterInfo();
    console.log('Router Model:', staticInfo.model);
    console.log('Firmware:', staticInfo.firmwareVersion);
    console.log('Kernel:', staticInfo.kernelVersion);
    console.log('Firewall Active:', staticInfo.isFirewall);
    console.log('WiFi Interfaces:', staticInfo.wifiInterfaces);
    console.log('WAN IP:', staticInfo.wan.ipAddress);
    // console.log('Full Static Info:', JSON.stringify(staticInfo, null, 2));

    // 3. Test Router Status (Live stats)
    console.log('\n--- Fetching Router Status ---');
    const status = await router.getRouterStatus();
    console.log('CPU Usage:', status.routerInfo.cpuUsage, '%');
    console.log('Memory Usage:', status.routerInfo.memory.usage, '%');
    console.log('Total Clients:', status.routerInfo.totalClientCount);

    // 4. Test Attached Devices
    console.log('\n--- Attached Devices ---');
    const devices = status.attachedDevices;
    console.log(`Found ${devices.length} devices.`);
    devices.forEach((d) => {
      console.log(`- [${d.mac}] ${d.name} (${d.ip}) via ${d.connectedVia} (${d.interface || 'N/A'})`);
    });

    // 5. Test Firewall Block Check (Optional)
    // const testMac = 'AA:BB:CC:DD:EE:FF';
    // const isBlocked = await router.isDeviceBlocked(testMac);
    // console.log(`\nDevice ${testMac} blocked status:`, isBlocked);

  } catch (error) {
    console.error('Test failed:', error);
  } finally {
    console.log('\nLogging out...');
    await router.logout();
    process.exit(0);
  }
}

runTest();
