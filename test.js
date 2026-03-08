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
  // 0. Test Discovery
  console.log('--- 0. Network Discovery ---');
  try {
    const discovered = await OpenWRTRouter.discover({ timeout: 1000, silent: true });
    console.log(`Discovered ${discovered.length} OpenWRT routers:`);
    discovered.forEach((r) => console.log(` - ${r.ip} (${r.hostname || 'N/A'})`));
  } catch (e) {
    console.error('Discovery failed:', e.message);
  }

  console.log(`Connecting to router at ${config.host}...`);
  const router = new OpenWRTRouter(config);

  try {
    // 1. Test Login
    await router.login();
    console.log('Login successful.');

    // 2. Test Static Router Info (Hardware, Firmware, Interfaces)
    console.log('\n--- 1. Fetching Static Router Info ---');
    const staticInfo = await router.getStaticRouterInfo();
    console.log('Router Model:', staticInfo.model);
    console.log('Firmware:', staticInfo.firmwareVersion);
    console.log('Kernel:', staticInfo.kernelVersion);
    console.log('Firewall Active:', staticInfo.isFirewall);
    console.log('WiFi Interfaces:', staticInfo.wifiInterfaces);
    console.log('WAN IP:', staticInfo.wan.ipAddress);

    // 3. Package Status
    console.log('\n--- 2. Package Status ---');
    console.log('nlbwmon installed:', router.isNlbwmonInstalled);
    console.log('etherwake installed:', router.isEtherWakeInstalled);

    // 4. Test Router Status (Live stats)
    console.log('\n--- 3. Fetching Router Status ---');
    const status = await router.getRouterStatus();

    // CPU usage requires two samples to calculate load.
    if (status.routerInfo.cpuUsage === null) {
      console.log('First poll (CPU usage needs diff)... waiting 2s...');
      await new Promise((resolve) => setTimeout(resolve, 2000));
      Object.assign(status, await router.getRouterStatus());
    }

    console.log('CPU Usage:', status.routerInfo.cpuUsage, '%');
    console.log('Memory Usage:', status.routerInfo.memory.usage, '%');
    console.log('Total Clients:', status.routerInfo.totalClientCount);

    // 5. Test Attached Devices
    console.log('\n--- 4. Attached Devices ---');
    const devices = status.attachedDevices;
    console.log(`Found ${devices.length} devices.`);
    devices.forEach((d) => {
      console.log(`- [${d.mac}] ${d.name} (${d.ip}) via ${d.connectedVia} (${d.interface || 'N/A'})`);
    });

    // 6. Test Firewall Block Check
    console.log('\n--- 5. Firewall Check ---');
    if (devices.length > 0) {
      const testMac = devices[0].mac;
      console.log(`Checking block status for ${testMac}...`);
      const isBlocked = await router.isDeviceBlocked(testMac);
      console.log(`Device ${testMac} blocked status:`, isBlocked);
    } else {
      console.log('No devices available to test firewall check.');
    }

    // 7. WiFi & Radio
    console.log('\n--- 6. WiFi & Radio Info ---');
    if (staticInfo.wifi && staticInfo.wifi.length > 0) {
      staticInfo.wifi.forEach((radio) => {
        console.log(`Radio ${radio.radio}: Channel ${radio.channel}, Interfaces: ${radio.interfaces.length}`);
      });
    } else {
      console.log('No WiFi radios found.');
    }

    // 8. Other Methods (Skipped)
    console.log('\n--- 7. Other Methods (Skipped) ---');
    console.log('Skipping: installNlbwmon, installEtherWake, wakeOnLan, reboot, setWifiState, setRadioState, setDeviceTTL, setDevice');

    // 9. Update Options
    console.log('\n--- 8. Update Options ---');
    router.updateOptions({ timeout: 12000 });
    console.log('Options updated (timeout: 12000)');

  } catch (error) {
    console.error('Test failed:', error);
  } finally {
    console.log('\nLogging out...');
    await router.logout();
    process.exit(0);
  }
}

runTest();
