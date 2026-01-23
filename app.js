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

const Homey = require('homey');

module.exports = class MyApp extends Homey.App {

  async onInit() {
    this.registerFlowListeners(); // register flow listeners
    this.log('OpenWRT app has been initialized');
  }

  async onUninit() {
    this.log('app onUninit called');
    // this.homey.removeAllListeners('lastData');
  }

  registerFlowListeners() {
    // autocomplete functions
    const autoCompleteMac = async (query, args) => {
      const list = [];
      if (args.device.knownDevices) {
        Object.keys(args.device.knownDevices).forEach((key) => {
          const device = args.device.knownDevices[key];
          if (!device.mac) return;
          list.push({
            name: device.mac,
            description: device.name || 'unknown',
          });
        });
      }
      const results = list.filter((result) => { // filter for query on MAC and Name
        const macFound = result.name.toLowerCase().indexOf(query.toLowerCase()) > -1;
        const nameFound = result.description.toLowerCase().indexOf(query.toLowerCase()) > -1;
        return macFound || nameFound;
      });
      return results;
    };

    const autoCompleteSsid = async (query, args) => {
      const interfaces = args.device.wifiInterfaces || [];
      const results = interfaces
        .filter((iface) => iface.name.toLowerCase().includes(query.toLowerCase()))
        .map((iface) => ({
          name: iface.name,
          description: `Radio: ${iface.device}`,
          ssid: iface.ssid,
          device: iface.device,
        }));
      return results;
    };

    const autoCompleteRadio = async (query, args) => {
      const radios = args.device.wifiRadios || [];
      const results = radios
        .filter((radio) => radio.name.toLowerCase().includes(query.toLowerCase()));
      return results;
    };

    // custom device trigger cards
    const triggerList = Homey.manifest.flow.triggers;
    triggerList.forEach((trigger, index) => {
      this.log('setting up flow trigger method', trigger.id);
      this[`_${trigger.id}`] = this.homey.flow.getDeviceTriggerCard(trigger.id);
      this[`trigger_${trigger.id}`] = (device, tokens, state) => {
        this[`_${trigger.id}`]
          .trigger(device, tokens) // , state)
          // .then(this.log(device.getName(), tokens, state))
          .catch(this.error);
      };
    });

    // custom device condition cards
    const conditionListeners = [];
    const conditionList = Homey.manifest.flow.conditions;
    conditionList.forEach((condition, index) => {
      this.log('setting up flow condition listener', condition.id);
      conditionListeners[index] = this.homey.flow.getConditionCard(condition.id);
      if (condition.args) {
        condition.args.forEach((arg) => {
          if (arg.type === 'autocomplete') {
            if (arg.name === 'mac') conditionListeners[index].registerArgumentAutocompleteListener('mac', autoCompleteMac);
            if (arg.name === 'ssid') conditionListeners[index].registerArgumentAutocompleteListener('ssid', autoCompleteSsid);
            if (arg.name === 'radio') conditionListeners[index].registerArgumentAutocompleteListener('radio', autoCompleteRadio);
          }
        });
      }
      conditionListeners[index].registerRunListener(async (args) => {
        args.device.log(`Flow condition ${condition.id} called`);
        return args.device.handleFlowCondition({ condition: condition.id, args });
      });
    });

    // custom device action cards
    const actionListeners = [];
    const actionList = Homey.manifest.flow.actions;
    actionList.forEach((action, index) => {
      this.log('setting up flow action listener', action.id);
      actionListeners[index] = this.homey.flow.getActionCard(action.id);
      if (action.args) {
        action.args.forEach((arg) => {
          if (arg.type === 'autocomplete') {
            if (arg.name === 'mac') actionListeners[index].registerArgumentAutocompleteListener('mac', autoCompleteMac);
            if (arg.name === 'ssid') actionListeners[index].registerArgumentAutocompleteListener('ssid', autoCompleteSsid);
            if (arg.name === 'radio') actionListeners[index].registerArgumentAutocompleteListener('radio', autoCompleteRadio);
          }
        });
      }
      actionListeners[index].registerRunListener(async (args) => {
        try {
          args.device.log(`Flow action ${action.id} called`);
          await args.device.handleFlowAction({ action: action.id, args });
        } catch (error) {
          this.error(error);
        }
      });
    });
  }

};
