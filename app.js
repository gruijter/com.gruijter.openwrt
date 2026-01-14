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
    // custom trigger cards
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

    // custom action cards
    // const actionListeners = [];
    // const actionList = Homey.manifest.flow.actions;
    // actionList.forEach((action, index) => {
    //   this.log('setting up flow action listener', action.id);
    //   actionListeners[index] = this.homey.flow.getActionCard(action.id);
    //   actionListeners[index].registerRunListener(async (args) => {
    //     try {
    //       // special case for force poll
    //       if (action.id === 'force_poll') {
    //         args.device.log(`Flow action ${action.id} called.`);
    //         this.everyXminutesHandler().catch(this.error);
    //         return;
    //       }
    //       // all other actions
    //       args.device.log(`Flow action ${action.id} called with value ${args.val}`);
    //       await args.device.handleFlowAction({ action: action.id, val: args.val });
    //     } catch (error) {
    //       this.error(error);
    //     }
    //   });
    // });
  }

};
