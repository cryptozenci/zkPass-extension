import { getTemplate } from './chain'

export class Main {
  constructor() {
    this.messageListener

  }

  async init() {
    const _self = this
    this.messageListener = chrome.runtime.onMessage.addListener(function (data) {
      _self.disptachMessage(data)
    })
  }

  async buildRequest(templateId) {

    const [url, template, nodes] = await getTemplate(templateId)

  }

  /**
   * disptachMessage is main entry point for extension logic 
   * 
   * @param {*} data 
   */
  async disptachMessage(data) {
    if (!data || data.destination !== 'extension') return;
    switch (data.message) {

    }
  }

}

if (typeof (window) != 'undefined') {
  const main = new Main();
  main.init()
    .catch(err => {
      console.log('Error in main: ', err);
    });
}