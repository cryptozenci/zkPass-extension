/**
 * Available as part of the TLS
 */
import config from '../config';
import { concatTA, ba2int } from './utils.js';

export class Socket {
  constructor(name, port) {
    this.name = name;
    this.port = port;
    this.uid = Math.random().toString(36).slice(-10);

    this.buffer = new Uint8Array();
    this.connectTimeout = 5 * 1000;
    this.noDataTimeout = 5 * 1000;
    // close the socket after this time, even if it is in the middle of receiving data
    this.lifeTime = 50 * 1000;
    // delay after which we make a final check of the receicing buffer and if there was no data,
    // from the server, the we consider the data transmission finished
    this.delayBeforeFinalIteration = 500;
    this.wasClosed = false;
    this.backendPort = 20022;
  }

  async connect() {
    const _self = this;
    let timer;

    // eslint-disable-next-line no-async-promise-executor
    const response = await new Promise(async (resolve, reject) => {
      timer = setTimeout(() => {
        reject('Connect to the server failed. Please check your internet connection.');
        return;
      }, _self.connectTimeout);

      const message = { 'command': 'connect', 'args': { 'name': _self.name, 'port': _self.port }, 'uid': _self.uid };

      chrome.runtime.sendMessage(config.appId, message, (response) => { resolve(response); });
    }).catch(function (e) {
      throw (e);
    });

    chrome.runtime.lastError;
    clearTimeout(timer);

    if (response == undefined) {
      throw (undefined);
    }
    if (response.msg != 'success') {
      throw (response.msg)
    } else if (response.msg == 'success') {
      setTimeout(function () {
        if (!_self.wasClosed)
          _self.close();
      }, _self.lifeTime);

      _self.requestMore();

      return 'ready';
    }
  }

  async send(data) {
    const message = { 'command': 'send', 'args': { 'data': Array.from(data) }, 'uid': this.uid };
    chrome.runtime.sendMessage(config.appId, message);
  }

  // requestMore checks if there is any data in the buffer, if not, it requests more data from the server
  async requestMore() {
    if (this.wasClosed) {
      return;
    }
    const _self = this;
    // eslint-disable-next-line no-async-promise-executor
    const response = await new Promise(async function (resolve) {
      const message = { 'command': 'recv', 'uid': _self.uid };
      chrome.runtime.sendMessage(config.appId, message, (response) => { resolve(response); });
    });
    if (response.data.length > 0) {
      _self.buffer = concatTA(that.buffer, new Uint8Array(response.data));
    }
    setTimeout(function () {
      _self.requestMore();
    }, 200);
  }


  recv(is_handshake = false) {
    const _self = this;

    return new Promise((resolve, reject) => {
      const dataLastSeen = new Date().getTime();
      const complete_records = new Uint8Array();
      const buf = new Uint8Array();
      const resolved = false;
      const lastIteration = false;

      const finished_receiving = () => {
        resolved = true;
        resolve(complete_records);
      }

      var check = () => {
        var now = new Date().getTime();
        if ((now - dataLastSeen) > that.noDataTimeout) {
          reject('recv: no data timeout');
          return;
        }

        if (resolved) return;

        if (_self.buffer.length === 0) {
          if (lastIteration) {
            finished_receiving();
            return;
          }
          setTimeout(() => { check(); }, 200);
          return;
        }

        if (lastIteration) {
          lastIteration = false;
        }

        dataLastSeen = now;
        buf = concatTA(buf, that.buffer);
        that.buffer = new Uint8Array();
        const rv = that.check_complete_records(buf);
        complete_records = concatTA(complete_records, rv.comprecs);
        if (!rv.is_complete) {
          buf = rv.incomprecs;
          setTimeout(() => { check(); }, 200);
          return;
        } else {
          if (is_handshake) {
            return finished_receiving();
          } else {
            buf = new Uint8Array();
            lastIteration = true;
            setTimeout(() => { check(); }, _self.delayBeforeFinalIteration);
          }
        }
      };
      check();
    }).catch(function (error) {
      throw (error);
    });
  }

  async close() {
    this.wasClosed = true;

    const message = { 'command': 'close', 'uid': this.uid };

    chrome.runtime.sendMessage(config.appId, message);
  }

  check_complete_records(d) {
    let complete_records = new Uint8Array();
    while (d) {
      if (d.length < 5) {
        return {
          'is_complete': false,
          'comprecs': complete_records,
          'incomprecs': d
        };
      }
      var l = ba2int(d.slice(3, 5));
      if (d.length < (l + 5)) {
        return {
          'is_complete': false,
          'comprecs': complete_records,
          'incomprecs': d
        };
      } else if (d.length === (l + 5)) {
        return {
          'is_complete': true,
          'comprecs': concatTA(complete_records, d)
        };
      } else {
        complete_records = concatTA(complete_records, d.slice(0, l + 5));
        d = d.slice(l + 5);
        continue;
      }
    }
  }
}