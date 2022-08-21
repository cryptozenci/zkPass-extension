
// compares two Uint8Arrays or Arrays
export const eq = (a, b) => {
  assert(Array.isArray(a) || a instanceof Uint8Array);
  assert(Array.isArray(b) || b instanceof Uint8Array);
  return a.length === b.length &&
    a.every((val, index) => val === b[index]);
}

// xor 2 byte arrays of equal length
export const xor = (a, b) => {
  assert(a instanceof Uint8Array && b instanceof Uint8Array);
  assert(a.length == b.length);
  var c = new Uint8Array(a.length);
  for (var i = 0; i < a.length; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}

export const getRandom = (number) => {
  return crypto.getRandomValues(new Uint8Array(number));
}

// int2ba converts Number or BigInt into a byte array,
// optionally padding it to the desired length
export const int2ba = (int, size) => {
  assert(typeof (int) == 'bigint' || typeof (int) == 'number', 'Only can convert Number or BigInt');
  let hexstr = int.toString(16);
  if (hexstr.length % 2) {
    hexstr = '0' + hexstr;
  }
  const ba = [];
  for (let i = 0; i < hexstr.length / 2; i++) {
    ba.push(parseInt(hexstr.slice(2 * i, 2 * i + 2), 16));
  }
  if (size) {
    const oldlen = ba.length;
    for (let j = 0; j < (size - oldlen); j++) {
      ba.unshift(0);
    }
  }
  return new Uint8Array(ba);
}

// converts string to byte array
export const str2ba = (str) => {
  if (typeof (str) !== 'string') {
    throw ('Only type string is allowed in str2ba');
  }
  const ba = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    ba[i] = str.charCodeAt(i);
  }
  return ba;
}

// concatTA concatenates typed arrays of type Uint8Array
export const concatTA = (...arr) => {
  let newLen = 0;
  for (const item of arr) {
    assert(item instanceof Uint8Array);
    newLen += item.length;
  }
  const newArray = new Uint8Array(newLen);
  let offset = 0;
  for (const item of arr) {
    newArray.set(item, offset);
    offset += item.length;
  }
  return newArray;
}

// ba2int converts a bit-endian byte array into a Number or BigInt
export const ba2int = (ba) => {
  assert(ba instanceof Uint8Array);
  if (ba.length <= 8) {
    let retval = 0;
    for (let i = 0; i < ba.length; i++) {
      retval |= ba[ba.length - 1 - i] << 8 * i;
    }
    return retval;
  }
  else {
    var hexstr = '';
    for (let byte of ba) {
      let hexbyte = byte.toString(16);
      if (hexbyte.length == 1) {
        hexbyte = '0' + hexbyte;
      }
      hexstr += hexbyte;
    }
    return BigInt('0x' + hexstr);
  }
}

export const assert = (condition, message) => {
  if (!condition) {
    console.trace();
    throw message || 'Failed';
  }
}

export const pem2ba = (pem) => {
  var lines = pem.split('\n');
  var encoded = '';
  for (let line of lines) {
    if (line.trim().length > 0 &&
      line.indexOf('-BEGIN CERTIFICATE-') < 0 &&
      line.indexOf('-BEGIN PUBLIC KEY-') < 0 &&
      line.indexOf('-END PUBLIC KEY-') < 0 &&
      line.indexOf('-END CERTIFICATE-') < 0) {
      encoded += line.trim();
    }
  }
  return b64decode(encoded);
}

export const b64decode = (str) => {
  let dec;
  if (typeof (window) === 'undefined') {
    dec = Buffer.from(str, 'base64');
  }
  else {
    dec = atob(str).split('').map(function (c) {
      return c.charCodeAt(0);
    });
  }
  return new Uint8Array(dec);
}

export const sortKeys = (obj) => {
  const numArray = Object.keys(obj).map(function (x) { return Number(x); });
  return numArray.sort(function (a, b) { return a - b; });
}

export const bytesToBits = (ba) => {
  assert(ba instanceof Uint8Array);
  const bitArr = Array(ba.length * 8);
  let idx = 0;
  for (let i = ba.length - 1; i >= 0; i--) {
    for (let j = 0; j < 8; j++) {
      bitArr[idx] = (ba[i] >> j) & 0x01;
      idx++;
    }
  }
  return bitArr;
}

export const splitIntoChunks = (ba, chunkSize) => {
  assert(ba instanceof Uint8Array);
  assert(ba.length % chunkSize === 0);
  const newArray = [];
  const chunkCount = ba.length / chunkSize;
  for (let i = 0; i < chunkCount; i++) {
    newArray.push(ba.slice(i * chunkSize, (i + 1) * chunkSize));
  }
  return newArray;
}

export const ba2str = (ba) => {
  assert(ba instanceof Uint8Array);
  let result = '';
  for (const b of ba) {
    result += String.fromCharCode(b);
  }
  return result;
}
