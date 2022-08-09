/* global SocketNode */

import {concatTA, int2ba, str2ba, assert, ba2int, getRandom, eq, xor} from './utils.js';
import {Socket} from './Socket.js';


export class TLS {
  constructor (serverName, port, headers, options){
    this.serverName = serverName;
    this.port = port;
    this.headers = headers;
    this.sid = Math.random().toString(36).slice(-10);
    this.options = options;
    this.useMaxFragmentLength = options.useMaxFragmentLength;
    this.nodeWillEncryptRequest = options.nodeWillEncryptRequest;
    this.mustVerifyCert = options.mustVerifyCert;
    // allHandshakes is a concatenation of all handshake messages up to this point.
    // This is only data visible at the handshake layer and does not include record layer headers
    this.allHandshakes;
    // certPath is an array of certificates from the server arranged by pkijs in the ascending
    // order from leaf to root
    this.certPath;
    // cke is TLS handshake's Client Key Exchange message
    this.cke;
    this.clientRandom;
    this.commPrivkey;
    this.commSymmetricKey;
    this.isMhm; // multiple handshake messages
    this.rsaSig;
    this.serverRandom;
    this.sckt;
    this.serverEcPubkey;

    if (typeof(window) !== 'undefined'){
      this.sckt = new Socket(serverName, port);
    } else {
      // in node SocketNode was made global
      this.sckt = new SocketNode(serverName, port);
    }
  }

  buildClientHello(){
    let tmp = [];
    tmp.push(0x00, 0x0a); // Type supported_groups
    tmp.push(0x00, 0x04); // Length
    tmp.push(0x00, 0x02); // Supported Groups List Length
    tmp.push(0x00, 0x17); // Supported Group: secp256r1
    const supported_groups_extension = new Uint8Array(tmp);

    tmp = [];
    tmp.push(0x00, 0x0d); // Type signature_algorithms
    tmp.push(0x00, 0x04); // Length
    tmp.push(0x00, 0x02); // Signature Hash Algorithms Length
    tmp.push(0x04, 0x01); // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
    const signature_algorithm_extension = new Uint8Array(tmp);

    tmp = [];
    const server_name = str2ba(this.serverName);
    tmp.push(0x00, 0x00); // Extension type: server_name
    tmp.push(...Array.from(int2ba(server_name.length+5, 2))); // Length
    tmp.push(...Array.from(int2ba(server_name.length+3, 2))); // Server Name List Length
    tmp.push(0x00); // Type: host name
    tmp.push(...Array.from(int2ba(server_name.length, 2))); // Server Name Length
    tmp.push(...Array.from(server_name));
    const server_name_extension = new Uint8Array(tmp);

    tmp = [];
    if (this.useMaxFragmentLength){
      tmp.push(0x00, 0x01); // Type: max_fragment_length
      tmp.push(0x00, 0x01); // Length
      // allowed values 0x01 = 512 0x02 = 1024 0x03 = 2048 0x04 = 4096
      // some servers support 0x04 but send alert if < 0x04
      tmp.push(0x04);
    }
    const max_fragment_length_extension =  new Uint8Array(tmp);

    const extlen = supported_groups_extension.length + signature_algorithm_extension.length +
      server_name_extension.length + max_fragment_length_extension.length;

    tmp = [];
    tmp.push(0x01); // Handshake type: Client Hello
    tmp.push(...int2ba(extlen + 43, 3) ); // Length
    tmp.push(0x03, 0x03); // Version: TLS 1.2
    this.clientRandom = getRandom(32);
    tmp.push(...Array.from(this.clientRandom));
    tmp.push(0x00); // Session ID Length
    tmp.push(0x00, 0x02); // Cipher Suites Length
    tmp.push(0xc0, 0x2f); // Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    tmp.push(0x01); // Compression Methods Length
    tmp.push(0x00); // Compression Method: null
    tmp.push(...int2ba(extlen, 2));
    const ch = concatTA(
      new Uint8Array(tmp),
      supported_groups_extension,
      signature_algorithm_extension,
      server_name_extension,
      max_fragment_length_extension);

    this.allHandshakes = ch;

    tmp = [];
    tmp.push(0x16); // Type: Handshake
    tmp.push(0x03, 0x03); // Version: TLS 1.2
    tmp.push(...int2ba(ch.length, 2)); // Length
    const tls_record_header = new Uint8Array(tmp);

    return concatTA(tls_record_header, ch);
  }

  parseServerHello(s){
    let p = 0;
    assert(eq(s.slice(p, p+=1), [0x02])); // Server Hello
    // eslint-disable-next-line no-unused-vars
    const shlen = ba2int(s.slice(p, p+=3));
    assert(eq(s.slice(p, p+=2), [0x03, 0x03])); // Version: TLS 1.2
    this.serverRandom = s.slice(p, p+=32);
    const sidlen = ba2int(s.slice(p, p+=1));
    if (sidlen > 0){
      p+=sidlen; // 32 bytes of session ID, if any
    }
    assert(eq(s.slice(p, p+=2), [0xc0, 0x2f])); // Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    assert(eq(s.slice(p, p+=1), [0x00])); // Compression Method: null (0)
    // May contain Extensions. We don't need to parse them
  }

  async verifyNodeSig(){}

  async parseCertificate(s){}

  async parseServerKeyExchange(k){}

  // Obsolete: encrypt request without 2PC.
  async encryptRequest(headers_str, client_write_key, client_write_IV, chunkSize){
    let headers = str2ba(headers_str);
    chunkSize = chunkSize || headers.length; // one chunk only
    const chunks = Math.ceil(headers.length/chunkSize);
    const encReq = [];
    for (let i=0; i < chunks; i++){
      let thisChunkSize = chunkSize;
      if (i == chunks-1){
        // last chunk may be smaller
        const rem = headers.length % chunkSize;
        thisChunkSize = (rem == 0) ? chunkSize : rem;
      }
      const explicit_nonce = int2ba(2+i, 8);
      // const explicit_nonce = getRandom(8)
      const nonce = concatTA(client_write_IV, explicit_nonce);
      const seq_num = 1+i;
      const aad = concatTA(
        int2ba(seq_num, 8),
        new Uint8Array([0x17, 0x03, 0x03]), // type 0x17 = Application data , TLS Version 1.2
        int2ba(thisChunkSize, 2)); // unencrypted data length in bytes
      const cwkCryptoKey = await crypto.subtle.importKey(
        'raw',
        client_write_key.buffer,
        'AES-GCM',
        true,
        ['encrypt', 'decrypt']);
      const ciphertext = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: nonce.buffer,
        additionalData: aad.buffer},
      cwkCryptoKey,
      headers.slice(chunkSize*i, chunkSize*(i+1)).buffer);
      encReq.push(concatTA(explicit_nonce, new Uint8Array(ciphertext)));
    }
    return encReq;
  }

  // ephemeral key usage time must be within the time of ephemeral key validity
  checkEphemKeyExpiration(validFrom, validUntil, time){
    time = time || Math.floor(new Date().getTime() / 1000);
    if (ba2int(validFrom) > time || time > ba2int(validUntil)){
      throw('Ephemeral key expired');
    }
  }

  async buildAndSendClientHello(){
    const ch = this.buildClientHello();
    await this.sckt.connect();
    this.sckt.send(ch); // Send Client Hello
  }

  // receiveAndParseServerHelloAndFriends receives Server Hello, Certificate,
  // Server Key Exchange, and Server Hello Done and parses them
  async receiveAndParseServerHello(){
    try{
      this.sckt.recv_timeout = 5 * 1000;
      var s = await this.sckt.recv(true);
    } catch (err){
      await this.sckt.close();
      // some incompatible websites silently do not respond to ClientHello
      throw('Failed to receive a response from a webserver. Make sure your internet connection is working and try again. If this error persists, this may mean that the webserver is not compatible with PageSigner. Please contact the PageSigner devs about this issue.');
    }
    // restore normal timeout value
    this.sckt.recv_timeout = 20 * 1000;

    // Parse Server Hello, Certificate, Server Key Exchange, Server Hello Done
    if (eq(s.slice(0, 2), [0x15, 0x03])){
      console.log('Server sent Alert instead of Server Hello');
      throw ('Unfortunately PageSigner is not yet able to notarize this website. Please contact the PageSigner devs about this issue.');
    }
    let p = 0; // current position in the byte stream
    assert(eq(s.slice(p, p+=1), [0x16])); // Type: Handshake
    assert(eq(s.slice(p, p+=2), [0x03, 0x03])); // Version: TLS 1.2
    const handshakelen = ba2int(s.slice(p, p+=2));
    // This may be the length of multiple handshake messages (MHM)
    // For MHM there is only 1 TLS Record layer header followed by Handshake layer messages
    // Without MHM, each handshake message has its own TLS Record header

    // Parse Server Hello
    const shlen = ba2int(s.slice(p+1, p+4));
    const sh = s.slice(p, p + 4 + shlen);
    this.updateAllHandshakes(sh);
    this.parseServerHello(sh);
    p = 5+4+shlen;

    if (handshakelen > shlen+4) {
      this.isMhm = true; }// multiple handshake messages
    let reclenMhm = 0;
    if (!this.isMhm){
      // read the TLS Record header
      assert(eq(s.slice(p, p+=3), [0x16, 0x03, 0x03])); // Type: Handshake # Version: TLS 1.2
      reclenMhm = ba2int(s.slice(p, p+=2));
    }

    // Parse Certificate
    const clen = ba2int(s.slice(p+1, p+4));
    if (!this.isMhm) {
      assert(reclenMhm == clen+4);}
    const c = s.slice(p, p + 4 + clen);
    this.allHandshakes = concatTA(this.allHandshakes, c);
    const cParsedByted = await this.parseCertificate(c);
    p += cParsedByted;

    if (this.isMhm && (handshakelen+5 == p)){
      // another MHM header will follow, read its header
      assert(eq(s.slice(p, p+=1), [0x16])); // Type: Handshake
      assert(eq(s.slice(p, p+=2), [0x03, 0x03])); // Version: TLS 1.2
      // eslint-disable-next-line no-unused-vars
      const handshakelen = ba2int(s.slice(p, p+=2)); // This may be the length of multiple handshake messages (MHM)
    }
    reclenMhm = 0;
    if (!this.isMhm){
      // read the TLS Record header
      assert(eq(s.slice(p, p+=3), [0x16, 0x03, 0x03])); // Type: Handshake # Version: TLS 1.2
      reclenMhm = ba2int(s.slice(p, p+=2));
    }

    // Parse Server Key Exchange
    const skelen = ba2int(s.slice(p+1, p+4));
    if (!this.isMhm){
      assert(reclenMhm == skelen+4);}
    const ske = s.slice(p, p + 4+ skelen);
    this.allHandshakes = concatTA(this.allHandshakes, ske);
    const skeParsedByted = await this.parseServerKeyExchange(ske);
    p += skeParsedByted;

    // Parse Server Hello Done
    if (!this.isMhm) {
      // read the TLS Record header
      assert(eq(s.slice(p, p+=3), [0x16, 0x03, 0x03])); // Type: Handshake # Version: TLS 1.2
      // eslint-disable-next-line no-unused-vars
      const reclen = ba2int(s.slice(p, p+=2));
    }
    const shd = s.slice(p, p+=4);
    assert(eq(shd, [0x0e, 0x00, 0x00, 0x00]));
    assert(p == s.length);
    this.updateAllHandshakes(shd);
    return this.serverEcPubkey;
  }

  // buildClientKeyExchange builds the TLS handshake's Client Key Exchange message
  // cpubBytes is client's pubkey for the ECDH
  async buildClientKeyExchange(cpubBytes){
    let tmp = [0x10]; // Handshake type: Client Key Exchange
    tmp.push(0x00, 0x00, 0x42); // Length
    tmp.push(0x41); // Pubkey Length: 65
    // 0x04 means compressed pubkey format
    this.cke = concatTA(new Uint8Array(tmp), new Uint8Array([0x04]), cpubBytes);
    this.updateAllHandshakes(this.cke);
  }

  getRandoms(){
    return [this.clientRandom, this.serverRandom];
  }

  getAllHandshakes(){
    return this.allHandshakes;
  }

  getCertPath(){
    return this.certPath;
  }

  getRSAsignature(){
    return this.rsaSig;
  }

  async sendClientFinished(){}

  updateAllHandshakes(appendMsg){
    this.allHandshakes = concatTA(this.allHandshakes, appendMsg);
  }

  // receiveServerFinished receives Change Cipher Spec and encrypted Server Finished.
  // Returns encrypted Server Finished
  async receiveServerFinished(){
    const data = await this.sckt.recv(true);

    if (eq(data.slice(0, 2), [0x15, 0x03])){
      console.log('Server sent Alert instead of Server Finished');
      throw('Server sent Alert instead of Server Finished');
    }
    // Parse CCS and Server's Finished
    const ccs_server = data.slice(0, 6);
    assert(eq(ccs_server, [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]));

    let f = null; // server finished
    if (data.length === 6) {
      // didnt receive the Server Finished, try again
      f = await this.sckt.recv(true);
    }
    else {
      f = data.slice(6);
    }

    assert (eq(f.slice(0, 5), [0x16, 0x03, 0x03, 0x00, 0x28]));
    const encSF = f.slice(5, 45); // encrypted Server Finished
    // There may be some extra data received after the Server Finished. We ignore it.
    return encSF;
  }

  async buildAndSendRequest(gctrBlocks, ghashOutputs, encRequestBlocks){
    // authTags contains authentication tag for each TLS record in the request
    // (For now there's a limit of 1 TLS record for the client request)
    const authTags = [];
    assert(ghashOutputs.length === gctrBlocks.length);
    for (let i=0; i < ghashOutputs.length; i++){
      authTags[i] = xor(ghashOutputs[i], gctrBlocks[i]);
    }

    const finalRecords = [];
    const TLSRecord = concatTA(int2ba(2, 8), ...encRequestBlocks, authTags[0]);
    finalRecords.push(TLSRecord);

    let appdata = new Uint8Array();
    for (let i=0; i< finalRecords.length; i++){
      appdata = concatTA(
        appdata,
        new Uint8Array([0x17, 0x03, 0x03]), // Type: Application data, TLS Version 1.2
        int2ba(finalRecords[i].length, 2), // 2-byte length of encrypted data
        finalRecords[i]);
    }
    console.log('sending http request');
    this.sckt.send(appdata);
  }

  // receiveServerResponse returns encrypted server response split into TLS records
  async receiveServerResponse(){}
  
  // split a raw TLS response into encrypted application layer records
  splitResponseIntoRecords(s){ }

  // verify signature over EC parameters from Server Key Exchange
  static async verifyECParamsSig(cert, ECpubkey, sig, cr, sr){}
}