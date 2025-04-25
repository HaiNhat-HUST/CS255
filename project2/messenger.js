'use strict'

/** ******* Imports ********/
const {subtle} = require('node:crypto').webcrypto
const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    const keypair = await generateEG();
    this.EGKeyPair = keypair;

    const certificate = {
      username: username,
      publicKey: this.EGKeyPair.pub
    }

    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!isValid) throw new Error("Invalid  certificate signature");
    this.certs[certificate.username] = certificate;
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    // CHECK CERT
    if (!this.certs[name]) throw new Error(`No certificate found for ${name}`);

    if (!this.conns[name]) await this._initconnection(name);


    const conn = this.conns[name];
    const sendKey = conn.sendChain.key;
    
    
    const iv = genRandomSalt();

    // ENCRYPT KEY FOR GOVERMENT
    const {vGov, cGov, ivGov } = await this._govEnc(sendKey);
    const header = {
      vGov: vGov,
      cGov: cGov,
      ivGov: ivGov,
      receiverIV: iv
    }

    const encKey = await HMACtoAESKey(sendKey, govEncryptionDataStr);
    const ciphertext = await encryptWithGCM(encKey, plaintext, iv, JSON.stringify(header));

    //update send chain
    const [nextSendKey,_] = await HKDF(sendKey, sendKey, "nextkey");
    this.conns[name].sendChain.key = nextSendKey;
    this.conns[name].sendChain.counter += 1;

    return [header, ciphertext];
  }
  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {

    if(!this.certs[name]) throw new Error(`No certificate found for ${name}`);

    if (!this.conns[name]) await this._initconnection(name, false);

    const conn = this.conns[name];
    const recvKey = conn.recvChain.key;
    const decKey = await HMACtoAESKey(recvKey, govEncryptionDataStr);

    const plaintextBuf = await decryptWithGCM(decKey, ciphertext, header.receiverIV, JSON.stringify(header));
    const plaintext = bufferToString(plaintextBuf);

    //udpate recvChain
    const [nextRecvKey,_] = await HKDF(recvKey, recvKey, "nextkey");
    this.conns[name].recvChain.key = nextRecvKey;
    this.conns[name].recvChain.counter += 1;
    return plaintext;
  }
  
  async _initconnection(name, firstSender = true){
    const recvPublicKey = this.certs[name].publicKey;
    const sharedSecret = await computeDH(this.EGKeyPair.sec, recvPublicKey);
    const [rootKey,_] = await HKDF(sharedSecret,sharedSecret, "initRootRatchet");
    let [sendKey,recvKey] = await HKDF(rootKey, rootKey, "doubleRatchet");

    if (!firstSender) {
      [sendKey, recvKey] = [recvKey, sendKey];
    }

    this.conns[name] = {
      username: name,
      rootChain: rootKey,
      sendChain: {
        key: sendKey,
        counter: 0
      },
      recvChain: {
        key: recvKey,
        counter: 0
      }
    } 
  }

  async _govEnc(sendKey){
    const ivGov = genRandomSalt();

    const govKeyChainArrayBuffer = await subtle.exportKey("raw", sendKey);
    const govSharedSecret = await computeDH(this.EGKeyPair.sec, this.govPublicKey);
    const govEncKey = await HMACtoAESKey(govSharedSecret, govEncryptionDataStr);

    const cGov = await encryptWithGCM(govEncKey, govKeyChainArrayBuffer, ivGov);
    
    return {
      vGov: this.EGKeyPair.pub,
      cGov: cGov,
      ivGov: ivGov,
  };
  }
};

module.exports = {
  MessengerClient
}
