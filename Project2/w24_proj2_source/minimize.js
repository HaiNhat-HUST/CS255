'use strict'

/** ******* Imports ********/
const { subtle } = require('node:crypto').webcrypto

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
    this.EGKeyPair = await generateEG()
    const certificate = {
      username: username,
      publicKey: this.EGKeyPair.pub,
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
    const certString = JSON.stringify(certificate);
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!isValid) throw new Error('Invalid certificate signature');
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
  
    if (!this.certs[name]) throw new Error('No certificate found for receiver: ${name}'); 
      
    if (!this.conns[name]) await this._initConnection(name);

    const conn = this.conns[name];
    const iv = genRandomSalt();

    // SEND RATCHET
    const messageKey = await HMACtoAESKey(conn.chainKey, "message");           //HMACtoAESKey to create key for enc message
    const nextChainKey = await HMACtoHMACKey(conn.chainKey, "chain");
    conn.chainKey = nextChainKey;
    
    const header = {
      senderPubKey: this.EGKeyPair.pub,               //sender public key
      messageNum: conn.sendCounter || 0,
      receiverIV: iv
    };
       
    const ciphertext = await encryptWithGCM(messageKey, plaintext, iv, JSON.stringify(header));
    conn.sendCounter = (conn.sendCounter || 0) + 1;
    
    return [header, ciphertext]
  };

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
    
    if (!this.certs[name]) throw new Error(`No certificate found for sender: ${name}`);

    if (!this.conns[name]) await this._initConnection(name);

    const conn = this.conns[name];
    const senderPubKey = header.senderPubKey;
    const messageNum = header.messageNum || 0;
    const iv = header.receiverIV;
    
    // check mesage number to prevent relay attacks
    if (messageNum < (conn.recvCounter || 0)) {
      throw new Error('Message number too old - possible replay attack')
    }

    // Perform DH ratchet if recv new publicKey 
    const lastPubKeyStr = conn.lastReceivedPubKey ? JSON.stringify(conn.lastReceivedPubKey) : null;
    if (!lastPubKeyStr || lastPubKeyStr !== JSON.stringify(senderPubKey)){
      const sharedSecret = await computeDH(this.EGKeyPair.sec, senderPubKey)
      const [newRootKey, newChainKey] = await HKDF(sharedSecret, conn.rootKey, "ratchet");

      conn.rootKey = newRootKey;
      conn.chainKey = newChainKey;
      conn.lastReceivedPubKey = senderPubKey;
      conn.recvCounter = 0
    }

    // Check if we need to advance the chain to match message number
    while ((conn.recvCounter || 0) < messageNum) {
      conn.chainKey = await HMACtoHMACKey(conn.chainKey, "chain");
      conn.recvCounter = (conn.recvCounter || 0) + 1;
    }

    const messageKey = await HMACtoAESKey(conn.chainKey, "message");
    conn.chainKey = await HMACtoHMACKey(conn.chainKey, "chain");

    // decrypt message
    // try {
    
    const plaintextBuf = await decryptWithGCM(messageKey, ciphertext, iv, JSON.stringify(header));
    conn.recvCounter = (conn.recvCounter || 0) + 1;
    const plaintext = bufferToString(plaintextBuf);
    return plaintext;

    // } catch (e) {
    //   throw new Error('Decryption failed: ' + e.message)
    // }
  };

  async _initConnection(name){
    const recipientPubKey = this.certs[name].publicKey;    
    const sharedSecret = await computeDH(this.EGKeyPair.sec,recipientPubKey);
    
    //Initial RootKey
    const salt = await subtle.importKey(
      'raw',
      new Uint8Array(32),  // 32 bytes của 0x00 (giá trị mặc định khi khởi tạo)
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // create chain key for ROOTKEYCHAIN and new chain key for SENDKEYCHAIN
    const [rootKey, chainKey] = await HKDF(sharedSecret, salt, "initial");
    // add connection info to conns
    this.conns[name]={
      rootKey,
      chainKey,
      lastReceivedPubkey: null,       // this is removable
      sendCounter: 0,                 // use for send key chain
      recvCounter: 0                  // use for recv key chain 
    }
  }
};

module.exports = {
  MessengerClient
}
