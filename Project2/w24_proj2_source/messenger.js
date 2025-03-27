'use strict'

/** ******* Imports ********/

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
    //generate keypair 
    const keyPair = await generateEG();
    this.EGKeyPair = keyPair;

    const certificate = {
      username: username,
      pub: keyPair.pub,     //public key of the keypair
      timestamp: Date.now()     //prevent replay attack
    }


    return certificate
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
    const certString = JSON.stringify(certificate);
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!isValid) {
      throw new Error('Invalid certificate signature')
    }
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
    
    if (!this.certs[name]) throw new Error('No certificate found for recipient')

    const recipientCert = this.certs[name];
    const recipientPubKey = recipientCert.pub;

    // computeDH output used for generate RootKey
    const sharedSecret = await computeDH(this.EGKeyPair.sec, recipientPubKey);
    
    const aesKey = await HMACtoAESKey(sharedSecret, 'message encryption');
    const iv = genRandomSalt();

    // for government access keys
    // const govSecret = await computeDH(this.EGKeyPair.sec, this.govPublicKey);
    // const govKey = await HMACtoAESKey(govSecret, govEncryptionDataStr);
    // const ivGov = genRandomSalt();
    // const cGov = await encryptWithGCM(govKey, aesKey, ivGov);


    const header = {
      sender: this.EGKeyPair.pub,               //sender public key
      receiverIV: iv
      // vGov: this.govPublicKey,
      // cGov: cGov,
      // ivGov: ivGov
    };

    //enc message including header with AES-GCM
    const ciphertext = await encryptWithGCM(aesKey, plaintext, iv, JSON.stringify(header));

    return [header, ciphertext]
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
    //check if sender certificate
    if (!this.certs[name]) {
      throw new Error('No certificate found for sender');
    }

    const senderCert = this.certs[name];
    const sharedSecret = await computeDH(this.EGKeyPair.sec, senderCert.pub);
    const aesKey = await HMACtoAESKey(sharedSecret, 'message encryption');

    const bufferPlaintext = await decryptWithGCM(aesKey, ciphertext, header.receiverIV, JSON.stringify(header));
    
    const plaintext = bufferToString(bufferPlaintext);
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
