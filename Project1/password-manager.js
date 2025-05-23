"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(password) {
    this.masterPassword = password;
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.kvs = {}; // Initialize kvs object
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: 
    */
  static async init(password) {
    const masterPassword = password;
    let keychain = new Keychain(password);
    keychain.kvs = {};
    return keychain;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain or false
    */
  static async load(password, repr, trustedDataCheck) {
    try {
      // Integrity check with hash
      const secretsHash = await subtle.digest(
        "SHA-256", stringToBuffer(repr));            // Extract hash from repr
      if (bufferToString(secretsHash) !== trustedDataCheck) {         // Compare extracted hash with trustedDataCheck
        throw new Error('checksum not match');
      }
  
      let kvsState = JSON.parse(repr);
      let newKeychain = new Keychain(password);
  
      // Validate the password by comparing the stored hash
      const storedHashedPassword = kvsState.hashedPassword;
      const providedHashedPassword = bufferToString(await subtle.digest("SHA-256", stringToBuffer(password)));
      if (storedHashedPassword !== providedHashedPassword) {
        throw new Error('password is incorrect'); // Throw an error if the password is incorrect
      }
  
      newKeychain.kvs = kvsState.kvs;
      return newKeychain;
    } catch (error) {
      // Log the error for debugging purposes
      console.error('Error loading keychain:', error);
      throw error; // Re-throw the error to be caught by the test
    }
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    let arr = new Array();
    const hashedPassword = bufferToString(await subtle.digest("SHA-256", stringToBuffer(this.masterPassword)));
    const kvsState = JSON.stringify({ kvs: this.kvs, hashedPassword }); // convert the json object to string for hash 
    arr.push(kvsState);      // arr[0] -> json encoding of password manager

    let kvsHash = bufferToString(await subtle.digest(
      "SHA-256", stringToBuffer(kvsState))); // SHA-256 hash for checksum 
    arr.push(kvsHash);      // arr[1] -> SHA-256 checksum (as a string)
    return arr;
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    let hmacKey = await this.deriveKeys(this.masterPassword, 'hmac-salt').then(keys => keys.hmacKey);
    let hashedName = await this.hashDomain(hmacKey, name);

    let encryptedData = this.kvs[hashedName];
    if (!encryptedData) {
      return null;
    }

    let aesKey = await this.deriveKeys(this.masterPassword, 'aes-salt').then(keys => keys.aesKey);
    return this.decryptPass(aesKey, encryptedData);
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    let hmacKey = await this.deriveKeys(this.masterPassword, 'hmac-salt').then(keys => keys.hmacKey);
    let hashedName = await this.hashDomain(hmacKey, name);

    let aesKey = await this.deriveKeys(this.masterPassword, 'aes-salt').then(keys => keys.aesKey);
    let encryptedData = await this.encryptPass(aesKey, value);

    this.kvs[hashedName] = encryptedData;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    let hmacKey = await this.deriveKeys(this.masterPassword, 'hmac-salt').then(keys => keys.hmacKey);
    let hashedName = await this.hashDomain(hmacKey, name);

    if (this.kvs[hashedName]) {
      delete this.kvs[hashedName];
      return true;
    }
    else return false;
  };

  /**Create key from password**/
  async deriveKeys(password, salt) {
    let keyMaterial = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveBits"]);
    let derivedBits = await subtle.deriveBits({ name: "PBKDF2", salt: stringToBuffer(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, 512);

    let aesKey = await subtle.importKey("raw", derivedBits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
    let hmacKey = await subtle.importKey("raw", derivedBits.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

    return { aesKey, hmacKey };
  };

  /**Encryption**/
  async encryptPass(aesKey, plaintext) {
    let iv = getRandomBytes(12);
    let encrypted = await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, stringToBuffer(plaintext));
    return { iv: encodeBuffer(iv), data: encodeBuffer(encrypted) };
  };

  /**Decyption**/
  async decryptPass(aesKey, encryptedData) {
    let iv = decodeBuffer(encryptedData.iv);
    let data = decodeBuffer(encryptedData.data);
    let decrypted = await subtle.decrypt({ name: "AES-GCM", iv }, aesKey, data);
    return bufferToString(decrypted);
  };

  /*Hide domain name by using HMAC*/
  async hashDomain(hmacKey, domain) {
    let hash = await subtle.sign("HMAC", hmacKey, stringToBuffer(domain));
    return encodeBuffer(hash);
  };
};

module.exports = { Keychain };