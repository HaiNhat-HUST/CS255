"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; 
const MAX_PASSWORD_LENGTH = 64;  
const PBKDF2_SALT_LENGTH = 16;   
const AES_GCM_IV_LENGTH = 12;     

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   * You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor(kvs, salt, aesKey, hmacKey, metadata) {
    this.kvs = kvs; 
    this.salt = salt; 
    this.aesKey = aesKey; 
    this.hmacKey = hmacKey;
    this.metadata = metadata;
  };


  static async deriveKeys(password, salt) {

    let keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveBits"] 
    );

  
    let derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt, 
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256" 
      },
      keyMaterial,
      512 
    );

   
    
    let aesKeyMaterial = derivedBits.slice(0, 32); 
    let hmacKeyMaterial = derivedBits.slice(32, 64);

    // Import AES-GCM key [cite: 112]
    let aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial,
      "AES-GCM",
      false, 
      ["encrypt", "decrypt"] 
    );

    // Import HMAC key [cite: 102]
    let hmacKey = await subtle.importKey(
      "raw",
      hmacKeyMaterial,
      { name: "HMAC", hash: "SHA-256" }, 
      false, 
      ["sign", "verify"] 
    );

    return { aesKey, hmacKey };
  };

  /**
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    * password: string
    * Return Type: Promise<Keychain>
    */
  static async init(password) {
    const kvs = {};
    const salt = getRandomBytes(PBKDF2_SALT_LENGTH); 
    const { aesKey, hmacKey } = await Keychain.deriveKeys(password, salt);
    const magicString = "CS255_PASSWORD_CHECK";
    const iv = getRandomBytes(AES_GCM_IV_LENGTH);
    const encryptedMagicString = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      stringToBuffer(magicString)
    );
    const metadata = {
      salt: encodeBuffer(salt),
      encryptedMagicString: encodeBuffer(encryptedMagicString),
      magicStringIv: encodeBuffer(iv)
    };

    return new Keychain(kvs, salt, aesKey, hmacKey, metadata);
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
    * password:           string
    * repr:               string
    * trustedDataCheck: string
    * Return Type: Promise<Keychain>
    */
  static async load(password, repr, trustedDataCheck) {
    const parsedRepr = JSON.parse(repr);
    let actualKVS = parsedRepr.kvs;
    const metadata = parsedRepr.metadata; 

    if (!metadata || !metadata.salt || !metadata.encryptedMagicString || !metadata.magicStringIv) {
      throw new Error("Invalid keychain representation: Missing metadata.");
    }

    const salt = decodeBuffer(metadata.salt); 

    
    const { aesKey, hmacKey } = await Keychain.deriveKeys(password, salt);

    try {
      const decryptedMagicStringBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: decodeBuffer(metadata.magicStringIv) },
        aesKey,
        decodeBuffer(metadata.encryptedMagicString)
      );
      const decryptedMagicString = bufferToString(decryptedMagicStringBuffer);

      if (decryptedMagicString !== "CS255_PASSWORD_CHECK") {
        throw new Error("Invalid master password."); 
      }
    } catch (e) {
      
      console.error("Error during password verification:", e);
      throw new Error("Invalid master password or corrupted data.");
    }

    if (trustedDataCheck !== undefined && trustedDataCheck !== null) { 
      const actualChecksumBuffer = await subtle.digest("SHA-256", stringToBuffer(repr)); 
      const actualChecksum = bufferToString(actualChecksumBuffer);

      if (actualChecksum !== trustedDataCheck) {
        throw new Error('Checksum mismatch: Data may have been tampered with (rollback attack).'); 
      }
    }

    return new Keychain(actualKVS, salt, aesKey, hmacKey, metadata);
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    * arr[0] = JSON encoding of password manager
    * arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: Promise<string[]>
    */
  async dump() {
    let arr = [];
    const kvsState = JSON.stringify({ kvs: this.kvs, metadata: this.metadata }); 
    arr.push(kvsState);    

    let kvsHash = bufferToString(await subtle.digest("SHA-256", stringToBuffer(kvsState))); 
    arr.push(kvsHash);     
    return arr;
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    * name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    let hashedName = await this.hashDomain(name);

    let encryptedRecord = this.kvs[hashedName];
    if (!encryptedRecord) {
      return null;
    }

    return this.decryptPass(encryptedRecord, hashedName);
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  * name: string
  * value: string
  * Return Type: Promise<void>
  */
  async set(name, value) {
    let hashedName = await this.hashDomain(name); 

    let encryptedRecord = await this.encryptPass(value, hashedName);

    this.kvs[hashedName] = encryptedRecord;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    * name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    let hashedName = await this.hashDomain(name); 

    if (this.kvs[hashedName]) {
      delete this.kvs[hashedName];
      return true;
    }
    return false;
  };


  async encryptPass(plaintext, aad) {
    
    const paddedPlaintext = plaintext.padEnd(MAX_PASSWORD_LENGTH, '\0'); 

    const iv = getRandomBytes(AES_GCM_IV_LENGTH); 
    const encodedAad = stringToBuffer(aad); 

    let encrypted = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: encodedAad },
      this.aesKey,
      stringToBuffer(paddedPlaintext)
    );

    return { iv: encodeBuffer(iv), data: encodeBuffer(encrypted) };
  };

  async decryptPass(encryptedRecord, aad) {
    const iv = decodeBuffer(encryptedRecord.iv);
    const data = decodeBuffer(encryptedRecord.data);
    const encodedAad = stringToBuffer(aad); 

    try {
      let decrypted = await subtle.decrypt(
        { name: "AES-GCM", iv: iv, additionalData: encodedAad }, 
        this.aesKey, 
        data
      );
    
      return bufferToString(decrypted).replace(/\0+$/, ''); 
    } catch (e) {
      console.error("Decryption failed (possible tampering or wrong AAD):", e);
      throw new Error("Decryption failed: possible data tampering or integrity violation (swap attack).");
    }
  };


  async hashDomain(domain) {
    let hash = await subtle.sign("HMAC", this.hmacKey, stringToBuffer(domain)); 
    return encodeBuffer(hash); 
  };
};

module.exports = { Keychain };