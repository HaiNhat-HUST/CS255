"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm [cite: 93]
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters [cite: 36]
const PBKDF2_SALT_LENGTH = 16;    // 128 bits = 16 bytes for salt [cite: 88]
const AES_GCM_IV_LENGTH = 12;     // 96 bits = 12 bytes for IV recommended for AES-GCM

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

  /**
   * Derives the necessary keys from a master password and salt using PBKDF2.
   * Arguments:
   * password: string - The master password
   * salt: Buffer - The random salt
   * Return Type: Promise<{aesKey: CryptoKey, hmacKey: CryptoKey}>
   */
  static async deriveKeys(password, salt) {
    // Import raw password as key material for PBKDF2 [cite: 107, 108, 109]
    let keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveBits"] // Only allow deriving bits from this key material [cite: 101]
    );

    // Derive 512 bits (64 bytes) from PBKDF2, enough for 256-bit AES key and 256-bit HMAC key
    let derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt, // Use the provided salt [cite: 88]
        iterations: PBKDF2_ITERATIONS, // Fixed iterations [cite: 93]
        hash: "SHA-256" // Use SHA-256 for PBKDF2's PRF [cite: 98]
      },
      keyMaterial,
      512 // 256 bits for AES, 256 bits for HMAC
    );

    // Split derived bits into AES key and HMAC key material
    // Note: derivedBits is an ArrayBuffer, slice returns an ArrayBuffer
    let aesKeyMaterial = derivedBits.slice(0, 32); // First 32 bytes for AES-256
    let hmacKeyMaterial = derivedBits.slice(32, 64); // Next 32 bytes for HMAC-SHA256

    // Import AES-GCM key [cite: 112]
    let aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial,
      "AES-GCM",
      false, // Not exportable
      ["encrypt", "decrypt"] // Usages for AES-GCM [cite: 103, 114]
    );

    // Import HMAC key [cite: 102]
    let hmacKey = await subtle.importKey(
      "raw",
      hmacKeyMaterial,
      { name: "HMAC", hash: "SHA-256" }, // Algorithm and hash for HMAC
      false, // Not exportable
      ["sign", "verify"] // Usages for HMAC [cite: 102]
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
    const kvs = {}; // Empty KVS [cite: 118]
    const salt = getRandomBytes(PBKDF2_SALT_LENGTH); // Generate a random salt for PBKDF2 [cite: 87, 88, 89]

    // Derive keys using the master password and the newly generated salt
    const { aesKey, hmacKey } = await Keychain.deriveKeys(password, salt);

    // Create a "magic string" for password verification during load
    // This value is encrypted once and stored. If password is correct, it decrypts correctly.
    // If password is wrong, decryption will fail or result in garbage.
    const magicString = "CS255_PASSWORD_CHECK";
    const iv = getRandomBytes(AES_GCM_IV_LENGTH);
    const encryptedMagicString = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      stringToBuffer(magicString)
    );

    // Store the encrypted magic string and its IV for later verification
    const metadata = {
      salt: encodeBuffer(salt), // Store salt in plaintext [cite: 90]
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

    // Integrity check with trustedDataCheck (rollback attack defense) [cite: 78]
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

  /**
   * Pads the plaintext to MAX_PASSWORD_LENGTH and encrypts it using AES-GCM.
   * Arguments:
   * plaintext: string - The password to encrypt
   * aad: string - Additional Authenticated Data (hashed domain name) for integrity protection
   * Return Type: Promise<{iv: string, data: string, tag: string}> (Base64 encoded)
   */
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

  /**
   * Decrypts the ciphertext and unpads it.
   * Arguments:
   * encryptedRecord: object - Contains iv and data (Base64 encoded)
   * aad: string - Additional Authenticated Data (hashed domain name) for integrity protection
   * Return Type: Promise<string>
   */
  async decryptPass(encryptedRecord, aad) {
    const iv = decodeBuffer(encryptedRecord.iv);
    const data = decodeBuffer(encryptedRecord.data);
    const encodedAad = stringToBuffer(aad); // AAD must be a BufferSource

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

  /**
   * Hashes the domain name using HMAC.
   * Arguments:
   * domain: string - The domain name
   * Return Type: Promise<string> (Base64 encoded HMAC)
   */
  async hashDomain(domain) {
    let hash = await subtle.sign("HMAC", this.hmacKey, stringToBuffer(domain)); 
    return encodeBuffer(hash); 
  };
};

module.exports = { Keychain };