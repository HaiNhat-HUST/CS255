'use strict'

const {
  bufferToString,
  genRandomSalt,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  cryptoKeyToJSON
} = require('./lib')

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // {name: {rootKey, chainKey, dhPair, lastReceivedPubKey, sendCounter, recvCounter}}
    this.certs = {} // {username: certificate}
    this.EGKeyPair = null
  }

  async generateCertificate(username) {
    this.EGKeyPair = await generateEG()
    const certificate = {
      username: username,
      publicKey: await cryptoKeyToJSON(this.EGKeyPair.pub),
      timestamp: Date.now()
    }
    return certificate
  }

  async receiveCertificate(certificate, signature) {
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!isValid) throw new Error('Invalid certificate signature')
    this.certs[certificate.username] = certificate
  }

  async sendMessage(name, plaintext) {
    if (!this.certs[name]) {
      throw new Error(`No certificate for user: ${name}`)
    }
    
    if (!this.conns[name]) {
      await this._initializeConnection(name)
    }
    
    const conn = this.conns[name]
    
    // Generate new DH pair if needed
    if (!conn.dhPair) {
      conn.dhPair = await generateEG()
    }
    
    // Advance symmetric ratchet
    const [messageKey, nextChainKey] = await this._ratchetChain(conn.chainKey)
    conn.chainKey = nextChainKey
    
    // Generate IV for encryption
    const iv = genRandomSalt(12) // 12 bytes recommended for GCM
    
    // Create header
    const header = {
      senderPubKey: await cryptoKeyToJSON(conn.dhPair.pub),
      messageNum: conn.sendCounter || 0,
      iv: Array.from(iv) // Convert Uint8Array to array for JSON
    }
    conn.sendCounter = (conn.sendCounter || 0) + 1
    
    // Encrypt with GCM
    const ciphertext = await encryptWithGCM(
      messageKey,
      plaintext,
      iv,
      JSON.stringify(header)
    )
    
    return [header, ciphertext]
  }

  async receiveMessage(name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error(`No certificate for user: ${name}`)
    }
    
    if (!this.conns[name]) {
      await this._initializeConnection(name)
    }
    
    const conn = this.conns[name]
    const senderPubKey = header.senderPubKey
    const iv = new Uint8Array(header.iv)
    
    // Perform DH ratchet if new public key received
    const lastPubKeyStr = conn.lastReceivedPubKey ? JSON.stringify(conn.lastReceivedPubKey) : null
    if (!lastPubKeyStr || lastPubKeyStr !== JSON.stringify(senderPubKey)) {
      const dhOutput = await computeDH(conn.dhPair, senderPubKey)
      const [newRootKey, newChainKey] = await HKDF(dhOutput, conn.rootKey, "ratchet")
      
      conn.rootKey = newRootKey
      conn.chainKey = newChainKey
      conn.lastReceivedPubKey = senderPubKey
      conn.dhPair = await generateEG()
      conn.recvCounter = 0
    }
    
    // Advance symmetric ratchet
    const [messageKey, nextChainKey] = await this._ratchetChain(conn.chainKey)
    conn.chainKey = nextChainKey
    
    // Decrypt message
    try {
      const plaintextBuf = await decryptWithGCM(
        messageKey,
        ciphertext,
        iv,
        JSON.stringify(header)
      )
      conn.recvCounter = (conn.recvCounter || 0) + 1
      return bufferToString(plaintextBuf)
    } catch (e) {
      throw new Error('Decryption failed: ' + e.message)
    }
  }

  async _initializeConnection(name) {
    const theirPubKey = this.certs[name].publicKey
    const dhPair = await generateEG()
    const dhOutput = await computeDH(dhPair, theirPubKey)
    
    const salt = genRandomSalt()
    const [rootKey, chainKey] = await HKDF(dhOutput, salt, "initial")
    
    this.conns[name] = {
      rootKey,
      chainKey,
      dhPair,
      lastReceivedPubKey: null,
      sendCounter: 0,
      recvCounter: 0
    }
  }

  async _ratchetChain(chainKey) {
    const messageKey = await HMACtoAESKey(chainKey, "message")
    const nextChainKey = await HMACtoHMACKey(chainKey, "chain")
    return [messageKey, nextChainKey]
  }
}

module.exports = {
  MessengerClient
}