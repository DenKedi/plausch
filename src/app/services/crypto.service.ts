import { Injectable } from '@angular/core';

/**
 * CryptoService handles all cryptographic operations for end-to-end encryption
 * Uses Web Crypto API for RSA-OAEP (key exchange) and AES-GCM (message encryption)
 */
@Injectable({
  providedIn: 'root',
})
export class CryptoService {
  private keyPair: CryptoKeyPair | null = null;

  private readonly ALGORITHM_RSA = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  };

  private readonly ALGORITHM_AES = {
    name: 'AES-GCM',
    length: 256,
  };

  constructor() {}

  /**
   * Generate RSA key pair for the current user
   * Called after login to create encryption keys
   */
  async generateKeyPair(): Promise<void> {
    try {
      this.keyPair = (await window.crypto.subtle.generateKey(
        this.ALGORITHM_RSA,
        true, // extractable
        ['encrypt', 'decrypt']
      )) as CryptoKeyPair;

      // Store private key in IndexedDB for persistence
      await this.storePrivateKey(this.keyPair.privateKey);
      console.log('✅ RSA key pair generated successfully');
    } catch (error) {
      console.error('❌ Error generating key pair:', error);
      throw new Error('Failed to generate encryption keys');
    }
  }

  /**
   * Export public key as PEM-encoded string for uploading to server
   */
  async exportPublicKey(): Promise<string> {
    if (!this.keyPair?.publicKey) {
      throw new Error('No keypair available. Call generateKeyPair() first');
    }

    try {
      const exported = await window.crypto.subtle.exportKey('spki', this.keyPair.publicKey);
      return this.arrayBufferToPem(exported, 'PUBLIC KEY');
    } catch (error) {
      console.error('❌ Error exporting public key:', error);
      throw error;
    }
  }

  /**
   * Import a public key from PEM format (used for friend's public keys)
   */
  async importPublicKey(pemKey: string): Promise<CryptoKey> {
    try {
      const binaryKey = this.pemToArrayBuffer(pemKey);
      return await window.crypto.subtle.importKey(
        'spki',
        binaryKey,
        this.ALGORITHM_RSA,
        true,
        ['encrypt']
      );
    } catch (error) {
      console.error('❌ Error importing public key:', error);
      throw error;
    }
  }

  /**
   * Encrypt a message using hybrid encryption (AES + RSA)
   * 
   * @param plaintext - The message to encrypt
   * @param recipientPublicKeys - Array of { userId, publicKey } for all chat participants
   * @returns Encrypted message with keys for each recipient
   */
  async encryptMessage(
    plaintext: string,
    recipientPublicKeys: Array<{ userId: string; publicKey: string }>
  ): Promise<{
    encryptedContent: string;
    iv: string;
    encryptedKeys: Array<{ userId: string; encryptedKey: string }>;
  }> {
    try {
      // Step 1: Generate random AES-256 session key
      const aesKey = await window.crypto.subtle.generateKey(
        this.ALGORITHM_AES,
        true,
        ['encrypt', 'decrypt']
      );

      // Step 2: Encrypt message with AES
      const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
      const encodedText = new TextEncoder().encode(plaintext);

      const encryptedContent = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        encodedText
      );

      // Step 3: Encrypt AES key with each recipient's RSA public key
      const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
      const encryptedKeys: Array<{ userId: string; encryptedKey: string }> = [];

      for (const recipient of recipientPublicKeys) {
        const publicKey = await this.importPublicKey(recipient.publicKey);

        const encryptedKey = await window.crypto.subtle.encrypt(
          { name: 'RSA-OAEP' },
          publicKey,
          exportedAesKey
        );

        encryptedKeys.push({
          userId: recipient.userId,
          encryptedKey: this.arrayBufferToBase64(encryptedKey),
        });
      }

      return {
        encryptedContent: this.arrayBufferToBase64(encryptedContent),
        iv: this.arrayBufferToBase64(iv.buffer),
        encryptedKeys,
      };
    } catch (error) {
      console.error('❌ Error encrypting message:', error);
      throw new Error('Failed to encrypt message');
    }
  }

  /**
   * Decrypt an encrypted message
   * 
   * @param encryptedContent - Base64 encoded encrypted message
   * @param iv - Base64 encoded initialization vector
   * @param encryptedKey - Base64 encoded AES key (encrypted with user's public key)
   * @returns Decrypted plaintext message
   */
  async decryptMessage(
    encryptedContent: string,
    iv: string,
    encryptedKey: string
  ): Promise<string> {
    if (!this.keyPair?.privateKey) {
      throw new Error('No private key available. Cannot decrypt message.');
    }

    try {
      // Step 1: Decrypt AES key using RSA private key
      const encryptedKeyBuffer = this.base64ToArrayBuffer(encryptedKey);
      const aesKeyBuffer = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        this.keyPair.privateKey,
        encryptedKeyBuffer
      );

      // Step 2: Import AES key
      const aesKey = await window.crypto.subtle.importKey(
        'raw',
        aesKeyBuffer,
        this.ALGORITHM_AES,
        false,
        ['decrypt']
      );

      // Step 3: Decrypt message with AES
      const ivBuffer = this.base64ToArrayBuffer(iv);
      const encryptedBuffer = this.base64ToArrayBuffer(encryptedContent);

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBuffer },
        aesKey,
        encryptedBuffer
      );

      return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
      console.error('❌ Error decrypting message:', error);
      throw new Error('Failed to decrypt message');
    }
  }

  /**
   * Load existing private key from IndexedDB
   * Called on app initialization after login
   */
  async loadPrivateKey(): Promise<boolean> {
    try {
      const keyData = await this.getFromIndexedDB('privateKey');
      if (!keyData) {
        return false;
      }

      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        keyData,
        this.ALGORITHM_RSA,
        false,
        ['decrypt']
      );

      this.keyPair = { privateKey, publicKey: null as any };
      console.log('✅ Private key loaded from IndexedDB');
      return true;
    } catch (error) {
      console.error('❌ Error loading private key:', error);
      return false;
    }
  }

  /**
   * Check if user has encryption keys set up
   */
  hasKeys(): boolean {
    return this.keyPair !== null && this.keyPair.privateKey !== null;
  }

  /**
   * Clear keys from memory (on logout)
   */
  clearKeys(): void {
    this.keyPair = null;
  }

  // ============================================
  // PRIVATE UTILITY METHODS
  // ============================================

  /**
   * Store private key in IndexedDB
   */
  private async storePrivateKey(privateKey: CryptoKey): Promise<void> {
    try {
      const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);
      await this.saveToIndexedDB('privateKey', exported);
    } catch (error) {
      console.error('❌ Error storing private key:', error);
      throw error;
    }
  }

  /**
   * Save data to IndexedDB
   */
  private saveToIndexedDB(key: string, data: ArrayBuffer): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('PlauschCrypto', 1);

      request.onerror = () => reject(request.error);

      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction(['keys'], 'readwrite');
        const store = transaction.objectStore('keys');

        store.put({ id: key, data });

        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
      };

      request.onupgradeneeded = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys', { keyPath: 'id' });
        }
      };
    });
  }

  /**
   * Get data from IndexedDB
   */
  private getFromIndexedDB(key: string): Promise<ArrayBuffer | null> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('PlauschCrypto', 1);

      request.onerror = () => reject(request.error);

      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction(['keys'], 'readonly');
        const store = transaction.objectStore('keys');
        const getRequest = store.get(key);

        getRequest.onsuccess = () => {
          resolve(getRequest.result ? getRequest.result.data : null);
        };
        getRequest.onerror = () => reject(getRequest.error);
      };

      request.onupgradeneeded = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys', { keyPath: 'id' });
        }
      };
    });
  }

  /**
   * Convert ArrayBuffer to Base64 string
   */
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert Base64 string to ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Convert ArrayBuffer to PEM format
   */
  private arrayBufferToPem(buffer: ArrayBuffer, type: string): string {
    const base64 = this.arrayBufferToBase64(buffer);
    const pemLines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${type}-----\n${pemLines.join('\n')}\n-----END ${type}-----`;
  }

  /**
   * Convert PEM format to ArrayBuffer
   */
  private pemToArrayBuffer(pem: string): ArrayBuffer {
    const base64 = pem
      .replace(/-----BEGIN .*-----/, '')
      .replace(/-----END .*-----/, '')
      .replace(/\s/g, '');
    return this.base64ToArrayBuffer(base64);
  }
}
