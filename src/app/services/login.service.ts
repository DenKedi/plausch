import { Injectable, inject } from '@angular/core';
import api from '../utils/api';
import { LoginResponse } from '../data-domain/models/login-response.model';
import { AxiosError } from 'axios';
import { CryptoService } from './crypto.service';

@Injectable({
  providedIn: 'root',
})
export class LoginService {
  private cryptoService = inject(CryptoService);

  public async login(email: string, password: string): Promise<any> {
    try {
      const response = await api.post<LoginResponse>(`/api/user/login`, {
        email,
        password,
      });

      if (response.data && response.data.token) {
        localStorage.setItem('authToken', response.data.token);

        // Setup encryption keys after successful login (pass password for encryption)
        await this.setupEncryption(password);
      }

      return response.data;
    } catch (error) {
      if (error instanceof AxiosError) {
        const errorMessage = error.response?.data.msg;
        throw new Error(errorMessage);
      }

      return null;
    }
  }

  /**
   * Setup encryption keys for the user
   *
   * Flow:
   * 1. Try to load encrypted private key from server (existing user)
   * 2. If not found, generate new keypair (new user)
   * 3. Upload encrypted keys to server
   *
   * @param userPassword - User's login password (for encrypting/decrypting private key)
   */
  private async setupEncryption(userPassword: string): Promise<void> {
    try {
      console.log('🔐 Setting up encryption...');

      // Step 1: Try to load encrypted private key from server
      try {
        const keysResponse = await api.get('/api/user/keys/private');
        const { encryptedPrivateKey } = keysResponse.data;

        if (encryptedPrivateKey) {
          console.log(
            '🔑 Found encrypted private key on server, decrypting...'
          );
          // Decrypt with user's password and load into memory
          await this.cryptoService.loadPrivateKeyFromServer(
            encryptedPrivateKey,
            userPassword
          );
          console.log('✅ Keys loaded from server successfully');
          return; // Done - keys are now in memory
        }
      } catch (error) {
        console.log(
          'ℹ️  No encrypted key on server yet (new user or first login)'
        );
      }

      // Step 2: No keys on server - generate new keypair
      console.log('🔑 Generating new keypair...');
      await this.cryptoService.generateKeyPair();

      // Step 3: Upload encrypted keys to server
      const publicKey = await this.cryptoService.exportPublicKey();
      const privateKey = await this.cryptoService.exportPrivateKey();

      // Encrypt private key with user's password
      const encryptedPrivateKey = await this.encryptPrivateKeyWithPassword(
        privateKey,
        userPassword
      );

      await this.uploadEncryptedKeys(publicKey, encryptedPrivateKey);
      console.log('✅ New keys generated and uploaded to server');
    } catch (error) {
      console.error('❌ Encryption setup failed:', error);
      // Don't throw - allow login to succeed even if encryption fails
    }
  }

  /**
   * Encrypt private key with password using PBKDF2 + AES-256-GCM
   * Matches backend encryption algorithm
   */
  private async encryptPrivateKeyWithPassword(
    privateKeyPem: string,
    password: string
  ): Promise<string> {
    try {
      console.log('🔐 Encrypting private key with password...');

      // Generate random salt for PBKDF2
      const saltBuffer = window.crypto.getRandomValues(new Uint8Array(32));
      const passwordBuffer = this.stringToArrayBuffer(password);

      // Derive encryption key from password
      const derivedKey = await window.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltBuffer,
          iterations: 100000,
          hash: 'SHA-256',
        },
        await window.crypto.subtle.importKey(
          'raw',
          passwordBuffer,
          'PBKDF2',
          false,
          ['deriveBits']
        ),
        256 // 256-bit key
      );

      // Encrypt with AES-256-GCM
      const iv = window.crypto.getRandomValues(new Uint8Array(16));
      const encrypted = await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128,
        },
        await window.crypto.subtle.importKey(
          'raw',
          derivedKey,
          'AES-GCM',
          false,
          ['encrypt']
        ),
        new TextEncoder().encode(privateKeyPem)
      );

      // Extract auth tag (last 16 bytes)
      const encryptedArray = new Uint8Array(encrypted);
      const encryptedContent = encryptedArray.slice(
        0,
        encryptedArray.length - 16
      );
      const authTag = encryptedArray.slice(encryptedArray.length - 16);

      const encryptedData = {
        v: 1,
        algorithm: 'aes-256-gcm',
        encrypted: this.arrayBufferToBase64(encryptedContent),
        iv: this.arrayBufferToBase64(iv),
        salt: this.arrayBufferToBase64(saltBuffer),
        authTag: this.arrayBufferToBase64(authTag),
      };

      console.log('✅ Private key encrypted with password');
      return JSON.stringify(encryptedData);
    } catch (error) {
      console.error('❌ Error encrypting private key:', error);
      throw error;
    }
  }

  /**
   * Helper: Convert string to ArrayBuffer
   */
  private stringToArrayBuffer(str: string): ArrayBuffer {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

  /**
   * Helper: Convert ArrayBuffer to Base64
   */
  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Upload encrypted private key and public key with new system
   */
  private async uploadEncryptedKeys(
    publicKey: string,
    encryptedPrivateKey: string
  ): Promise<void> {
    try {
      await api.post('/api/user/keys/upload-encrypted', {
        publicKey,
        encryptedPrivateKey,
      });
    } catch (error) {
      console.error('❌ Failed to upload encrypted keys:', error);
      throw error;
    }
  }
}
