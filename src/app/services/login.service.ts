import { Injectable, inject } from '@angular/core';
import api from '../utils/api';
import { LoginResponse } from "../data-domain/models/login-response.model";
import { AxiosError } from "axios";
import { CryptoService } from './crypto.service';

@Injectable({
  providedIn: 'root'
})
export class LoginService {
  private cryptoService = inject(CryptoService);

  public async login(email: string, password: string): Promise<any> {
    try {
      const response = await api.post<LoginResponse>(`/api/user/login`, { email, password });

      if (response.data && response.data.token) {
        localStorage.setItem('authToken', response.data.token);

        // Setup encryption keys after successful login
        await this.setupEncryption();
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
   * - Tries to load existing private key from IndexedDB
   * - If no key exists, generates new RSA keypair
   * - Uploads public key to server
   * - Handles migration for existing accounts without keys
   */
  private async setupEncryption(): Promise<void> {
    try {
      console.log('🔐 Setting up encryption...');

      // Try to load existing private key from IndexedDB
      const hasExistingKey = await this.cryptoService.loadPrivateKey();

      if (!hasExistingKey) {
        console.log('🔑 No existing key found, generating new keypair...');
        
        // Generate new keypair
        await this.cryptoService.generateKeyPair();

        // Export and upload public key to server
        const publicKey = await this.cryptoService.exportPublicKey();
        await this.uploadPublicKey(publicKey);

        console.log('✅ New encryption keys generated and uploaded');
      } else {
        console.log('✅ Existing encryption keys loaded from IndexedDB');
        
        // Check if user's public key is on server
        // If not, upload it (migration for existing accounts)
        try {
          const userPublicKey = await this.cryptoService.exportPublicKey();
          await this.uploadPublicKey(userPublicKey);
          console.log('✅ Public key synchronized with server');
        } catch (error) {
          console.warn('⚠️ Could not sync public key:', error);
        }
      }
    } catch (error) {
      console.error('❌ Encryption setup failed:', error);
      // Don't throw - allow login to succeed even if encryption fails
    }
  }

  /**
   * Upload user's public key to server
   */
  private async uploadPublicKey(publicKey: string): Promise<void> {
    try {
      await api.post('/api/user/keys/upload', { publicKey });
    } catch (error) {
      console.error('❌ Failed to upload public key:', error);
      throw error;
    }
  }
}

