import { Injectable, inject } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { Observable, Subject } from 'rxjs';
import { Message } from '../data-domain/models/message.model';
import { Chat } from '../data-domain/models/chat.model';
import { flattenObject } from '../utils/flatten-object';
import { environment } from '../../environment/environment';
import { CryptoService } from './crypto.service';
import api from '../utils/api';

@Injectable({
  providedIn: 'root',
})
export class SocketService {
  private cryptoService = inject(CryptoService);
  private socket: Socket | undefined;
  private errorSubject = new Subject<string>();
  private newMessageSubject = new Subject<Message>();
  private storedMessagesSubject = new Subject<Chat>();
  private friendRequestSubject = new Subject<any>();
  private currentUserId: string | null = null;

  public connect(): void {
    const token = localStorage.getItem('authToken');

    this.socket = io(environment.apiBaseUrl, {
      path: '/socket.io',
      withCredentials: true,
      auth: {
        token: token,
      },
    });

    this.socket.on('connect', () => {
      console.log('Connected to server, socket ID:', this.socket?.id);
    });

    this.socket.on('connect_error', (err) => {
      console.error('Connection failed:', err.message);
    });

    this.socket.on('error', (error: { message: string }) => {
      console.error('Server error:', error.message);
      this.errorSubject.next(error.message);
    });

    this.socket.on('newMessage', async (data) => {
      try {
        // Decrypt message if encrypted
        const message = await this.decryptMessageIfNeeded(data.message);
        this.newMessageSubject.next(message);
      } catch (error) {
        console.error('Error processing new message:', error);
        this.errorSubject.next('Failed to decrypt message');
      }
    });

    this.socket.on('chatData', async (data: Chat) => {
      try {
        // Decrypt all messages in chat history
        const decryptedMessages: Message[] = await Promise.all(
          data.messages.map(async (message) => {
            const flattenedMessage = flattenObject(message);
            return await this.decryptMessageIfNeeded(flattenedMessage);
          })
        );

        this.storedMessagesSubject.next({ ...data, messages: decryptedMessages });
      } catch (error) {
        console.error('Error processing chat data:', error);
        this.errorSubject.next('Failed to decrypt chat history');
      }
    });

    this.socket.on('friendRequest', (data: any) => {
      this.friendRequestSubject.next(data);
    });
  }

  /**
   * Decrypt a message if it's encrypted, otherwise return as-is
   */
  private async decryptMessageIfNeeded(message: any): Promise<Message> {
    if (!message.isEncrypted) {
      return message; // Return plain text message as-is
    }

    try {
      // Get current user ID from token
      if (!this.currentUserId) {
        this.currentUserId = await this.getCurrentUserId();
      }

      // Find encrypted key for current user
      const userKey = message.encryptedKeys?.find(
        (k: any) => k.userId === this.currentUserId
      );

      if (!userKey) {
        console.warn('No encryption key found for current user');
        return { ...message, text: '[Encrypted message - cannot decrypt]' };
      }

      // Decrypt the message
      const decryptedText = await this.cryptoService.decryptMessage(
        message.encryptedContent,
        message.iv,
        userKey.encryptedKey
      );

      return { ...message, text: decryptedText };
    } catch (error) {
      console.error('Error decrypting message:', error);
      return { ...message, text: '[Failed to decrypt message]' };
    }
  }

  /**
   * Get current user ID from JWT token
   */
  private async getCurrentUserId(): Promise<string> {
    try {
      const response = await api.get('/api/user/me');
      return response.data._id;
    } catch (error) {
      console.error('Failed to get current user ID:', error);
      throw error;
    }
  }

  /**
   * Fetch public keys for all participants in a chat
   */
  private async getPublicKeysForChat(chatId: string): Promise<Array<{ userId: string; publicKey: string }>> {
    try {
      const response = await api.get(`/api/user/keys/${chatId}`);
      return response.data.publicKeys;
    } catch (error) {
      console.error('Failed to fetch public keys:', error);
      throw error;
    }
  }

  public joinRoom(chatId: string): void {
    if (this.socket) {
      this.socket.emit('joinRoom', { chatId });
    }
  }

  /**
   * Send a message (encrypted if crypto service has keys)
   */
  public async sendMessage(chatId: string, text: string): Promise<void> {
    if (!this.socket) {
      throw new Error('Socket not connected');
    }

    try {
      // Check if encryption is available
      if (this.cryptoService.hasKeys()) {
        // Get public keys for all chat participants
        const publicKeys = await this.getPublicKeysForChat(chatId);

        if (publicKeys.length > 0 && publicKeys.every(pk => pk.publicKey)) {
          // All participants have public keys - send encrypted
          const encrypted = await this.cryptoService.encryptMessage(text, publicKeys);

          this.socket.emit('sendMessage', {
            chatId,
            isEncrypted: true,
            encryptedContent: encrypted.encryptedContent,
            iv: encrypted.iv,
            encryptedKeys: encrypted.encryptedKeys,
          });

          console.log('✅ Sent encrypted message');
          return;
        }
      }

      // Fallback to plain text if encryption not available
      console.warn('⚠️  Sending unencrypted message (encryption not available)');
      this.socket.emit('sendMessage', { chatId, text, isEncrypted: false });
    } catch (error) {
      console.error('❌ Error sending message:', error);
      // Fallback to unencrypted on error
      this.socket.emit('sendMessage', { chatId, text, isEncrypted: false });
    }
  }

  public onStoredMessages(): Observable<any> {
    return this.storedMessagesSubject.asObservable();
  }

  public onNewMessage(): Observable<any> {
    return this.newMessageSubject.asObservable();
  }

  public onError(): Observable<string> {
    return this.errorSubject.asObservable();
  }

  public onFriendRequest(): Observable<any> {
    return this.friendRequestSubject.asObservable();
  }

  public disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
    }
  }
}
