import { Injectable } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { Observable, Subject } from 'rxjs';
import { Message } from "../data-domain/models/message.model";
import { Chat } from "../data-domain/models/chat.model";
import { flattenObject } from "../utils/flatten-object";
import { environment } from "../../environment/environment";

@Injectable({
  providedIn: 'root',
})
export class SocketService {
  private socket: Socket | undefined;
  private errorSubject = new Subject<string>();
  private newMessageSubject = new Subject<Message>();
  private storedMessagesSubject = new Subject<Chat>();

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

    this.socket.on('newMessage', (message) => {
      this.newMessageSubject.next(message);
    });

    this.socket.on('chatData', (data: Chat) => {
      const messages: Message[] = data.messages.map((message => {
        return flattenObject(message);
      }))

      this.storedMessagesSubject.next({...data, messages});
    });
  }

  public joinRoom(chatId: string): void {
    if (this.socket) {
      this.socket.emit('joinRoom', { chatId });
    }
  }

  public sendMessage(chatId: string, text: string): void {
    if (this.socket) {
      this.socket.emit('sendMessage', { chatId, text });
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

  public disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
    }
  }
}
