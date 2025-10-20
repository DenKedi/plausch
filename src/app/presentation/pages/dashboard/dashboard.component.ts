import { Component, HostListener, OnDestroy, OnInit } from '@angular/core';
import { UserService } from '../../../services/user.service';
import { User } from '../../../data-domain/models/user.model';
import { HeaderComponent } from '../../ui-components/header/header.component';
import { FooterComponent } from '../../ui-components/footer/footer.component';
import { SocketService } from '../../../services/socket.service';
import { ChatComponent } from './components/chat/chat.component';
import { SearchFriendModalComponent } from './components/search-friend-modal/search-friend-modal.component';
import { FriendsListComponent } from './components/friends-list/friends-list.component';
import { HelpModalComponent } from '../../ui-components/help-modal/help-modal.component';
import { LogoutService } from '../../../services/logout.service';
import { Router } from '@angular/router';
import { NgClass } from '@angular/common';
import { ToggleComponent } from '../../ui-components/toggle/toggle.component';
import { SelectFriendService } from '../../../services/select-friend.service';
import axios from 'axios';
import { environment } from '../../../../environment/environment';

@Component({
  selector: 'app-dashboard',
  imports: [
    HeaderComponent,
    FooterComponent,
    ChatComponent,
    SearchFriendModalComponent,
    FriendsListComponent,
    HelpModalComponent,
    NgClass,
    ToggleComponent,
  ],
  templateUrl: './dashboard.component.html',
  standalone: true,
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent implements OnInit, OnDestroy {
  public user: User | undefined;
  public friends: User[] = [];
  public isSearchModalVisible = false;
  public isFriendsListVisible = true;
  public showFirstTimeHelp = false;
  public unreadChats: Set<string> = new Set();
  private currentActiveChatId: string | undefined;
  private lastMessageTimestamps: Map<string, number> = new Map(); // chatId -> timestamp

  public isMobileView: boolean = false;

  public constructor(
    private userService: UserService,
    private socketService: SocketService,
    private logoutService: LogoutService,
    private router: Router,
    private selectFriendService: SelectFriendService
  ) {}

  public async ngOnInit(): Promise<void> {
    this.checkIfMobile();

    const token = localStorage.getItem('authToken');

    if (token) {
      try {
        this.user = await this.userService.getUserByToken(token);
        this.socketService.connect();

        // Check if user should see first-time tutorial
        if (!this.user.hasSeenTutorial) {
          this.showFirstTimeHelp = true;
        }

        // Listen for decryption errors - logout if occurs
        this.socketService.onDecryptionError().subscribe(async () => {
          console.error('🔓 Decryption error detected - logging out user');
          alert('Verschlüsselungsfehler erkannt. Du wirst abgemeldet. Bitte melde dich erneut an.');
          await this.logoutService.logout();
          await this.router.navigate(['/home']);
        });

        // Listen for friend requests and acceptances
        this.socketService.onFriendRequest().subscribe(async (data) => {
          // Only process if this user is the receiver
          if (data.receiverId === this.user?._id) {
            if (data.type === 'accepted') {
              // Friend request was accepted
              console.log('✅ Friend request accepted by:', data.accepter.displayed_name);
              
              // Refresh user data to get new friend
              const token = localStorage.getItem('authToken');
              if (token) {
                this.user = await this.userService.getUserByToken(token);
                
                // Add new friend to friends list
                const newFriend = await this.userService.getUserById(data.accepter._id);
                this.friends.push(newFriend);
              }

              // Show notification
              this.showFriendAcceptedNotification(data.accepter.displayed_name);
            } else {
              // New friend request
              console.log('📬 New friend request from:', data.sender.displayed_name);
              
              // Refresh user data to get updated pending requests
              const token = localStorage.getItem('authToken');
              if (token) {
                this.user = await this.userService.getUserByToken(token);
              }

              // Show notification
              this.showFriendRequestNotification(data.sender.displayed_name);
            }
          }
        });

        // Track active chat to prevent unread badge on open chats
        this.selectFriendService.selectedFriend.subscribe((friend) => {
          if (friend) {
            const chat = this.user?.chats.find(
              (c) => c.friendId === friend._id
            );
            this.currentActiveChatId = chat?.chatId;
          } else {
            this.currentActiveChatId = undefined;
          }
        });

        // Listen for new messages to track unread
        this.socketService
          .onNewMessage()
          .subscribe((data: { message: any; chatId: string }) => {
            // Update last message timestamp for this chat
            this.lastMessageTimestamps.set(
              data.chatId,
              new Date(data.message.timestamp).getTime()
            );

            // Re-sort friends list by most recent message
            this.sortFriendsByRecentMessage();

            // Only mark as unread if:
            // 1. Message is not from current user
            // 2. Chat is not currently active
            if (
              data.message.from !== this.user?._id &&
              data.chatId !== this.currentActiveChatId
            ) {
              this.unreadChats.add(data.chatId);
            }
          });

        // Load all friends
        for (let friendId of this.user.friends) {
          const friend = await this.userService.getUserById(friendId);
          this.friends.push(friend);
        }

        // Load initial timestamps and sort immediately
        this.loadInitialMessageTimestamps();

        // Setup subscription to load timestamps when chat data arrives
        this.loadLastMessageTimestamps();
      } catch (error) {
        this.logoutService.logout();
        await this.router.navigate(['/home']);
      }
    }
  }

  @HostListener('window:resize', ['$event'])
  public checkIfMobile(): void {
    this.isMobileView = window.innerWidth <= 768;
    this.isFriendsListVisible = window.innerWidth > 768;
  }

  public ngOnDestroy(): void {
    this.socketService.disconnect();
  }

  public toggleFriendsList(): void {
    this.isFriendsListVisible = !this.isFriendsListVisible;
  }

  public async showSearchModal(): Promise<void> {
    const token = localStorage.getItem('authToken');
    this.user = await this.userService.getUserByToken(token ?? '');

    this.isSearchModalVisible = true;
  }

  public closeSearchModal(): void {
    this.isSearchModalVisible = false;
  }

  public async closeFirstTimeHelp(): Promise<void> {
    this.showFirstTimeHelp = false;

    // Mark tutorial as seen in backend
    try {
      const token = localStorage.getItem('authToken');
      await axios.post(
        `${environment.apiBaseUrl}api/user/tutorial-seen`,
        {},
        {
          headers: {
            'x-auth-token': token,
          },
        }
      );

      // Update local user object
      if (this.user) {
        this.user.hasSeenTutorial = true;
      }
    } catch (error) {
      console.error('Error marking tutorial as seen:', error);
    }
  }

  public getChatIdForFriend(friendId: string): string | undefined {
    return this.user?.chats.find((chat) => chat.friendId === friendId)?.chatId;
  }

  public hasUnreadMessages(friendId: string): boolean {
    const chatId = this.getChatIdForFriend(friendId);
    return chatId ? this.unreadChats.has(chatId) : false;
  }

  public markChatAsRead(friendId: string): void {
    const chatId = this.getChatIdForFriend(friendId);
    if (chatId) {
      this.unreadChats.delete(chatId);
    }
  }

  /**
   * Load last message timestamps for all chats from backend
   * Called when chatData is received via socket
   */
  private loadLastMessageTimestamps(): void {
    // Subscribe to chat data events to extract timestamps
    this.socketService.onStoredMessages().subscribe((chatData: any) => {
      if (chatData.messages && chatData.messages.length > 0) {
        const lastMessage = chatData.messages[chatData.messages.length - 1];
        this.lastMessageTimestamps.set(
          chatData._id,
          new Date(lastMessage.timestamp).getTime()
        );
        this.sortFriendsByRecentMessage();
      }
    });
  }

  /**
   * Load initial message timestamps from user data for immediate sorting
   * Called once on dashboard init to sort friends by most recent chat
   * This loads all chat data via socket to extract timestamps
   */
  private loadInitialMessageTimestamps(): void {
    if (!this.user?.chats) return;

    // Join all chats to load their data
    for (const chat of this.user.chats) {
      this.socketService.joinRoom(chat.chatId);
    }

    // The timestamps will be populated by loadLastMessageTimestamps() subscription
    // Wait a bit for socket events to arrive before sorting
    setTimeout(() => {
      this.sortFriendsByRecentMessage();
    }, 500);
  }

  /**
   * Sort friends by most recent message (newest first)
   */
  private sortFriendsByRecentMessage(): void {
    this.friends.sort((a, b) => {
      const chatIdA = this.getChatIdForFriend(a._id);
      const chatIdB = this.getChatIdForFriend(b._id);

      const timestampA = chatIdA ? this.lastMessageTimestamps.get(chatIdA) || 0 : 0;
      const timestampB = chatIdB ? this.lastMessageTimestamps.get(chatIdB) || 0 : 0;

      // Sort descending (newest first)
      return timestampB - timestampA;
    });
  }

  /**
   * Show notification for incoming friend request
   */
  private showFriendRequestNotification(senderName: string): void {
    this.showNotification(
      'Neue Freundschaftsanfrage',
      `${senderName} möchte mit dir befreundet sein`
    );
  }

  /**
   * Show notification for accepted friend request
   */
  private showFriendAcceptedNotification(accepterName: string): void {
    this.showNotification(
      'Freundschaftsanfrage akzeptiert',
      `${accepterName} hat deine Anfrage akzeptiert! 🎉`
    );
  }

  /**
   * Generic notification helper
   */
  private showNotification(title: string, body: string): void {
    // Try to use browser notifications if permission granted
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(title, {
        body: body,
        icon: '/favicon.ico',
      });
    } else if ('Notification' in window && Notification.permission !== 'denied') {
      // Request permission
      Notification.requestPermission().then((permission) => {
        if (permission === 'granted') {
          new Notification(title, {
            body: body,
            icon: '/favicon.ico',
          });
        }
      });
    }

    // Also log to console
    console.log(`🔔 ${title}: ${body}`);
  }
}
