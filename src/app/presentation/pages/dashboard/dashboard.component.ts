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

        // Listen for friend requests
        this.socketService.onFriendRequest().subscribe(async (data) => {
          // Only process if this user is the receiver
          if (data.receiverId === this.user?._id) {
            // Refresh user data to get updated pending requests
            const token = localStorage.getItem('authToken');
            if (token) {
              this.user = await this.userService.getUserByToken(token);
            }
          }
        });

        // Track active chat to prevent unread badge on open chats
        this.selectFriendService.selectedFriend.subscribe((friend) => {
          if (friend) {
            const chat = this.user?.chats.find(c => c.friendId === friend._id);
            this.currentActiveChatId = chat?.chatId;
          } else {
            this.currentActiveChatId = undefined;
          }
        });

        // Listen for new messages to track unread
        this.socketService
          .onNewMessage()
          .subscribe((data: { message: any; chatId: string }) => {
            // Only mark as unread if:
            // 1. Message is not from current user
            // 2. Chat is not currently active
            if (data.message.from !== this.user?._id && data.chatId !== this.currentActiveChatId) {
              this.unreadChats.add(data.chatId);
            }
          });

        for (let friendId of this.user.friends) {
          const friend = await this.userService.getUserById(friendId);
          this.friends.push(friend);
        }
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
}
