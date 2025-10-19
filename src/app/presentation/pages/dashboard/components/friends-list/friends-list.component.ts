import { Component, EventEmitter, input, Output } from '@angular/core';
import { User } from "../../../../../data-domain/models/user.model";
import { FriendsTileComponent } from "../friends-tile/friends-tile.component";
import { NgClass } from "@angular/common";
import { SelectFriendService } from "../../../../../services/select-friend.service";
import { CtaButtonComponent } from "../../../../ui-components/cta-button/cta-button.component";

@Component({
  selector: 'friends-list',
  standalone: true,
    imports: [
        FriendsTileComponent,
        NgClass,
        CtaButtonComponent
    ],
  templateUrl: './friends-list.component.html',
  styleUrl: './friends-list.component.scss'
})
export class FriendsListComponent {
  public constructor(private selectFriendService: SelectFriendService) {}

  public friends = input.required<User[]>();
  public showHint = input.required<boolean>();
  public unreadChats = input.required<Set<string>>();
  public user = input.required<User>();

  @Output()
  public showSearchModalEvent = new EventEmitter<void>();

  @Output()
  public friendSelected = new EventEmitter<string>();

  public selectedFriend: User | undefined;

  public showSearchModal(): void {
    this.showSearchModalEvent.emit();
  }

  public selectFriend(friend: User) {
    if (friend._id === this.selectedFriend?._id) {
      return;
    }

    this.selectedFriend = friend;
    this.selectFriendService.selectFriend(friend);
    this.friendSelected.emit(friend._id);
  }

  public hasUnreadMessages(friendId: string): boolean {
    const chatId = this.user().chats.find(chat => chat.friendId === friendId)?.chatId;
    return chatId ? this.unreadChats().has(chatId) : false;
  }
}
