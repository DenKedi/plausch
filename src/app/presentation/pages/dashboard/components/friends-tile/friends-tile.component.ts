import { Component, input } from '@angular/core';
import { User } from '../../../../../data-domain/models/user.model';

@Component({
  selector: 'friends-tile',
  imports: [],
  templateUrl: './friends-tile.component.html',
  standalone: true,
  styleUrl: './friends-tile.component.scss',
})
export class FriendsTileComponent {
  public user = input.required<User>();
  public hasUnread = input<boolean>(false);
}
