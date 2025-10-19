export interface User {
  _id: string;
  user_id: string;
  displayed_name: string;
  email: string;
  isConfirmed: boolean;
  isVisible: boolean;
  hasSeenTutorial?: boolean;
  bio: string;
  chats: ChatConnection[];
  friends: string[];
  pendingRequests: FriendRequest[];
  createdAt: Date;
  updatedAt: Date;
}

export interface FriendRequest {
  from: string;
  _id: string;
  status: RequestStatus;
}

export interface ChatConnection {
  chatId: string;
  friendId: string;
}

export enum RequestStatus {
  PENDING = 'pending',
  ACCEPTED = 'accepted',
  DENIED = 'denied',
}
