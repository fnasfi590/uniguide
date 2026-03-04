export enum UserRole {
  STUDENT = 'STUDENT',
  PROFESSOR = 'PROFESSOR'
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatar: string;
  department?: string;
  isOnline?: boolean;
  password?: string;
}

export interface Attachment {
  name: string;
  type: string;
  url: string; // Base64 data URL
}

export interface Message {
  id: string;
  senderId: string;
  text: string;
  timestamp: Date;
  isSystem?: boolean;
  attachment?: Attachment;
}

export interface ChatSession {
  id: string;
  participantId: string; // The ID of the user you are talking to
  participantName: string;
  participantEmail?: string; // Added for search
  participantRole: UserRole;
  participantAvatar: string;
  participantDepartment: string;
  lastMessage?: string;
  unreadCount?: number;
  isOnline: boolean;
}

export enum CallType {
  MISSED = 'MISSED',
  INCOMING = 'INCOMING',
  OUTGOING = 'OUTGOING'
}

export interface CallLog {
  id: string;
  participantName: string;
  participantAvatar: string;
  timestamp: Date;
  type: CallType;
  duration?: string; // e.g., "5:23"
}

export interface Notification {
  id: string;
  title: string;
  message: string;
  timestamp: Date;
  isRead: boolean;
  type: 'message' | 'call' | 'system';
}