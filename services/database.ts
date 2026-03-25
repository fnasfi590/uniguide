import { User, UserRole, CallLog, CallType, Notification, Message, Attachment } from "../types";

const DB_KEY = 'uniguide_users_db_v2';
const MESSAGE_DB_KEY = 'uniguide_messages_db_v1';

// Seed data with specific credentials
const SEED_USERS: User[] = [
  {
    id: 'p_zied',
    name: 'Zied Benhamad',
    email: 'zied.benhamad@apac.tn',
    password: 'zied1234@',
    role: UserRole.PROFESSOR,
    avatar: 'https://ui-avatars.com/api/?name=Zied+Benhamad&background=7c3aed&color=fff',
    department: 'Computer Science',
    isOnline: true
  },
  {
    id: 's_farouk',
    name: 'Farouk Nasfi',
    email: 'farouk.nasfi@apac.tn',
    password: 'farouk1234@',
    role: UserRole.STUDENT,
    avatar: 'https://ui-avatars.com/api/?name=Farouk+Nasfi&background=0ea5e9&color=fff',
    department: 'Software Engineering',
    isOnline: true
  }
];

// Helper to get users from storage
const getStoredUsers = (): User[] => {
  const stored = localStorage.getItem(DB_KEY);
  if (!stored) {
    localStorage.setItem(DB_KEY, JSON.stringify(SEED_USERS));
    return SEED_USERS;
  }
  return JSON.parse(stored);
};

// --- Messaging helpers ---

interface StoredMessage {
  id: string;
  conversationId: string;
  senderId: string;
  text: string;
  timestamp: string;
  attachment?: Attachment;
}

const getConversationId = (userId1: string, userId2: string): string => {
  return [userId1, userId2].sort().join('__');
};

const getStoredMessages = (): StoredMessage[] => {
  try {
    const raw = localStorage.getItem(MESSAGE_DB_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch {
    return [];
  }
};

const saveStoredMessages = (messages: StoredMessage[]) => {
  localStorage.setItem(MESSAGE_DB_KEY, JSON.stringify(messages));
};

// Helper to validate email format (first.last@apac.tn)
const validateApacEmail = (email: string): boolean => {
  // Regex: start, word chars, dot, word chars, @apac.tn, end
  const regex = /^[a-zA-Z0-9]+\.[a-zA-Z0-9]+@apac\.tn$/i;
  return regex.test(email);
};

export const db = {
  // Get all users excluding the current user, filtered by opposite role
  // LOGIC CHANGE: If currentUser is STUDENT, mask the names of PROFESSORS
  getContacts: (currentUserRole: UserRole, currentUserId: string): User[] => {
    const allUsers = getStoredUsers();
    const targetRole = currentUserRole === UserRole.STUDENT ? UserRole.PROFESSOR : UserRole.STUDENT;
    
    let contacts = allUsers.filter(u => u.role === targetRole && u.id !== currentUserId);

    // Anonymity Logic
    if (currentUserRole === UserRole.STUDENT) {
      contacts = contacts.map(contact => {
        if (contact.role === UserRole.PROFESSOR) {
          return {
            ...contact,
            name: "Professeur", // Mask the real name to generic "Professeur"
            avatar: `https://ui-avatars.com/api/?name=P&background=9ca3af&color=fff` // Generic gray avatar with 'P'
          };
        }
        return contact;
      });
    }

    return contacts;
  },

  // --- Direct messaging between student & professor (no system/AI messages) ---
  getMessagesBetween: (userId1: string, userId2: string): Message[] => {
    const conversationId = getConversationId(userId1, userId2);
    const all = getStoredMessages();
    const filtered = all.filter(m => m.conversationId === conversationId);
    return filtered.map<Message>(m => ({
      id: m.id,
      senderId: m.senderId,
      text: m.text,
      timestamp: new Date(m.timestamp),
      attachment: m.attachment
    }));
  },

  saveMessage: (userId1: string, userId2: string, message: Message): void => {
    const conversationId = getConversationId(userId1, userId2);
    const all = getStoredMessages();
    const stored: StoredMessage = {
      id: message.id,
      conversationId,
      senderId: message.senderId,
      text: message.text,
      timestamp: message.timestamp.toISOString(),
      attachment: message.attachment
    };
    all.push(stored);
    saveStoredMessages(all);
  },

  // Simulate Login with Password
  login: async (email: string, password?: string): Promise<User> => {
    await new Promise(resolve => setTimeout(resolve, 800));
    
    if (!validateApacEmail(email)) {
      throw new Error("Invalid email format. Must be 'firstname.lastname@apac.tn'");
    }

    const users = getStoredUsers();
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    
    if (!user) {
      throw new Error("User not found");
    }

    // Password Check
    if (user.password && user.password !== password) {
       throw new Error("Incorrect password");
    }

    return user;
  },

  // Simulate Signup with Password
  signup: async (name: string, email: string, password: string, role: UserRole, department: string): Promise<User> => {
    await new Promise(resolve => setTimeout(resolve, 800));
    
    if (!validateApacEmail(email)) {
      throw new Error("Invalid email format. Must be 'firstname.lastname@apac.tn'");
    }

    const users = getStoredUsers();
    
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      throw new Error("Email already exists");
    }

    const newUser: User = {
      id: crypto.randomUUID(),
      name,
      email: email.toLowerCase(),
      password, // Store password
      role,
      department,
      avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=${role === UserRole.STUDENT ? '0ea5e9' : '7c3aed'}&color=fff`,
      isOnline: true
    };

    users.push(newUser);
    localStorage.setItem(DB_KEY, JSON.stringify(users));
    
    return newUser;
  },

  // Simulate Social Login
  socialLogin: async (email: string, name: string, role: UserRole, department: string): Promise<User> => {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Validate domain even for social login
    if (!validateApacEmail(email)) {
      throw new Error(`Social account email (${email}) must belong to @apac.tn domain.`);
    }

    const users = getStoredUsers();
    let user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    
    if (!user) {
      // Create new user if they passed validation
      user = {
        id: crypto.randomUUID(),
        name,
        email: email.toLowerCase(),
        role,
        department,
        avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=${role === UserRole.STUDENT ? '0ea5e9' : '7c3aed'}&color=fff`,
        isOnline: true
      };
      users.push(user);
      localStorage.setItem(DB_KEY, JSON.stringify(users));
    }
    
    return user;
  },

  // Get Mock Call History
  getCallHistory: (): CallLog[] => {
    // Return empty array to remove all example/fake professors from history
    return [];
  },

  // Get Notifications
  getNotifications: (): Notification[] => {
    return [
      {
        id: '1',
        title: 'Bienvenue sur UniGuide',
        message: 'Bienvenue sur la plateforme ! N\'hésitez pas à contacter vos professeurs.',
        timestamp: new Date(),
        isRead: false,
        type: 'system'
      },
      {
        id: '2',
        title: 'Rappel Cours',
        message: 'Votre cours de "Génie Logiciel" commence dans 1 heure.',
        timestamp: new Date(Date.now() - 3600000), // 1 hour ago
        isRead: false,
        type: 'system'
      }
    ];
  }
};