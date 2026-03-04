import React, { useState, useEffect, useRef } from 'react';
import { User, UserRole, ChatSession, CallLog, CallType, Notification } from '../types';
import ChatInterface from './ChatInterface';
import { LogOut, Search, Bell, User as UserIcon, Loader2, AlertTriangle, Phone, Users, PhoneIncoming, PhoneOutgoing, PhoneMissed, Check, X } from 'lucide-react';
import { db } from '../services/database';

interface DashboardProps {
  currentUser: User;
  onLogout: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ currentUser, onLogout }) => {
  const [activeSession, setActiveSession] = useState<ChatSession | null>(null);
  const [contacts, setContacts] = useState<ChatSession[]>([]);
  const [callHistory, setCallHistory] = useState<CallLog[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const [sidebarView, setSidebarView] = useState<'contacts' | 'calls'>('contacts');

  // Fetch users, history and notifications
  useEffect(() => {
    const fetchData = () => {
      setLoading(true);
      const dbUsers = db.getContacts(currentUser.role, currentUser.id);
      
      // Convert DB users to ChatSession format
      const mappedContacts: ChatSession[] = dbUsers.map(u => ({
        id: `session-${u.id}`,
        participantId: u.id,
        participantName: u.name,
        participantEmail: u.email,
        participantRole: u.role,
        participantAvatar: u.avatar,
        participantDepartment: u.department || 'Général',
        lastMessage: 'Appuyez pour discuter', 
        isOnline: u.isOnline || false,
        unreadCount: 0
      }));

      setContacts(mappedContacts);
      setCallHistory(db.getCallHistory());
      setNotifications(db.getNotifications());
      setLoading(false);
    };

    fetchData();
  }, [currentUser]);

  // Enhanced Search Logic
  const filteredContacts = contacts.filter(c => {
    const term = searchTerm.toLowerCase();
    const matchesName = c.participantName.toLowerCase().includes(term);
    const matchesDept = c.participantDepartment.toLowerCase().includes(term);
    const matchesEmail = c.participantEmail?.toLowerCase().includes(term);
    
    // Status search (online/en ligne)
    const matchesStatus = (term === 'online' || term === 'en ligne') && c.isOnline;

    return matchesName || matchesDept || matchesEmail || matchesStatus;
  });

  const handleLogoutClick = () => {
    setShowLogoutConfirm(true);
  };

  const confirmLogout = () => {
    setShowLogoutConfirm(false);
    onLogout();
  };

  // Notification Logic
  const unreadNotificationsCount = notifications.filter(n => !n.isRead).length;

  const markNotificationAsRead = (id: string) => {
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, isRead: true } : n));
  };

  const clearNotifications = () => {
    setNotifications([]);
  };

  const renderCallIcon = (type: CallType) => {
    switch(type) {
      case CallType.MISSED: return <PhoneMissed className="w-4 h-4 text-red-500" />;
      case CallType.INCOMING: return <PhoneIncoming className="w-4 h-4 text-green-500" />;
      case CallType.OUTGOING: return <PhoneOutgoing className="w-4 h-4 text-blue-500" />;
    }
  };

  return (
    <div className="h-screen flex bg-gray-50 overflow-hidden animate-fade-in relative">
      {/* Logout Confirmation Modal */}
      {showLogoutConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/50 backdrop-blur-sm animate-fade-in">
          {/* Backdrop click to close */}
          <div className="absolute inset-0" onClick={() => setShowLogoutConfirm(false)}></div>
          
          <div className="bg-white p-6 rounded-2xl shadow-xl max-w-sm w-full mx-4 animate-slide-up border border-gray-100 relative z-10">
            <div className="flex items-center gap-3 mb-4 text-amber-600">
               <div className="p-2 bg-amber-50 rounded-full">
                 <AlertTriangle className="w-6 h-6" />
               </div>
               <h3 className="text-lg font-bold text-gray-900">Déconnexion</h3>
            </div>
            
            <p className="text-gray-600 mb-6 leading-relaxed">
              Êtes-vous sûr de vouloir vous déconnecter de UniGuide ?
            </p>
            
            <div className="flex justify-end gap-3">
              <button 
                onClick={() => setShowLogoutConfirm(false)} 
                className="px-4 py-2.5 text-gray-600 hover:bg-gray-100 font-medium rounded-xl transition-colors"
              >
                Annuler
              </button>
              <button 
                onClick={confirmLogout} 
                className="px-4 py-2.5 bg-red-600 text-white font-medium rounded-xl hover:bg-red-700 shadow-lg shadow-red-200 transition-all hover:scale-105"
              >
                Se déconnecter
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar - Contacts List */}
      <div className={`w-full md:w-80 bg-white border-r border-gray-200 flex flex-col transition-all duration-300 ${activeSession ? 'hidden md:flex' : 'flex'}`}>
        {/* User Profile Header */}
        <div className="p-4 border-b border-gray-100 flex items-center justify-between">
          <div className="flex items-center gap-3">
             <img src={currentUser.avatar} alt="Profil" className="w-10 h-10 rounded-full border border-gray-200 shadow-sm" />
             <div className="overflow-hidden">
               <h3 className="font-semibold text-gray-900 truncate">{currentUser.name}</h3>
               <span className="text-xs px-2 py-0.5 rounded-full bg-brand-50 text-brand-600 font-medium">
                 {currentUser.role === UserRole.STUDENT ? 'Étudiant' : 'Professeur'}
               </span>
             </div>
          </div>
          <div className="flex gap-2">
            {/* Notification Bell */}
            <div className="relative">
                <button 
                    onClick={() => setShowNotifications(!showNotifications)}
                    className={`p-2 rounded-lg transition-colors relative ${showNotifications ? 'bg-brand-50 text-brand-600' : 'text-gray-400 hover:text-gray-600 hover:bg-gray-50'}`}
                >
                <Bell className="w-5 h-5" />
                {unreadNotificationsCount > 0 && (
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white"></span>
                )}
                </button>

                {/* Dropdown Panel */}
                {showNotifications && (
                    <>
                        <div className="fixed inset-0 z-40" onClick={() => setShowNotifications(false)}></div>
                        <div className="absolute right-0 left-auto md:left-0 md:right-auto mt-2 w-72 md:w-80 bg-white rounded-2xl shadow-xl border border-gray-100 z-50 overflow-hidden animate-slide-up origin-top-right">
                            <div className="p-4 border-b border-gray-50 flex justify-between items-center bg-gray-50/50">
                                <h3 className="font-semibold text-gray-900">Notifications</h3>
                                {notifications.length > 0 && (
                                    <button onClick={clearNotifications} className="text-xs text-brand-600 hover:text-brand-700 font-medium">
                                        Tout effacer
                                    </button>
                                )}
                            </div>
                            <div className="max-h-[300px] overflow-y-auto">
                                {notifications.length === 0 ? (
                                    <div className="p-8 text-center text-gray-400">
                                        <Bell className="w-8 h-8 mx-auto mb-2 opacity-20" />
                                        <p className="text-sm">Aucune notification</p>
                                    </div>
                                ) : (
                                    notifications.map(notification => (
                                        <div 
                                            key={notification.id} 
                                            onClick={() => markNotificationAsRead(notification.id)}
                                            className={`p-4 border-b border-gray-50 hover:bg-gray-50 transition-colors cursor-pointer ${!notification.isRead ? 'bg-blue-50/30' : ''}`}
                                        >
                                            <div className="flex gap-3">
                                                <div className={`mt-1 w-2 h-2 rounded-full shrink-0 ${!notification.isRead ? 'bg-brand-500' : 'bg-gray-200'}`}></div>
                                                <div>
                                                    <h4 className={`text-sm ${!notification.isRead ? 'font-semibold text-gray-900' : 'font-medium text-gray-600'}`}>
                                                        {notification.title}
                                                    </h4>
                                                    <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{notification.message}</p>
                                                    <span className="text-[10px] text-gray-400 mt-2 block">
                                                        {notification.timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </>
                )}
            </div>

            <button onClick={handleLogoutClick} title="Se déconnecter" className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors">
               <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex p-2 bg-gray-50/50">
            <button 
                onClick={() => setSidebarView('contacts')}
                className={`flex-1 py-2 flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-all ${
                    sidebarView === 'contacts' ? 'bg-white shadow-sm text-brand-600' : 'text-gray-500 hover:bg-gray-200/50'
                }`}
            >
                <Users className="w-4 h-4" /> Contacts
            </button>
            <button 
                onClick={() => setSidebarView('calls')}
                className={`flex-1 py-2 flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-all ${
                    sidebarView === 'calls' ? 'bg-white shadow-sm text-brand-600' : 'text-gray-500 hover:bg-gray-200/50'
                }`}
            >
                <Phone className="w-4 h-4" /> Appels
            </button>
        </div>

        {/* Search */}
        {sidebarView === 'contacts' && (
            <div className="px-4 pb-2">
            <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                <input 
                type="text" 
                placeholder="Rechercher par nom, email, statut..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-brand-500/50 text-sm transition-all"
                />
            </div>
            </div>
        )}

        {/* List Content */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {sidebarView === 'contacts' ? (
            <>
                <h4 className="px-4 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    {currentUser.role === UserRole.STUDENT ? 'Vos Professeurs' : 'Vos Étudiants'}
                </h4>
                {loading ? (
                    <div className="flex flex-col items-center justify-center py-8 text-gray-400">
                    <Loader2 className="w-6 h-6 animate-spin mb-2" />
                    <span className="text-xs">Chargement de l'annuaire...</span>
                    </div>
                ) : filteredContacts.length === 0 ? (
                    <div className="text-center py-8 text-gray-400 text-sm px-4">
                    <p>Aucun contact trouvé.</p>
                    <p className="mt-1 text-xs">Essayez un autre terme de recherche.</p>
                    </div>
                ) : (
                    filteredContacts.map((contact, idx) => (
                    <button
                        key={contact.id}
                        onClick={() => setActiveSession(contact)}
                        style={{ animationDelay: `${idx * 0.05}s` }}
                        className={`w-full p-3 rounded-xl flex items-center gap-3 transition-all animate-slide-up ${
                        activeSession?.id === contact.id 
                            ? 'bg-brand-50 border border-brand-100 shadow-sm' 
                            : 'hover:bg-gray-50 border border-transparent'
                        }`}
                    >
                        <div className="relative">
                        <img src={contact.participantAvatar} alt={contact.participantName} className="w-12 h-12 rounded-full border border-gray-200 object-cover" />
                        <span 
                            className={`absolute bottom-0 right-0 w-3.5 h-3.5 border-2 border-white rounded-full ${
                            contact.isOnline ? 'bg-green-500' : 'bg-gray-300'
                            }`}
                            title={contact.isOnline ? "En ligne" : "Hors ligne"}
                        ></span>
                        </div>
                        <div className="flex-1 text-left min-w-0">
                        <div className="flex justify-between items-baseline mb-0.5">
                            <h4 className={`font-semibold text-sm truncate ${activeSession?.id === contact.id ? 'text-brand-900' : 'text-gray-900'}`}>
                            {contact.participantName}
                            </h4>
                        </div>
                        <p className="text-xs text-gray-500 truncate">{contact.participantDepartment}</p>
                        </div>
                    </button>
                    ))
                )}
            </>
          ) : (
            // Call History View
            <div className="space-y-2">
                <h4 className="px-4 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Récents
                </h4>
                {callHistory.length === 0 ? (
                    <div className="text-center py-8 text-gray-400 text-sm px-4">
                        <PhoneMissed className="w-8 h-8 mx-auto mb-2 opacity-20" />
                        <p>Aucun appel récent</p>
                    </div>
                ) : (
                    callHistory.map((call) => (
                        <div key={call.id} className="p-3 mx-2 rounded-xl bg-white border border-gray-100 flex items-center gap-3 hover:bg-gray-50 transition-colors">
                            <img src={call.participantAvatar} alt={call.participantName} className="w-10 h-10 rounded-full border border-gray-200" />
                            <div className="flex-1">
                                <h4 className="font-semibold text-sm text-gray-900">{call.participantName}</h4>
                                <div className="flex items-center gap-1 text-xs text-gray-500">
                                    {renderCallIcon(call.type)}
                                    <span>
                                        {call.type === CallType.MISSED ? 'Manqué' : 
                                        call.type === CallType.INCOMING ? 'Entrant' : 'Sortant'}
                                    </span>
                                    {call.duration && <span>• {call.duration}</span>}
                                </div>
                            </div>
                            <span className="text-xs text-gray-400">
                                {call.timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                            </span>
                        </div>
                    ))
                )}
            </div>
          )}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className={`flex-1 flex flex-col h-full relative ${!activeSession ? 'hidden md:flex' : 'flex'}`}>
        {activeSession ? (
          <div className="h-full p-0 md:p-4 bg-gray-50 animate-fade-in">
             <ChatInterface 
               currentUser={currentUser} 
               session={activeSession} 
               onBack={() => setActiveSession(null)}
             />
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-gray-400 bg-gray-50">
            <div className="w-24 h-24 bg-white rounded-full flex items-center justify-center mb-6 shadow-sm animate-bounce">
              <UserIcon className="w-10 h-10 text-gray-300" />
            </div>
            <h2 className="text-xl font-semibold text-gray-600 mb-2">Bienvenue sur UniGuide</h2>
            <p className="text-gray-500 max-w-xs text-center">
              Sélectionnez un {currentUser.role === UserRole.STUDENT ? 'professeur' : 'étudiant'} dans la liste pour commencer une conversation.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;