import React, { useState, useEffect, useRef } from 'react';
import { Message, User, ChatSession, Attachment } from '../types';
import { Send, Paperclip, Phone, Video, X, FileText, Image as ImageIcon, Download, Trash2 } from 'lucide-react';
import CallOverlay from './CallOverlay';
import { db } from '../services/database';

interface ChatInterfaceProps {
  currentUser: User;
  session: ChatSession;
  onBack: () => void;
}

const ChatInterface: React.FC<ChatInterfaceProps> = ({ currentUser, session, onBack }) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [draftAttachment, setDraftAttachment] = useState<Attachment | null>(null);
  
  // Call State
  const [isCalling, setIsCalling] = useState(false);
  const [isVideoCall, setIsVideoCall] = useState(true);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load and keep messages in sync between the two users
  useEffect(() => {
    const syncMessages = () => {
      const existingMessages = db.getMessagesBetween(currentUser.id, session.participantId);
      setMessages(existingMessages);
    };

    syncMessages();
    const intervalId = window.setInterval(syncMessages, 1000);

    return () => window.clearInterval(intervalId);
  }, [currentUser.id, session.participantId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, draftAttachment]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 5 * 1024 * 1024) {
        alert("La taille du fichier doit être inférieure à 5 Mo");
        return;
      }
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          setDraftAttachment({
            name: file.name,
            type: file.type,
            url: event.target.result as string
          });
        }
      };
      reader.readAsDataURL(file);
    }
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSend = async () => {
    if (!input.trim() && !draftAttachment) return;

    const newMessage: Message = {
      id: Date.now().toString(),
      senderId: currentUser.id,
      text: input,
      timestamp: new Date(),
      attachment: draftAttachment || undefined
    };

    setMessages(prev => [...prev, newMessage]);
    db.saveMessage(currentUser.id, session.participantId, newMessage);
    setInput('');
    setDraftAttachment(null);
  };

  const handleDeleteMessage = (messageId: string) => {
    if (window.confirm("Voulez-vous vraiment supprimer ce message ?")) {
      setMessages(prev => prev.filter(m => m.id !== messageId));
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  const startCall = (video: boolean) => {
      setIsVideoCall(video);
      setIsCalling(true);
  };

  const renderAttachment = (attachment: Attachment) => {
    const isImage = attachment.type.startsWith('image/');

    if (isImage) {
      return (
        <div className="mb-2 mt-1">
          <img 
            src={attachment.url} 
            alt={attachment.name} 
            className="max-w-full sm:max-w-[250px] rounded-lg border border-white/20" 
          />
        </div>
      );
    }

    return (
      <div className="flex items-center gap-3 p-3 rounded-lg mb-2 mt-1 max-w-[250px] bg-black/5">
        <div className="bg-white p-2 rounded-md">
           <FileText className="w-5 h-5 text-gray-500" />
        </div>
        <div className="flex-1 overflow-hidden">
           <p className="text-xs font-medium truncate opacity-90 text-gray-800">{attachment.name}</p>
           <p className="text-[10px] opacity-70 uppercase">{attachment.name.split('.').pop()}</p>
        </div>
        <a href={attachment.url} download={attachment.name} className="p-1 hover:bg-black/10 rounded">
          <Download className="w-4 h-4 opacity-70" />
        </a>
      </div>
    );
  };

  return (
    <>
        {isCalling && (
            <CallOverlay 
                currentUser={currentUser}
                partnerName={session.participantName}
                partnerAvatar={session.participantAvatar}
                isVideo={isVideoCall}
                onEndCall={() => setIsCalling(false)}
            />
        )}

        <div className="flex flex-col h-full md:rounded-2xl md:shadow-lg overflow-hidden border transition-colors duration-300 animate-fade-in bg-white border-gray-200">
        {/* Header */}
        <div className="p-4 flex items-center justify-between sticky top-0 z-10 border-b bg-white border-gray-100 text-gray-900">
            <div className="flex items-center gap-3">
            <button onClick={onBack} className="md:hidden text-gray-500 hover:text-gray-700">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
            </button>
            <div className="relative">
                <img src={session.participantAvatar} alt={session.participantName} className="w-10 h-10 rounded-full object-cover border border-gray-200" />
                {session.isOnline && (
                <span className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 border-2 border-white rounded-full"></span>
                )}
            </div>
            <div>
                <h3 className="font-semibold">{session.participantName}</h3>
                <p className="text-xs flex items-center gap-1 text-gray-500">
                {session.isOnline ? 'En ligne' : 'Hors ligne'} • {session.participantDepartment}
                </p>
            </div>
            </div>
            
            <div className="flex items-center gap-2 text-gray-400">
            <button onClick={() => startCall(false)} className="p-2 rounded-full transition-colors hover:bg-gray-50"><Phone className="w-5 h-5" /></button>
            <button onClick={() => startCall(true)} className="p-2 rounded-full transition-colors hover:bg-gray-50"><Video className="w-5 h-5" /></button>
            </div>
        </div>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-6 bg-slate-50">
            {messages.map((msg) => {
            const isMe = msg.senderId === currentUser.id;
            return (
                <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'} animate-slide-up group`}>
                <div className={`flex max-w-[85%] md:max-w-[70%] ${isMe ? 'flex-row-reverse' : 'flex-row'} items-end gap-2`}>
                    {!isMe && (
                    <img src={session.participantAvatar} alt="sender" className="w-8 h-8 rounded-full mb-1 border border-gray-200" />
                    )}
                    
                    <div className="relative">
                        <div className={`p-4 rounded-2xl shadow-sm overflow-hidden ${
                        isMe 
                            ? 'bg-brand-600 text-white rounded-br-none' 
                            : 'bg-white text-gray-800 rounded-bl-none border border-gray-100'
                        }`}>
                        {msg.attachment && renderAttachment(msg.attachment)}
                        {msg.text && <p className="text-sm leading-relaxed whitespace-pre-wrap">{msg.text}</p>}
                        <p className={`text-[10px] mt-1 text-right ${isMe ? 'text-brand-100' : 'text-gray-400'}`}>
                            {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </p>
                        </div>
                        
                        {/* Delete Button for user's own messages */}
                        {isMe && (
                            <button 
                                onClick={() => handleDeleteMessage(msg.id)}
                                className="absolute -left-8 top-1/2 -translate-y-1/2 p-1.5 text-gray-400 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity bg-white/10 rounded-full"
                                title="Supprimer"
                            >
                                <Trash2 className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                </div>
                </div>
            );
            })}
            <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 border-t bg-white border-gray-100">
            {/* Attachment Preview */}
            {draftAttachment && (
            <div className="mb-3 p-3 border rounded-xl flex items-center justify-between animate-fade-in bg-gray-50 border-gray-200">
                <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg border flex items-center justify-center bg-white border-gray-200">
                    {draftAttachment.type.startsWith('image/') ? (
                        <ImageIcon className="w-5 h-5 text-brand-500" />
                    ) : (
                        <FileText className="w-5 h-5 text-gray-500" />
                    )}
                </div>
                <div className="flex flex-col">
                    <span className="text-sm font-medium truncate max-w-[200px] text-gray-700">{draftAttachment.name}</span>
                    <span className="text-xs text-gray-400">Prêt à envoyer</span>
                </div>
                </div>
                <button 
                onClick={() => setDraftAttachment(null)}
                className="p-1 rounded-full transition-colors hover:bg-gray-200 text-gray-500"
                >
                <X className="w-4 h-4" />
                </button>
            </div>
            )}

            <div className="flex items-center gap-2 p-2 rounded-xl border focus-within:ring-2 focus-within:ring-brand-500 focus-within:border-transparent transition-all bg-gray-50 border-gray-200">
            <input 
                type="file" 
                ref={fileInputRef}
                onChange={handleFileSelect}
                className="hidden" 
            />
            <button 
                onClick={triggerFileInput}
                className={`p-2 rounded-full transition-colors ${draftAttachment ? 'text-brand-500 bg-brand-50' : 'text-gray-400 hover:text-gray-600 hover:bg-gray-200'}`}
            >
                <Paperclip className="w-5 h-5" />
            </button>
            <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyPress}
                placeholder="Écrivez un message..."
                className="flex-1 bg-transparent border-none outline-none placeholder-gray-400 text-gray-700"
            />
            <button 
                onClick={handleSend}
                disabled={!input.trim() && !draftAttachment}
                className={`p-2 rounded-lg transition-all ${
                (input.trim() || draftAttachment)
                    ? 'bg-brand-600 text-white shadow-md hover:bg-brand-700' 
                    : 'bg-gray-200 text-gray-400 cursor-not-allowed'
                }`}
            >
                <Send className="w-5 h-5" />
            </button>
            </div>
        </div>
        </div>
    </>
  );
};

export default ChatInterface;