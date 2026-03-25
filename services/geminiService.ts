import { GoogleGenAI, Chat, Modality } from "@google/genai";
import { UserRole, Attachment } from "../types";
import { API_KEY, GEMINI_MODEL, LIVE_MODEL } from "../config";

let chatSession: Chat | null = null;

// Initialize with the key from config.ts
const ai = new GoogleGenAI({ apiKey: API_KEY });

// Helpers for Audio Processing
function base64ToUint8Array(base64: string) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function arrayBufferToBase64(buffer: ArrayBuffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

export const initializeChat = (userRole: UserRole, partnerName: string, partnerDepartment: string) => {
  const isAnonymousProfessor = partnerName === "Professeur";

  const systemInstruction = userRole === UserRole.STUDENT
    ? (isAnonymousProfessor 
        ? `Tu es un professeur serviable et compétent du département ${partnerDepartment}. Tu parles à un étudiant. Sois encourageant, académique mais accessible. Réponds en français.`
        : `Tu es le Professeur ${partnerName}, un professeur serviable et compétent du département ${partnerDepartment}. Tu parles à un étudiant. Sois encourageant, académique mais accessible. Réponds en français.`)
    : `Tu es un étudiant nommé ${partnerName} du département ${partnerDepartment}. Tu parles à ton professeur. Tu es respectueux et curieux. Réponds en français.`;

  chatSession = ai.chats.create({
    model: GEMINI_MODEL,
    config: {
      systemInstruction,
      temperature: 0.7,
    },
  });
};

export const sendMessageToGemini = async (message: string, attachment?: Attachment): Promise<string> => {
  if (!chatSession) {
    throw new Error("Session de chat non initialisée");
  }

  try {
    let result;
    
    if (attachment && attachment.type.startsWith('image/')) {
        const base64Data = attachment.url.split(',')[1];
        const parts = [
            { text: message || " " },
            { inlineData: { mimeType: attachment.type, data: base64Data } }
        ];
        result = await chatSession.sendMessage({ message: parts as any });
    } else {
        const textToSend = attachment 
            ? `${message}\n\n[L'utilisateur a envoyé un fichier: ${attachment.name}]` 
            : message;
        result = await chatSession.sendMessage({ message: textToSend });
    }

    return result.text || "Je rencontre des problèmes de connexion.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Erreur de connexion. Veuillez réessayer.";
  }
};

// --- Live API Implementation for Video/Audio Calls ---

export const startLiveSession = async (
  userRole: UserRole, 
  partnerName: string,
  onAudioData: (base64Audio: string) => void,
  onClose: () => void
) => {
    const isAnonymousProfessor = partnerName === "Professeur";

    const systemInstruction = userRole === UserRole.STUDENT
    ? (isAnonymousProfessor 
        ? `Tu es un professeur. Tu es en appel vidéo avec un étudiant. Parle de manière naturelle, concise et utile. Réponds en français.`
        : `Tu es le Professeur ${partnerName}. Tu es en appel vidéo avec un étudiant. Parle de manière naturelle, concise et utile. Réponds en français.`)
    : `Tu es l'étudiant ${partnerName}. Tu es en appel avec ton professeur. Réponds en français.`;

  try {
    const session = await ai.live.connect({
      model: LIVE_MODEL,
      config: {
        systemInstruction,
        responseModalities: [Modality.AUDIO],
        speechConfig: {
            voiceConfig: { prebuiltVoiceConfig: { voiceName: userRole === UserRole.STUDENT ? 'Fenrir' : 'Puck' } }
        }
      },
      callbacks: {
        onopen: () => console.log("Live session connected"),
        onmessage: (msg) => {
            if (msg.serverContent?.modelTurn?.parts?.[0]?.inlineData?.data) {
                onAudioData(msg.serverContent.modelTurn.parts[0].inlineData.data);
            }
        },
        onclose: () => {
            console.log("Live session closed");
            onClose();
        },
        onerror: (err) => console.error("Live session error", err)
      }
    });

    return session;
  } catch (e) {
    console.error("Failed to start live session", e);
    throw e;
  }
};

export const sendRealtimeAudio = async (session: any, inputData: Float32Array) => {
    // Convert Float32Array to 16-bit PCM
    const pcmData = new Int16Array(inputData.length);
    for (let i = 0; i < inputData.length; i++) {
        // Clamp values
        const s = Math.max(-1, Math.min(1, inputData[i]));
        pcmData[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
    }
    
    // Create base64
    const base64 = arrayBufferToBase64(pcmData.buffer);

    session.sendRealtimeInput({
        media: {
            mimeType: 'audio/pcm;rate=16000',
            data: base64
        }
    });
};