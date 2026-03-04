import React, { useEffect, useRef, useState } from 'react';
import { Mic, MicOff, Video, VideoOff, PhoneOff, User as UserIcon, AlertCircle, RotateCcw, X } from 'lucide-react';
import { User, UserRole } from '../types';
import { startLiveSession, sendRealtimeAudio } from '../services/geminiService';

interface CallOverlayProps {
  currentUser: User;
  partnerName: string;
  partnerAvatar: string;
  isVideo: boolean;
  onEndCall: () => void;
}

const CallOverlay: React.FC<CallOverlayProps> = ({ currentUser, partnerName, partnerAvatar, isVideo, onEndCall }) => {
  const [isMuted, setIsMuted] = useState(false);
  const [cameraEnabled, setCameraEnabled] = useState(isVideo);
  const [status, setStatus] = useState("Connexion...");
  const [volume, setVolume] = useState(0);
  const [error, setError] = useState<string | null>(null);
  
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const sessionRef = useRef<any>(null);

  // Audio Processing Refs
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const sourceRef = useRef<MediaStreamAudioSourceNode | null>(null);
  const streamRef = useRef<MediaStream | null>(null);

  useEffect(() => {
    let mounted = true;

    const initCall = async () => {
      setError(null);
      setStatus("Connexion...");

      try {
        // 1. Get User Media
        let stream;
        try {
            stream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    sampleRate: 16000,
                    channelCount: 1,
                    echoCancellation: true
                },
                video: true // Always get video for the local preview
            });
        } catch (mediaErr) {
            console.error("Media Error:", mediaErr);
            throw new Error("Accès au microphone ou à la caméra refusé. Veuillez vérifier vos permissions.");
        }
        
        streamRef.current = stream;

        if (localVideoRef.current) {
          localVideoRef.current.srcObject = stream;
          if (!cameraEnabled) {
             const videoTrack = stream.getVideoTracks()[0];
             if(videoTrack) videoTrack.enabled = false;
          }
        }

        // 2. Setup Audio Context
        const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
        audioContextRef.current = new AudioContextClass({ sampleRate: 16000 });
        
        // Output Audio Context (for receiving)
        const outputAudioContext = new AudioContextClass({ sampleRate: 24000 });
        let nextStartTime = 0;

        // 3. Connect to Live API
        try {
            sessionRef.current = await startLiveSession(
                currentUser.role, 
                partnerName, 
                async (base64Audio) => {
                    // Play Audio
                    if (!mounted) return;
                    
                    // Visualizer effect
                    setVolume(Math.random() * 100); 
                    setTimeout(() => setVolume(0), 200);

                    const binaryString = atob(base64Audio);
                    const len = binaryString.length;
                    const bytes = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    
                    const dataInt16 = new Int16Array(bytes.buffer);
                    const buffer = outputAudioContext.createBuffer(1, dataInt16.length, 24000);
                    const channelData = buffer.getChannelData(0);
                    for (let i = 0; i < dataInt16.length; i++) {
                        channelData[i] = dataInt16[i] / 32768.0;
                    }

                    const source = outputAudioContext.createBufferSource();
                    source.buffer = buffer;
                    source.connect(outputAudioContext.destination);
                    
                    const currentTime = outputAudioContext.currentTime;
                    if (nextStartTime < currentTime) nextStartTime = currentTime;
                    source.start(nextStartTime);
                    nextStartTime += buffer.duration;
                },
                () => {
                    if(mounted) {
                        setStatus("Appel terminé");
                        setTimeout(onEndCall, 1000);
                    }
                }
            );
        } catch (apiErr) {
            console.error("API Error:", apiErr);
            throw new Error("Échec de la connexion au serveur d'appel. Veuillez réessayer.");
        }

        setStatus("En ligne");

        // 4. Send Input Audio
        const source = audioContextRef.current.createMediaStreamSource(stream);
        const processor = audioContextRef.current.createScriptProcessor(4096, 1, 1);
        
        processor.onaudioprocess = (e) => {
            if (isMuted || !sessionRef.current) return;
            // Only send if not errored
            if (error) return; 

            const inputData = e.inputBuffer.getChannelData(0);
            try {
                sendRealtimeAudio(sessionRef.current, inputData);
            } catch (e) {
                console.error("Error sending audio frame", e);
            }
        };

        source.connect(processor);
        processor.connect(audioContextRef.current.destination); // Required for script processor to run
        
        sourceRef.current = source;
        processorRef.current = processor;

      } catch (err: any) {
        console.error("Initialization error", err);
        setError(err.message || "Une erreur inattendue est survenue.");
        setStatus("Erreur");
      }
    };

    initCall();

    return () => {
      mounted = false;
      // Cleanup
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(track => track.stop());
      }
      if (processorRef.current) processorRef.current.disconnect();
      if (sourceRef.current) sourceRef.current.disconnect();
      if (audioContextRef.current) audioContextRef.current.close();
      if (sessionRef.current) {
          // No explicit close on the simplified client object, usually handled by closing WS
      }
    };
  }, []); // Run once on mount

  const toggleMute = () => {
    setIsMuted(!isMuted);
  };

  const toggleCamera = () => {
    setCameraEnabled(!cameraEnabled);
    if (streamRef.current) {
      const videoTrack = streamRef.current.getVideoTracks()[0];
      if (videoTrack) videoTrack.enabled = !cameraEnabled;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-white flex flex-col animate-fade-in">
      {/* Remote Video (Simulated/Full Screen) */}
      <div className="flex-1 relative flex items-center justify-center overflow-hidden bg-gray-50">
        {/* Blurred background - using lighter colors for Light Mode */}
        <div className="absolute inset-0 bg-gradient-to-b from-gray-50 to-gray-100">
           <img src={partnerAvatar} className="w-full h-full object-cover opacity-20 blur-xl" />
        </div>

        {/* Central Avatar / "Remote Video" / Error State */}
        <div className="relative z-10 flex flex-col items-center max-w-md text-center p-4">
            {error ? (
                <div className="bg-red-50 backdrop-blur-md p-6 rounded-2xl border border-red-200 animate-bounce-in shadow-lg">
                    <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                        <AlertCircle className="w-8 h-8 text-red-600" />
                    </div>
                    <h3 className="text-xl font-bold text-red-900 mb-2">Erreur de connexion</h3>
                    <p className="text-red-600 mb-6">{error}</p>
                    <button 
                        onClick={onEndCall} 
                        className="px-6 py-2 bg-red-600 text-white font-semibold rounded-lg hover:bg-red-700 transition-colors shadow-sm"
                    >
                        Fermer
                    </button>
                </div>
            ) : (
                <>
                    <div className={`relative rounded-full p-2 transition-all duration-100 bg-white shadow-sm ${volume > 10 ? 'ring-4 ring-green-500/30' : ''} ${status === 'Erreur' ? 'ring-4 ring-red-500/30' : ''}`}>
                        <img 
                            src={partnerAvatar} 
                            alt={partnerName} 
                            className="w-32 h-32 md:w-48 md:h-48 rounded-full border-4 border-gray-50 shadow-xl object-cover" 
                        />
                        <span className={`absolute bottom-2 right-2 w-6 h-6 border-4 border-white rounded-full ${status === 'En ligne' ? 'bg-green-500' : status === 'Erreur' ? 'bg-red-500' : 'bg-yellow-500'}`}></span>
                    </div>
                    <h2 className="mt-6 text-2xl font-bold text-gray-900 tracking-wide">{partnerName}</h2>
                    <p className={`animate-pulse font-medium ${status === 'Erreur' ? 'text-red-500' : 'text-brand-600'}`}>{status}</p>
                </>
            )}
        </div>

        {/* Local Video (PiP) */}
        {!error && (
            <div className="absolute top-4 right-4 w-32 md:w-48 aspect-[3/4] bg-white rounded-xl overflow-hidden shadow-2xl border border-gray-200">
                {cameraEnabled ? (
                    <video 
                        ref={localVideoRef} 
                        autoPlay 
                        muted 
                        playsInline 
                        className="w-full h-full object-cover mirror-mode"
                        style={{ transform: 'scaleX(-1)' }} // Mirror effect
                    />
                ) : (
                    <div className="w-full h-full flex items-center justify-center bg-gray-100">
                        <UserIcon className="w-10 h-10 text-gray-400" />
                    </div>
                )}
            </div>
        )}
      </div>

      {/* Controls Bar - Light Mode */}
      <div className="bg-white/90 backdrop-blur-md p-6 pb-10 flex justify-center items-center gap-6 animate-slide-up border-t border-gray-100">
        {!error && (
            <>
                <button 
                    onClick={toggleMute}
                    className={`p-4 rounded-full transition-all duration-300 border ${isMuted ? 'bg-gray-100 text-gray-900 border-gray-200' : 'bg-white text-gray-700 hover:bg-gray-50 border-gray-200 shadow-sm'}`}
                    title={isMuted ? "Activer le micro" : "Couper le micro"}
                >
                    {isMuted ? <MicOff className="w-6 h-6" /> : <Mic className="w-6 h-6" />}
                </button>

                <button 
                    onClick={onEndCall}
                    className="p-5 bg-red-500 hover:bg-red-600 rounded-full shadow-lg shadow-red-200 transform hover:scale-110 transition-all duration-300 text-white"
                    title="Raccrocher"
                >
                    <PhoneOff className="w-8 h-8" />
                </button>

                <button 
                    onClick={toggleCamera}
                    className={`p-4 rounded-full transition-all duration-300 border ${!cameraEnabled ? 'bg-gray-100 text-gray-900 border-gray-200' : 'bg-white text-gray-700 hover:bg-gray-50 border-gray-200 shadow-sm'}`}
                    title={!cameraEnabled ? "Activer la caméra" : "Désactiver la caméra"}
                >
                    {!cameraEnabled ? <VideoOff className="w-6 h-6" /> : <Video className="w-6 h-6" />}
                </button>
            </>
        )}
        {error && (
            <button 
                onClick={onEndCall}
                className="p-4 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-700 transition-all"
            >
                <X className="w-6 h-6" />
            </button>
        )}
      </div>
    </div>
  );
};

export default CallOverlay;