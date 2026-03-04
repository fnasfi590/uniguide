import React, { useState } from 'react';
import { UserRole, User } from '../types';
import { GraduationCap, School, Github, Linkedin, Facebook, Mail, ArrowRight, AlertCircle, Loader2, Lock, User as UserIcon, Building2 } from 'lucide-react';
import { db } from '../services/database';

interface AuthProps {
  onLogin: (user: User) => void;
}

const Auth: React.FC<AuthProps> = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [selectedRole, setSelectedRole] = useState<UserRole>(UserRole.STUDENT);
  
  // Form State
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [department, setDepartment] = useState('');
  
  // UI State
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (isLogin) {
        // Login Logic
        const user = await db.login(email, password);
        onLogin(user);
      } else {
        // Signup Logic
        if (!department) {
          throw new Error("Veuillez entrer votre département/filière");
        }
        const user = await db.signup(name, email, password, selectedRole, department);
        onLogin(user);
      }
    } catch (err: any) {
      setError(err.message || "Authentification échouée");
    } finally {
      setLoading(false);
    }
  };

  const handleSocialLogin = async (provider: 'linkedin' | 'facebook' | 'github' | 'gmail') => {
    let url = '';
    let mockEmail = '';
    let mockName = '';
    
    // Config for provider URLs and Mock Data
    const randomNum = Math.floor(Math.random() * 1000);
    
    switch (provider) {
      case 'linkedin':
        url = isLogin ? 'https://www.linkedin.com/login' : 'https://www.linkedin.com/signup';
        mockName = "Utilisateur LinkedIn";
        mockEmail = `linkedin.user${randomNum}@apac.tn`;
        break;
      case 'facebook':
        url = isLogin ? 'https://www.facebook.com/login' : 'https://www.facebook.com/r.php';
        mockName = "Utilisateur Facebook";
        mockEmail = `facebook.user${randomNum}@apac.tn`;
        break;
      case 'github':
        url = isLogin ? 'https://github.com/login' : 'https://github.com/signup';
        mockName = "Utilisateur GitHub";
        mockEmail = `github.user${randomNum}@apac.tn`;
        break;
      case 'gmail':
        url = isLogin ? 'https://accounts.google.com/signin' : 'https://accounts.google.com/signup';
        mockName = "Utilisateur Google";
        mockEmail = `google.user${randomNum}@apac.tn`;
        break;
    }
    
    window.open(url, '_blank');

    setLoading(true);
    setError(null);

    setTimeout(async () => {
        const authorized = window.confirm(`Simulation OAuth : Avez-vous réussi à vous connecter avec ${provider} en utilisant un compte @apac.tn ?`);

        if (!authorized) {
            setLoading(false);
            setError("L'utilisateur a annulé le processus.");
            return;
        }

        try {
            const departmentToUse = department || (selectedRole === UserRole.STUDENT ? "Études Générales" : "Corps Enseignant");
            const user = await db.socialLogin(mockEmail, mockName, selectedRole, departmentToUse);
            onLogin(user);
        } catch (err: any) {
            setError(err.message || "L'authentification sociale a échoué");
            setLoading(false);
        }
    }, 1000);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col lg:flex-row animate-fade-in">
      {/* Brand Section */}
      <div className="lg:w-1/2 bg-brand-600 p-12 flex flex-col justify-between text-white relative overflow-hidden">
        <div className="absolute inset-0 opacity-10 pointer-events-none">
           <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
             <path d="M0 100 C 20 0 50 0 100 100 Z" fill="white" />
           </svg>
        </div>
        
        <div className="z-10 animate-slide-up">
          <div className="flex items-center gap-2 text-2xl font-bold mb-2">
            <School className="w-8 h-8" />
            <span>UniGuide</span>
          </div>
          <p className="text-brand-100">Le pont entre savoir et curiosité.</p>
        </div>

        <div className="z-10 my-12 animate-slide-up" style={{ animationDelay: '0.1s' }}>
          <h1 className="text-4xl lg:text-5xl font-bold mb-6 leading-tight">
            Connectez-vous à votre<br/>
            Réseau Académique<br/>
            en Temps Réel.
          </h1>
          <p className="text-lg text-brand-100 max-w-md">
            Communication fluide pour étudiants et professeurs. Rejoignez la communauté dès aujourd'hui.
          </p>
        </div>

        <div className="z-10 text-sm text-brand-200">
          © 2024 UniGuide Inc.
        </div>
      </div>

      {/* Form Section */}
      <div className="lg:w-1/2 p-8 lg:p-12 flex items-center justify-center">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-xl p-8 border border-gray-100 animate-slide-up" style={{ animationDelay: '0.2s' }}>
          <h2 className="text-3xl font-bold text-gray-900 mb-2">
            {isLogin ? 'Bon retour' : 'Créer un compte'}
          </h2>
          <p className="text-gray-500 mb-8">
            {isLogin ? 'Entrez vos détails pour accéder au tableau de bord.' : 'Commencez votre parcours académique avec nous.'}
          </p>

          {error && (
            <div className="mb-6 p-3 bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg flex items-center gap-2 animate-pulse">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Role Selection */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <button
                type="button"
                onClick={() => setSelectedRole(UserRole.STUDENT)}
                className={`flex flex-col items-center justify-center p-4 rounded-xl border-2 transition-all duration-200 ${
                  selectedRole === UserRole.STUDENT 
                    ? 'border-brand-500 bg-brand-50 text-brand-700 shadow-sm ring-2 ring-brand-100' 
                    : 'border-gray-200 text-gray-400 hover:border-brand-200 hover:bg-gray-50'
                }`}
              >
                <GraduationCap className="w-6 h-6 mb-2" />
                <span className="font-medium">Étudiant</span>
              </button>
              <button
                type="button"
                onClick={() => setSelectedRole(UserRole.PROFESSOR)}
                className={`flex flex-col items-center justify-center p-4 rounded-xl border-2 transition-all duration-200 ${
                  selectedRole === UserRole.PROFESSOR 
                    ? 'border-purple-500 bg-purple-50 text-purple-700 shadow-sm ring-2 ring-purple-100' 
                    : 'border-gray-200 text-gray-400 hover:border-purple-200 hover:bg-gray-50'
                }`}
              >
                <School className="w-6 h-6 mb-2" />
                <span className="font-medium">Professeur</span>
              </button>
            </div>

            {!isLogin && (
              <>
                <div className="animate-fade-in">
                  <label className="block text-sm font-medium text-gray-700 mb-1.5 ml-1">Nom Complet</label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <UserIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="w-full pl-10 pr-4 py-3 rounded-xl border border-gray-200 bg-gray-50 text-gray-900 focus:bg-white focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all duration-200"
                      placeholder="Jean Dupont"
                    />
                  </div>
                </div>
                <div className="animate-fade-in">
                  <label className="block text-sm font-medium text-gray-700 mb-1.5 ml-1">Département</label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Building2 className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      type="text"
                      required
                      value={department}
                      onChange={(e) => setDepartment(e.target.value)}
                      className="w-full pl-10 pr-4 py-3 rounded-xl border border-gray-200 bg-gray-50 text-gray-900 focus:bg-white focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all duration-200"
                      placeholder={selectedRole === UserRole.STUDENT ? "Informatique" : "Faculté des Sciences"}
                    />
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5 ml-1">Adresse Email</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-xl border border-gray-200 bg-gray-50 text-gray-900 focus:bg-white focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all duration-200"
                  placeholder="prenom.nom@apac.tn"
                  pattern="^[a-zA-Z0-9]+\.[a-zA-Z0-9]+@apac\.tn$"
                  title="L'email doit être au format : prenom.nom@apac.tn"
                />
              </div>
              <p className="text-xs text-gray-400 mt-1.5 ml-1">Doit être une adresse @apac.tn (ex: zied.benhamad@apac.tn)</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5 ml-1">Mot de passe</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-xl border border-gray-200 bg-gray-50 text-gray-900 focus:bg-white focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all duration-200"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full py-4 rounded-xl text-white font-semibold flex items-center justify-center gap-2 transition-all shadow-lg hover:shadow-xl hover:scale-[1.02] active:scale-[0.98] mt-6 ${
                 selectedRole === UserRole.STUDENT ? 'bg-brand-600 hover:bg-brand-700 shadow-brand-200' : 'bg-purple-600 hover:bg-purple-700 shadow-purple-200'
              }`}
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Traitement...</span>
                </>
              ) : (
                <>
                  {isLogin ? 'Se connecter' : "S'inscrire"} <ArrowRight className="w-5 h-5" />
                </>
              )}
            </button>
          </form>

          <div className="relative my-8">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-200"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-white text-gray-500">Ou continuer avec</span>
            </div>
          </div>

          <div className="grid grid-cols-4 gap-4">
            <button 
              onClick={() => handleSocialLogin('linkedin')}
              disabled={loading}
              className="flex items-center justify-center p-3 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50 hover:shadow-sm"
              title="LinkedIn"
            >
              <Linkedin className="w-5 h-5 text-[#0077b5]" />
            </button>
            <button 
              onClick={() => handleSocialLogin('facebook')}
              disabled={loading}
              className="flex items-center justify-center p-3 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50 hover:shadow-sm"
              title="Facebook"
            >
              <Facebook className="w-5 h-5 text-[#1877f2]" />
            </button>
            <button 
              onClick={() => handleSocialLogin('github')}
              disabled={loading}
              className="flex items-center justify-center p-3 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50 hover:shadow-sm"
              title="GitHub"
            >
              <Github className="w-5 h-5 text-gray-900" />
            </button>
            <button 
              onClick={() => handleSocialLogin('gmail')}
              disabled={loading}
              className="flex items-center justify-center p-3 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50 hover:shadow-sm"
              title="Google"
            >
              <Mail className="w-5 h-5 text-red-500" />
            </button>
          </div>

          <p className="mt-8 text-center text-sm text-gray-600">
            {isLogin ? "Vous n'avez pas de compte ? " : "Vous avez déjà un compte ? "}
            <button
              onClick={() => {
                setIsLogin(!isLogin);
                setError(null);
              }}
              className="font-semibold text-brand-600 hover:text-brand-700 transition-colors"
            >
              {isLogin ? "S'inscrire" : 'Se connecter'}
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Auth;