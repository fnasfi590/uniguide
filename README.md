# UniGuide - Académique Connexion

UniGuide est une plateforme de communication en temps réel pour le milieu académique, permettant aux étudiants et aux professeurs de collaborer efficacement.

## 🚀 Fonctionnalités

- **Authentification Sécurisée** : JWT + Bcrypt pour la protection des données utilisateurs.
- **Base de Données SQL** : Utilisation de SQLite pour une gestion persistante et robuste.
- **Proxy IA** : Intégration de Google Gemini avec protection de la clé API côté serveur.
- **Anonymat Étudiant** : Protection de l'identité des professeurs lors des premiers contacts étudiants.
- **Interface Moderne** : React 19 + Tailwind CSS + Lucide Icons.

## 🛠️ Installation

1. Installez les dépendances :
   ```bash
   npm install
   ```

2. Configurez l'environnement :
   Créez un fichier `.env` à la racine et ajoutez vos clés :
   ```env
   GEMINI_API_KEY=votre_cle_gemini
   JWT_SECRET=votre_secret_jwt
   PORT=5000
   ```

## 💻 Développement

Pour lancer le frontend et le backend en parallèle :
```bash
npm run dev
```

- **Frontend** : http://localhost:3000
- **Backend** : http://localhost:5000

## 🧪 Tests & Qualité

- **Tests Unitaires** : `npm run test` (Vitest)
- **Tests d'Intégration (Reconnexion)** : `npm run test:reconnection`
- **Linting** : `npm run lint` (ESLint)
- **Formatage** : `npm run format` (Prettier)

## 🏗️ Architecture

- `/src` : Code source frontend (React + Vite)
  - `/components` : Composants UI réutilisables
  - `/services` : Logique d'API et services tiers
- `server.js` : Backend Node.js Express + SQLite
- `database.sqlite` : Fichier de base de données local

## 🔒 Sécurité

- Protection contre les injections SQL via des requêtes préparées.
- En-têtes de sécurité avec Helmet.
- Validation des entrées et gestion d'erreurs centralisée.
- Hashage des mots de passe.
