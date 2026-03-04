// INSTRUCTIONS FOR UNIGUIDE.FUN:
// 1. Go to https://aistudio.google.com/app/apikey
// 2. Create a NEW API Key (It will start with "AIza" and is approx 39 chars long).
// 3. Click on the key name to edit settings.
// 4. Under "Application restrictions", select "Websites".
// 5. Add "https://uniguide.fun" and "https://www.uniguide.fun".
// 6. Copy the key and paste it inside the quotes below.

// If process.env.API_KEY is defined (via Vite define), it will be used.
// Otherwise, it falls back to the hardcoded key.
// @ts-ignore
export const API_KEY = (typeof process !== 'undefined' && process.env.API_KEY) || "AIzaSy_PASTE_YOUR_REAL_KEY_HERE";

// If you want to use a specific model version, you can configure it here
export const GEMINI_MODEL = "gemini-1.5-flash";
export const LIVE_MODEL = "gemini-2.0-flash-exp";
