// Configure your backend here
// Example Netlify base (Functions): https://<site>.netlify.app/.netlify/functions/api
// Example Vercel base (Serverless): https://<project>.vercel.app/api
// NOTE: must support CORS for chrome-extension scheme.

// Whitelist of allowed API endpoints for security
const ALLOWED_ORIGINS = [
  'https://topperytext.netlify.app',
  'https://topperytext.vercel.app'
];

const API_BASE = "https://topperytext.netlify.app/.netlify/functions/api";

// Validate API endpoint before making requests
function validateApiEndpoint(url) {
  try {
    const urlObj = new URL(url);
    return ALLOWED_ORIGINS.some(origin => urlObj.origin === origin);
  } catch {
    return false;
  }
}

export default { 
  API_BASE,
  validateApiEndpoint,
  ALLOWED_ORIGINS
};
