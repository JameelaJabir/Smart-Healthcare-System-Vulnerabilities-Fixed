# Smart Healthcare System — Security Hardened

> SE4030 Secure Software Development · Group Assignment

A full-stack hospital management web application originally sourced from a third-party repository. The project identifies, analyses, and remediates **8 distinct security vulnerabilities**, then extends the application with a **Google OAuth 2.0 (PKCE Authorization Code Flow)** login feature.

---

## Repository Links

| Resource | URL |
|----------|-----|
| Original Project (previous semester developed project) | [GitHub — Original](https://github.com/JameelaJabir/Smart-Healthcare-System) |
| Modified Project (vulnerabilities fixed) | [GitHub — Fixed](https://github.com/JameelaJabir/Smart-Healthcare-System-Vulnerabilities-Fixed) |

---

## Tech Stack

**Backend** — Node.js · Express · TypeScript · MongoDB (Mongoose) · JWT · Passport.js  
**Frontend** — React · Vite · TypeScript  
**Security Tools Used** — OWASP ZAP · npm audit · manual code review

---

## Vulnerabilities Identified & Fixed

### 1. NoSQL Injection (OWASP A03 — Injection)
**Original:** MongoDB queries accepted raw user-supplied objects (e.g. `{ $ne: null }`) directly, allowing authentication bypass and data exfiltration.  
**Fix:** Introduced `InputSanitizer.sanitizeObjectId()` and `sanitizeString()` in [`inputValidation.ts`](Hospital-Backend/dist/middlewares/inputValidation.js) to strip MongoDB operators (`$where`, `$ne`, `$or`, `$and`, `$regex`) and validate all ObjectId parameters before they reach the database layer.

---

### 2. Broken Authentication — Weak JWT Handling (OWASP A07)
**Original:** JWT secret fell back to the hardcoded string `'JWT_SECRET'` if the environment variable was absent, and tokens had no expiry enforcement.  
**Fix:** [`verifyToken.ts`](Hospital-Backend/dist/middlewares/verifyToken.js) now strictly reads `process.env.JWT_SECRET`, rejects malformed `Authorization` headers early, and surfaces a clear `401` for invalid or expired tokens. The `.env.example` enforces providing a real secret.

---

### 3. Missing Security Headers (OWASP A05 — Security Misconfiguration)
**Original:** The Express server sent no security-related HTTP headers, leaving the app exposed to clickjacking, MIME-type sniffing, and cross-site scripting via the browser.  
**Fix:** Added `helmet()` middleware in [`app.ts`](Hospital-Backend/dist/app.js), which sets `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, and related headers automatically.

---

### 4. Overly Permissive CORS (OWASP A05)
**Original:** CORS was configured with a wildcard origin (`*`), allowing any site to make credentialed cross-origin requests to the API.  
**Fix:** CORS is now restricted to the explicit `FRONTEND_ORIGIN` environment variable (`cors({ origin, credentials: true })`), so only the known frontend can perform credentialed calls.

---

### 5. Unrestricted File Upload (OWASP A04 — Insecure Design)
**Original:** The file upload endpoint accepted any MIME type and had no size limit, enabling server-side attacks via malicious file uploads.  
**Fix:** [`upload.ts`](Hospital-Backend/dist/middlewares/upload.js) uses a `multer` file filter to accept **only `application/pdf`** files and enforces a **5 MB** size cap. Any other type is rejected before the file reaches disk.

---

### 6. Server-Side Request Forgery — SSRF (OWASP A10)
**Original:** Endpoints that proxied external URLs accepted arbitrary user-supplied URLs, which could be used to reach internal services or cloud metadata endpoints.  
**Fix:** `InputSanitizer.validateUrl()` in [`inputValidation.ts`](Hospital-Backend/dist/middlewares/inputValidation.js) validates that URLs use HTTP/HTTPS, checks the hostname against an explicit allowlist, and blocks private/internal IP ranges (`10.x`, `172.16–31.x`, `192.168.x`, `127.x`, `169.254.x`).

---

### 7. Insufficient Input Validation on Appointment Data (OWASP A03)
**Original:** Appointment creation endpoints performed no server-side validation, allowing malformed dates, arbitrary status values, and oversized text fields to reach the database.  
**Fix:** `validateAppointmentData` middleware (using `express-validator`) enforces ISO 8601 dates, `HH:MM` time format, enumerated status values (`Active`, `Canceled`, `Completed`), character-length limits, and sanitisation for all string fields before the request is processed.

### 8. Vite Information Disclosure — CVE-2025-30208 (OWASP A05 — Security Misconfiguration)
**Original:** Vite's development server exposed arbitrary files from the project root (including `.env`, `package.json`, and config files) via crafted `/@fs/` URL requests, leaking secrets and configuration to any browser that could reach the dev server.  
**Fix:** [`vite.config.ts`](Hospital-Frontend/vite.config.ts) adds a `server.fs.deny` list that explicitly blocks `.env`, `.env.*`, `vite.config.ts`, `vite.config.js`, `package.json`, and `package-lock.json` from being served, preventing sensitive files from being read through the filesystem endpoint. The Vite dependency was also upgraded to `^7.1.6`, which includes the upstream patch.

---

## OAuth 2.0 / OpenID Connect Implementation

**Flow:** Authorization Code Grant with PKCE (RFC 7636) using **Google as the Identity Provider**

### How it works

1. **Initiate** — User clicks "Sign in with Google"; the backend generates a `code_verifier` (random 32-byte base64url string) and its `code_challenge` (SHA-256 hash), stores the verifier in an `httpOnly` cookie, and redirects the browser to Google's authorization endpoint.
2. **Authorize** — Google authenticates the user and redirects back to `/api/v1/auth/oauth/callback` with an authorization `code`.
3. **Exchange** — The backend reads the PKCE verifier from the cookie, exchanges the code + verifier for an `access_token` at Google's token endpoint.
4. **Profile** — The backend calls Google's UserInfo endpoint with the access token to retrieve `email`, `name`, and profile details.
5. **Session** — A local user/staff record is upserted in MongoDB. A signed JWT (24 h expiry) is issued and passed to the frontend via a redirect with a URL fragment, which the frontend reads and stores in memory.

### Key files

| File | Purpose |
|------|---------|
| [`config/oidc.ts`](Hospital-Backend/dist/config/oidc.js) | PKCE helper functions (`generateCodeVerifier`, `generateCodeChallenge`) and Google OAuth URL constants |
| [`routes/oauth.routes.ts`](Hospital-Backend/dist/routes/oauth.routes.js) | `/oauth/login` and `/oauth/callback` route handlers |

### Environment variables required

```env
OIDC_CLIENT_ID=your-google-client-id
OIDC_CLIENT_SECRET=your-google-client-secret        # leave empty for public PKCE clients
OIDC_REDIRECT_URI=http://localhost:3000/api/v1/auth/oauth/callback
OIDC_SCOPE=openid profile email
```

---

## Getting Started

### Prerequisites

- Node.js 18+
- MongoDB (local or Atlas)
- Google OAuth 2.0 credentials (for the OAuth feature)

### Backend setup

```bash
cd Hospital-Backend
cp .env.example .env          # fill in your values
npm install
npm run build
npm start
```

### Frontend setup

```bash
cd Hospital-Frontend
cp .env.example .env          # set REACT_APP_API_BASE_URL
npm install
npm run dev
```

The backend runs on `http://localhost:3000` and the frontend on `http://localhost:5173` by default.

---

## Security Testing Tools Used

| Tool | Purpose |
|------|---------|
| [OWASP ZAP](https://www.zaproxy.org/) | Black-box scanning — active and passive scans |
| `npm audit` | Dependency vulnerability audit |
| Manual code review | White-box analysis against OWASP Top 10 |

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [Google Identity — OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [express-validator](https://express-validator.github.io/docs/)
- [Helmet.js](https://helmetjs.github.io/)
