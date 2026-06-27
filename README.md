# Smart Healthcare System - Security Hardened

> **SE4030 - Secure Software Development** | Group Assignment | SLIIT

A full-stack Hospital Management System originally developed as a previous-semester project. This repository is the **security-hardened version** - it identifies, analyses, and remediates **8 distinct vulnerabilities** found in the original application, and extends it with a **Google OAuth 2.0 (Authorization Code Grant with PKCE)** login feature.

---

## Group Members

| Name | Index Number |
|------|-------------|
| Senevirathna K.M.U.T | IT22056320 |
| Mahindarathna D.G.P.T.D | IT22076052 |
| Jameela M.J.F | IT22060662 |
| Ariyasena M.K.M.M | IT22562524 |

---

## Links

| Resource | URL |
|----------|-----|
| Original Project (previous semester) | [GitHub - Smart-Healthcare-System](https://github.com/JameelaJabir/Smart-Healthcare-System) |
| Modified Project (vulnerabilities fixed) | [GitHub - Smart-Healthcare-System-Vulnerabilities-Fixed](https://github.com/JameelaJabir/Smart-Healthcare-System-Vulnerabilities-Fixed) |


---

## Application Overview

The Hospital Management System is a web application that manages hospital operations including:

- Staff and patient registration & authentication
- Appointment scheduling and management
- Patient diagnosis records
- Payment and bank deposit processing
- Insurance management
- Staff profile management
- Role-based dashboards (ADMIN, DOCTOR, NURSE, PATIENT)

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| Backend | Node.js · Express · TypeScript · MongoDB (Mongoose) · JWT |
| Frontend | React · Vite · TypeScript · TailwindCSS |
| Auth | Google OAuth 2.0 (PKCE) · JWT |
| Security Tools | OWASP ZAP · npm audit · Retire.js · npm-check · Semgrep |

---

## Vulnerabilities - Summary

| # | Vulnerability | OWASP Category | Severity | CVE / CWE | Fixed by |
|---|--------------|----------------|----------|-----------|---------|
| 1 | NoSQL Injection | A03:2021 – Injection | Medium | CWE-943 | IT22056320 |
| 2 | SSRF in Axios | A10:2021 – SSRF | Low (High Impact) | CVE-2025-27152 | IT22056320 |
| 3 | Vulnerable & Outdated Components | A06:2021 – Outdated Components | High | CVE-2019-10744 (Lodash) | IT22076052 |
| 4 | No Input Validation / XSS | A03:2021 – Injection | High | CWE-79 | IT22076052 |
| 5 | Hard-coded Credentials in Source Code | A05:2021 – Security Misconfiguration | High | CVE-2019-5418 | IT22060662 |
| 6 | Exposed Secrets in Version Control | A05:2021 – Security Misconfiguration | High | - | IT22060662 |
| 7 | CORS Misconfiguration | A05:2021 – Security Misconfiguration | Medium | - | IT22562524 |
| 8 | Vite Information Disclosure | A05:2021 – Security Misconfiguration | Medium | CVE-2025-30208 | IT22562524 |

---

## Vulnerability Details

### 1. NoSQL Injection - `A03:2021` · CWE-943 · Severity: Medium

**Original issue:** The appointment controller passed `req.params.id` and `req.params.staffId` directly into MongoDB queries without any validation. Attackers could inject operators like `{"$ne": null}` or `{"$where": "true"}` to bypass queries, return all records, or execute arbitrary JavaScript in the database context.

```js
// Before — vulnerable
const appointment = await appointmentService.findById(req.params.id);
const staffAppointments = await appointmentService.findByStaffId(req.params.staffId);
```

**Fix:** Created `inputValidation.ts` with `InputSanitizer.sanitizeObjectId()` that strips non-hex characters, validates 24-character ObjectId format using Mongoose, and rejects anything that doesn't match. Route-level middleware (`validateAppointmentId`, `validateStaffId`) wraps every appointment route before the handler runs.

```js
// After — secure
const sanitizedId = InputSanitizer.sanitizeObjectId(req.params.id);
if (!sanitizedId) return res.status(400).json({ error: 'Invalid appointment ID format' });
const appointment = await appointmentService.findById(sanitizedId);
```

**Relevant files:** [Hospital-Backend/dist/middlewares/inputValidation.js](Hospital-Backend/dist/middlewares/inputValidation.js) · [Hospital-Backend/dist/routes/appointment.routes.js](Hospital-Backend/dist/routes/appointment.routes.js)

---

### 2. Server-Side Request Forgery (SSRF) in Axios - `A10:2021` · CVE-2025-27152 · Severity: Low (High Impact)

**Original issue:** The frontend's `AuthService.tsx` used Axios directly with hardcoded URLs and no host restrictions. Malicious actors could manipulate request targets to reach internal services, cloud metadata endpoints (`169.254.169.254`), or scan the internal network.

```ts
// Before — vulnerable
const response = await axios.post('http://localhost:3000/api/v1/auth/login', { email, password });
```

**Fix:** Created `secureHttpClient.ts`, a wrapper around Axios that validates every URL against an explicit allowlist of hosts (`localhost`, `127.0.0.1`, `api.hospital-app.com`), allowed ports, and allowed protocols. Private IP ranges are blocked via regex. All auth service calls were updated to use this client.

```ts
// After — secure
import { secureHttpClient } from '../utils/secureHttpClient';
const response = await secureHttpClient.post<AuthResponse>('http://localhost:3000/api/v1/auth/login', { email, password });
```

---

### 3. Vulnerable & Outdated Components - `A06:2021` · CVE-2019-10744 · Severity: High

**Original issue:** Several npm packages (Axios, Lodash, TailwindCSS) were flagged by `npm audit`, `retire`, and `npm-check` as outdated and containing known vulnerabilities. Lodash's prototype pollution (CVE-2019-10744) was the most critical finding. The initial `npm audit` showed **8 vulnerabilities (4 low, 1 moderate, 2 high, 1 critical)**.

**Fix:**
- Ran `npm audit fix` to apply safe patch/minor updates automatically (result: **0 vulnerabilities**)
- Manually upgraded major packages (Axios, TailwindCSS) in isolated branches after compatibility testing
- Avoided `npm audit fix --force` in production (it caused breaking changes)
- Updated and committed `package-lock.json` for consistent dependency versions
- Integrated `npm audit`, `retire`, and `npm-check` into the workflow for continuous monitoring

---

### 4. No Input Validation & Output Sanitization (XSS) - `A03:2021` · CWE-79 · Severity: High

**Original issue:** Login fields, patient registration fields, and profile fields rendered user input directly into the UI without sanitization. Attackers could inject `<script>alert('XSS Attack!')</script>` into password or name fields, leading to reflected/stored XSS, session hijacking, or phishing.

**Fix:**
- **Client-side:** Added pattern detection in form validation that flags script tags and event handlers. The login form now shows "Security threat detected: Script tag detected" when injection is attempted.
- **Output sanitization:** Integrated `DOMPurify` on the frontend to clean user-supplied content before rendering.
- **Safe object handling:** Whitelisted allowed fields to prevent prototype pollution via deep merges.
- **Secure defaults:** Text-only rendering enforced for all non-HTML fields.

**Relevant files:** [Hospital-Backend/dist/middlewares/inputValidation.js](Hospital-Backend/dist/middlewares/inputValidation.js) · [Hospital-Backend/dist/middlewares/validateRequest.js](Hospital-Backend/dist/middlewares/validateRequest.js)

---

### 5. Hard-coded Credentials in Source Code - `A05:2021` · Severity: High

**Original issue:** A live MongoDB Atlas connection string (including username and password) was hardcoded in `src/config/db.ts`. Backend API base URLs were also hardcoded in multiple React components (`AdminDashboard.tsx`, `AdminPatientPage.tsx`, `PatientDiagnosisPage.tsx`, `PatientListPage.tsx`).

```ts
// Before — vulnerable (src/config/db.ts)
this.URI = process.env.MONGO_URI ||
  'mongodb+srv://staticcodeanalyzer:8OMHzLFj7ieezIUv@cluster0.ubsop.mongodb.net/hospital_db';
```

**Fix:** All secrets and configuration values moved to environment variables loaded via `dotenv`. The application now throws a descriptive error at startup if critical variables are missing.

```ts
// After — secure
this.URI = process.env.MONGO_URI; // required — throws if absent
```

```ts
// AdminDashboard.tsx — after
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;
const response = await fetch(`${API_BASE_URL}/staff?role=PATIENT`);
```

**Relevant files:** [Hospital-Backend/.env.example](Hospital-Backend/.env.example) · [Hospital-Backend/dist/config/db.js](Hospital-Backend/dist/config/db.js)

---

### 6. Exposed Secrets in Version Control - `A05:2021` · Severity: High

**Original issue:** `.env` and `config.env` files containing `REACT_APP_API_BASE_URL`, `MONGO_URI`, and other secrets were committed to Git. They were not excluded in `.gitignore`, making all secrets available to anyone with repository access — including through git history.

**Fix:**
- **Secrets rotated:** All exposed database URIs and tokens were immediately invalidated.
- **`.gitignore` updated:** `.env` and `config.env` added to prevent future commits.
- **History cleaned:** Sensitive files removed from repository history using `git rm --cached` and BFG Repo-Cleaner.
- **`.env.example` provided:** A safe template with placeholder values committed instead.

```gitignore
# .gitignore
.env
config.env
```

---

### 7. CORS Misconfiguration - `A05:2021` · Severity: Medium

**Original issue:** The Express server used `app.use(cors())` with no restrictions, allowing requests from any origin. Authenticated users were at risk — malicious websites could make API calls on their behalf (booking appointments, modifying staff data, triggering payments).

**Fix:** CORS now reads allowed origins from `process.env.ALLOWED_ORIGINS` and uses a callback-based validator to reject unlisted origins with a `403`. Only trusted frontend origins can make credentialed requests. Allowed HTTP methods and headers are explicitly listed.

```ts
// After — secure
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173').split(',');
const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error('CORS policy: Not allowed by server'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
this.app.use(cors(corsOptions));
```

**Relevant files:** [Hospital-Backend/dist/app.js](Hospital-Backend/dist/app.js)

---

### 8. Vite Information Disclosure - `A05:2021` · CVE-2025-30208 · Severity: Medium

**Original issue:** Vite versions before 5.4.15 / 6.0.12 / 6.1.2 / 6.2.3 allowed attackers to bypass `@fs` filesystem restrictions using crafted query strings (`?raw??`, `?import&raw??`), reading arbitrary files from the project root — including `.env`, `package.json`, and config files. This was compounded by the `.env` file being committed to the repository.

**Fix:**
- Upgraded Vite to `^7.1.6` (patched version).
- Added `server.fs.deny` in `vite.config.ts` to explicitly block sensitive files even as a defence-in-depth measure.
- Removed `.env` from version control (see Vulnerability 6).

```ts
// vite.config.ts — after
export default defineConfig({
  plugins: [react()],
  server: {
    fs: {
      deny: ['.env', '.env.*', 'vite.config.ts', 'vite.config.js', 'package.json', 'package-lock.json']
    }
  }
});
```

---

## Vulnerabilities Not Fixed

| Item | Reason |
|------|--------|
| Two-Factor Authentication (2FA) | System is for internal organisational use only. Authorised staff and patients have managed credentials; OAuth combined with JWT is sufficient for the current scope. |
| Some flagged transitive dependencies | Major version upgrades introduced breaking API changes. Mitigated with lockfile pinning, validation checks, and active monitoring. Future iterations will refactor affected modules to allow safe upgrades. |

---

## OAuth 2.0 / OpenID Connect Implementation

**Grant type:** Authorization Code Grant with PKCE (RFC 7636)  
**Identity Provider:** Google OAuth 2.0 (direct integration — no third-party service like Auth0)  
**Implemented by:** Mahindarathna D.G.P.T.D (IT22076052)

### Why Google OAuth with PKCE?

- **Secure Login & Logout:** PKCE prevents authorization code interception - user credentials are never exposed to the application
- **User Convenience:** Healthcare professionals often already have Google accounts through their institution
- **Data Protection:** OAuth scopes limit access to only what the user explicitly grants (`openid profile email`)
- **Multi-Role Support:** System automatically assigns roles (ADMIN, DOCTOR, NURSE, PATIENT) based on email domain, defaulting to PATIENT

### Google Cloud Console Setup

1. Created a new project in Google Cloud Console named `HospitalVulnerabilities`
2. Enabled Google+ API and OAuth 2.0 services
3. Generated OAuth 2.0 credentials:
   - **Authorized JavaScript origins:** `http://localhost:5173`
   - **Authorized redirect URIs:** `http://localhost:3000/api/v1/auth/oauth/callback`
4. Stored `Client ID` and `Client Secret` in `.env` (never committed)

### Login Flow (Step-by-Step)

1. User clicks **"LOGIN WITH OAUTH"** on the login page
2. Backend generates a `code_verifier` (random 32-byte base64url) and `code_challenge` (SHA-256 hash), stores verifier in an `httpOnly` cookie (10-minute TTL)
3. User is redirected to Google's authorization endpoint with `response_type=code`, `scope=openid profile email`, and `code_challenge_method=S256`
4. User authenticates with Google and grants permissions
5. Google redirects to `/api/v1/auth/oauth/callback` with an authorization `code`
6. Backend reads the PKCE verifier from the `httpOnly` cookie and exchanges the code + verifier for an `access_token` at Google's token endpoint
7. Backend fetches the user profile from Google's UserInfo endpoint (`email`, `name`)
8. Backend upserts local `User` and `Staff` records in MongoDB (creates on first login, finds on subsequent logins)
9. Backend signs a JWT (24h expiry) containing user and staff details
10. PKCE cookie is cleared; user is redirected to frontend with token and role in the URL hash
11. Frontend reads the hash, stores the JWT, updates auth context, and routes the user to the appropriate role-based dashboard

### Logout Flow

The frontend clears the JWT from memory and the authentication context. Protected routes immediately redirect to the login page.

### Protected Routes

| Scenario | Behaviour |
|----------|-----------|
| Unauthenticated user visits a protected URL | Redirected to login with toast: *"Please login to access this page"* |
| Authenticated user visits a route for a different role | Redirected to `/unauthorized` with: *"You don't have permission to access this page"* |
| Both login methods (email/password + OAuth) | Populate the same auth context — protected route logic is method-agnostic |

### Key Files

| File | Purpose |
|------|---------|
| [Hospital-Backend/dist/config/oidc.js](Hospital-Backend/dist/config/oidc.js) | `generateCodeVerifier()`, `generateCodeChallenge()`, Google OAuth URL constants |
| [Hospital-Backend/dist/routes/oauth.routes.js](Hospital-Backend/dist/routes/oauth.routes.js) | `GET /oauth/login` (PKCE init + redirect) and `GET /oauth/callback` (token exchange + JWT issuance) |

### Required Environment Variables

```env
# Backend — .env
OIDC_CLIENT_ID=your-google-client-id
OIDC_CLIENT_SECRET=your-google-client-secret
OIDC_REDIRECT_URI=http://localhost:3000/api/v1/auth/oauth/callback
OIDC_SCOPE=openid profile email
OIDC_ISSUER=https://accounts.google.com
```

---

## Security Scanning Tools Used

| Tool | Type | Purpose |
|------|------|---------|
| [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) | White-box | Scans dependency tree for known vulnerabilities by severity (low → critical) |
| [Retire.js](https://github.com/RetireJS/retire.js) | White-box | Detects vulnerable JavaScript libraries in both frontend and backend dependencies |
| [npm-check](https://github.com/dylang/npm-check) | White-box | Identifies outdated, unused, and missing dependencies |
| [OWASP ZAP](https://www.zaproxy.org/) | Black-box | Active and passive scanning for runtime vulnerabilities |
| [Semgrep](https://semgrep.dev/) | White-box (SAST) | Static analysis with pre-built rules for detecting injection, secrets, and misconfigurations |

---

## Getting Started

### Prerequisites

- Node.js 18+
- MongoDB (local or Atlas)
- Google OAuth 2.0 credentials (Client ID + Secret from Google Cloud Console)

### Backend Setup

```bash
cd Hospital-Backend
copy .env.example .env        # Windows: fill in all values
npm install
npm run build
npm start
# Server runs on http://localhost:3000
```

### Frontend Setup

```bash
cd Hospital-Frontend
# Create .env with: REACT_APP_API_BASE_URL=http://localhost:3000/api/v1
npm install
npm run dev
# App runs on http://localhost:5173
```

---

## Individual Contributions

| Index | Name | Contributions |
|-------|------|--------------|
| IT22056320 | Senevirathna K.M.U.T | Vulnerability 1 - NoSQL Injection · Vulnerability 2 - SSRF in Axios |
| IT22076052 | Mahindarathna D.G.P.T.D | Vulnerability 3 - Vulnerable & Outdated Components · Vulnerability 4 - Input Validation & XSS · OAuth 2.0 Implementation |
| IT22060662 | Jameela M.J.F | Vulnerability 5 - Hard-coded Credentials · Vulnerability 6 - Exposed Secrets in VCS |
| IT22562524 | Ariyasena M.K.M.M | Vulnerability 7 - CORS Misconfiguration · Vulnerability 8 - Vite Information Disclosure |

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [CWE-943 - NoSQL Injection](https://cwe.mitre.org/data/definitions/943.html)
- [CWE-79 - Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-1104 - Vulnerable Components](https://cwe.mitre.org/data/definitions/1104.html)
- [CVE-2025-27152 - Axios SSRF](https://nvd.nist.gov/vuln/detail/CVE-2025-27152)
- [CVE-2025-30208 - Vite Information Disclosure](https://nvd.nist.gov/vuln/detail/CVE-2025-30208)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [Google Identity - OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [npm Security Advisory Database](https://www.npmjs.com/advisories)
- [Retire.js](https://github.com/RetireJS/retire.js)
