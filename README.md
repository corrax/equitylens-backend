EquityLens e‑Sign Backend (AWS Lambda + API Gateway)

Overview
- API for creating e‑sign sessions, uploading original documents, assigning signers and placement, preparing signable PDFs, and returning signed documents.
- AWS SAM template with Node.js 18 Lambda functions, DynamoDB for session state, and S3 for file storage.
- PAdES B‑LT target: timestamped CMS signature with embedded validation artefacts (OCSP/CRL) for long‑term validation.

Architecture
- API Gateway (HTTP) → Lambda handlers in `src/handlers/sessions.js`
- DynamoDB table `EquityLensESignSessions` stores session metadata, signers, fields, states, and file keys
- S3 bucket `equitylens-esign-uploads` stores original, prepared, and signed PDFs per session
- Optional: a Python Lambda (pyHanko) for applying PAdES B‑LT; orchestrated by Node Lambda

Endpoints
- POST /sessions → create session, returns presigned S3 PUT URL for file
- PUT /sessions/{id}/fields → attach signers and signature field definitions
- POST /sessions/{id}/prepare → convert DOCX→PDF (if needed) and insert visible signature fields (AcroForm). Stubbed by default.
- POST /sessions/{id}/start → kick off signing (email invites). Stubbed by default.
- GET /sessions/{id} → get session state
- GET /sessions/{id}/download → presigned GET URL for the signed PDF (or prepared PDF)

Deploy (with AWS SAM)
1. Prereqs: AWS account, AWS CLI configured, AWS SAM CLI installed
2. Create S3 bucket and DynamoDB table via SAM:
   sam build
   sam deploy --guided
3. After deploy, note the API base URL output.

Implementation notes
- In `prepare` you should:
  1) If DOCX, convert to PDF (e.g., LibreOffice on Lambda layer or a conversion service)
  2) Inject AcroForm signature fields at each (page,x,y,w,h) for the appropriate signer (e.g., with pdf-lib or a lightweight PDF toolkit). This step does not apply cryptographic signatures yet.
  3) Store prepared PDF at `s3://bucket/{sessionId}/prepared.pdf`
- In `start`, send signer emails (e.g., Amazon SES) with unique signing links for a lightweight signing portal, or do server-side signing when users authenticate and approve.
- For PAdES B‑LT, call a Python Lambda running pyHanko to:
  - compute ByteRange and sign CMS/PKCS#7 with signer certificate
  - add RFC‑3161 timestamp
  - embed OCSP/CRL (+ chain) in DSS
  - attach audit JSON as Associated File and optionally append a certificate page

Local testing
- Handlers are stateless and use S3/DynamoDB; you can invoke via `sam local start-api` if you provide AWS credentials or use LocalStack (optional).

