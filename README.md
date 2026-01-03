Codexia EDMS Lite

- Stack: React+TS+Vite, Go Gin, Python FastAPI+Redis RQ, Postgres, MinIO
- Services: frontend, api-service, worker-service, worker-rq, postgres, redis, minio, migrations

Run

- Copy infra/.env.example to infra/.env and adjust values if needed
- From infra directory run: docker compose up --build
- Frontend: http://localhost:5173
- API: http://localhost:8080
- Worker Service: http://localhost:8001
- MinIO Console: http://localhost:9001
- Postgres: localhost:5432

Accounts

- admin@codexia.local / Admin#123
- editor@codexia.local / Editor#123
- viewer@codexia.local / Viewer#123

Endpoints

- POST /api/auth/login
- GET /api/me
- GET /api/health
- Folder: POST /api/folders, GET /api/folders, PATCH /api/folders/{id}, DELETE /api/folders/{id}
- Documents: POST /api/documents, POST /api/documents/{doc}/versions, GET /api/documents, GET /api/documents/{doc}, GET /api/documents/{doc}/download, GET /api/documents/{doc}/preview, PATCH /api/documents/{doc}
- Metadata: PUT /api/documents/{doc}/metadata
- Tags: POST /api/documents/{doc}/tags, DELETE /api/documents/{doc}/tags/{tag_id}
- Share: POST /api/documents/{doc}/share, POST /api/documents/{doc}/unshare
- Delete/Restore: POST /api/documents/{doc}/delete, POST /api/documents/{doc}/restore
- Search: GET /api/search
- Audit: GET /api/audit

Flow

- Login to obtain JWT
- Upload a document; file stored in MinIO and version recorded
- Index job enqueued to Redis RQ via worker-service
- Worker downloads from MinIO, extracts text, updates document_index and job status
- Search uses Postgres FTS across title, extracted_text, tags, metadata
- Share permissions grant VIEW or EDIT to users or roles
- Soft delete moves document to DELETED, restore resets to ACTIVE

Troubleshooting

- Ensure Docker Desktop is running
- If migrations fail, recreate postgres_data volume and rerun
- MinIO credentials taken from infra/.env
