CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role user_role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE folders (
  folder_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_id UUID REFERENCES folders(folder_id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  created_by UUID REFERENCES users(user_id) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE documents (
  doc_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  description TEXT,
  status doc_status NOT NULL DEFAULT 'ACTIVE',
  folder_id UUID REFERENCES folders(folder_id) ON DELETE SET NULL,
  owner_id UUID REFERENCES users(user_id) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE document_versions (
  ver_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_id UUID REFERENCES documents(doc_id) ON DELETE CASCADE NOT NULL,
  version_no INT NOT NULL,
  original_filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  bucket TEXT NOT NULL,
  key TEXT NOT NULL,
  checksum_sha256 TEXT NOT NULL,
  uploaded_by UUID REFERENCES users(user_id) NOT NULL,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE document_metadata (
  doc_id UUID PRIMARY KEY REFERENCES documents(doc_id) ON DELETE CASCADE,
  meta_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by UUID REFERENCES users(user_id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tags (
  tag_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE document_tags (
  doc_id UUID REFERENCES documents(doc_id) ON DELETE CASCADE,
  tag_id UUID REFERENCES tags(tag_id) ON DELETE CASCADE,
  PRIMARY KEY (doc_id, tag_id)
);

CREATE TABLE document_permissions (
  perm_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_id UUID REFERENCES documents(doc_id) ON DELETE CASCADE NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  perm perm_level NOT NULL,
  created_by UUID REFERENCES users(user_id) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_id UUID REFERENCES documents(doc_id) ON DELETE SET NULL,
  user_id UUID REFERENCES users(user_id) NOT NULL,
  action audit_action NOT NULL,
  detail JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip_addr TEXT
);

CREATE TABLE processing_jobs (
  job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_id UUID REFERENCES documents(doc_id) ON DELETE CASCADE,
  ver_id UUID REFERENCES document_versions(ver_id) ON DELETE CASCADE,
  job_type job_type NOT NULL,
  status job_status NOT NULL,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  error_message TEXT
);

CREATE TABLE document_index (
  doc_id UUID PRIMARY KEY REFERENCES documents(doc_id) ON DELETE CASCADE,
  ver_id UUID REFERENCES document_versions(ver_id) ON DELETE CASCADE,
  extracted_text TEXT,
  search_vector tsvector,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
