INSERT INTO users (email, password_hash, full_name, role)
VALUES
('admin@codexia.local', crypt('Admin#123', gen_salt('bf', 10)), 'Admin User', 'ADMIN'),
('editor@codexia.local', crypt('Editor#123', gen_salt('bf', 10)), 'Editor User', 'EDITOR'),
('viewer@codexia.local', crypt('Viewer#123', gen_salt('bf', 10)), 'Viewer User', 'VIEWER');
