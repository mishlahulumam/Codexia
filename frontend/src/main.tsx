import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080'
const api = axios.create({ baseURL: API_BASE })

function useAuth() {
  const token = localStorage.getItem('token')
  return { token }
}

function setToken(t: string) {
  localStorage.setItem('token', t)
  api.defaults.headers.common['Authorization'] = `Bearer ${t}`
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
        <Route path="/documents" element={<RequireAuth><Documents /></RequireAuth>} />
        <Route path="/documents/new" element={<RequireAuth><NewDocument /></RequireAuth>} />
        <Route path="/documents/:id" element={<RequireAuth><DocumentDetail /></RequireAuth>} />
        <Route path="/search" element={<RequireAuth><Search /></RequireAuth>} />
        <Route path="/admin/users" element={<RequireAuth><AdminUsers /></RequireAuth>} />
      </Routes>
    </BrowserRouter>
  )
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { token } = useAuth()
  if (!token) return <Navigate to="/login" replace />
  api.defaults.headers.common['Authorization'] = `Bearer ${token}`
  return <>{children}</>
}

function Login() {
  const [email, setEmail] = React.useState('admin@codexia.local')
  const [password, setPassword] = React.useState('Admin#123')
  const [error, setError] = React.useState('')
  const nav = useNavigate()
  return (
    <div style={{ padding: 24 }}>
      <h1>Codexia Login</h1>
      <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button onClick={async () => {
        try {
          const res = await api.post('/api/auth/login', { email, password })
          setToken(res.data.token)
          nav('/')
        } catch {
          setError('Invalid credentials')
        }
      }}>Login</button>
      <div>{error}</div>
    </div>
  )
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex' }}>
      <nav style={{ width: 200, padding: 16, borderRight: '1px solid #ddd' }}>
        <div><Link to="/">Dashboard</Link></div>
        <div><Link to="/documents">Documents</Link></div>
        <div><Link to="/documents/new">Upload</Link></div>
        <div><Link to="/search">Search</Link></div>
        <div><Link to="/admin/users">Users</Link></div>
      </nav>
      <main style={{ flex: 1, padding: 16 }}>{children}</main>
    </div>
  )
}

function Dashboard() {
  const [me, setMe] = React.useState<any>(null)
  const [audit, setAudit] = React.useState<any[]>([])
  React.useEffect(() => {
    api.get('/api/me').then(r => setMe(r.data))
    api.get('/api/audit?page=1&page_size=10').then(r => setAudit(r.data))
  }, [])
  return (
    <Layout>
      <h2>Welcome</h2>
      <div>{me && `${me.email} (${me.role})`}</div>
      <h3>Recent Audit</h3>
      <ul>
        {audit.map(a => <li key={a.audit_id}>{a.action} {new Date(a.created_at).toLocaleString()}</li>)}
      </ul>
    </Layout>
  )
}

function Documents() {
  const [docs, setDocs] = React.useState<any[]>([])
  React.useEffect(() => {
    api.get('/api/documents?page=1&page_size=50').then(r => setDocs(r.data))
  }, [])
  return (
    <Layout>
      <h2>Documents</h2>
      <table>
        <thead><tr><th>Title</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {docs.map(d => <tr key={d.doc_id}>
            <td><Link to={`/documents/${d.doc_id}`}>{d.title}</Link></td>
            <td>{d.status}</td>
            <td></td>
          </tr>)}
        </tbody>
      </table>
    </Layout>
  )
}

function NewDocument() {
  const [title, setTitle] = React.useState('')
  const [description, setDescription] = React.useState('')
  const [file, setFile] = React.useState<File | null>(null)
  const nav = useNavigate()
  return (
    <Layout>
      <h2>Upload</h2>
      <input placeholder="Title" value={title} onChange={e => setTitle(e.target.value)} />
      <input placeholder="Description" value={description} onChange={e => setDescription(e.target.value)} />
      <input type="file" onChange={e => setFile(e.target.files?.[0] || null)} />
      <button onClick={async () => {
        const fd = new FormData()
        fd.append('title', title)
        fd.append('description', description)
        if (file) fd.append('file', file)
        const res = await api.post('/api/documents', fd)
        nav(`/documents/${res.data.doc_id}`)
      }}>Submit</button>
    </Layout>
  )
}

function DocumentDetail() {
  const id = window.location.pathname.split('/').pop()
  const [doc, setDoc] = React.useState<any>(null)
  const [tags, setTags] = React.useState<any[]>([])
  const [meta, setMeta] = React.useState<any>({})
  React.useEffect(() => {
    api.get(`/api/documents/${id}`).then(r => {
      setDoc(r.data)
      setTags(r.data.tags || [])
      setMeta(r.data.metadata ? JSON.parse(r.data.metadata) : {}
      )
    })
  }, [id])
  return (
    <Layout>
      <h2>{doc?.doc?.title}</h2>
      {doc?.latest_version && <a href="#" onClick={async (e) => {
        e.preventDefault()
        const r = await api.get(`/api/documents/${id}/preview`)
        window.open(r.data.url, '_blank')
      }}>Preview</a>}
      <h3>Tags</h3>
      <ul>{tags.map(t => <li key={t.tag_id}>{t.name}</li>)}</ul>
      <h3>Metadata</h3>
      <pre>{JSON.stringify(meta, null, 2)}</pre>
    </Layout>
  )
}

function Search() {
  const [q, setQ] = React.useState('')
  const [res, setRes] = React.useState<any[]>([])
  return (
    <Layout>
      <h2>Search</h2>
      <input value={q} onChange={e => setQ(e.target.value)} placeholder="Query" />
      <button onClick={async () => {
        const r = await api.get(`/api/search?q=${encodeURIComponent(q)}&page=1&page_size=50`)
        setRes(r.data)
      }}>Search</button>
      <ul>{res.map(r => <li key={r.doc_id}><Link to={`/documents/${r.doc_id}`}>{r.title}</Link></li>)}</ul>
    </Layout>
  )
}

function AdminUsers() {
  const [users, setUsers] = React.useState<any[]>([])
  const [email, setEmail] = React.useState('')
  const [fullName, setFullName] = React.useState('')
  const [role, setRole] = React.useState('VIEWER')
  const [password, setPassword] = React.useState('')
  React.useEffect(() => {
    api.get('/api/admin/users').then(r => setUsers(r.data))
  }, [])
  return (
    <Layout>
      <h2>Users</h2>
      <table>
        <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Actions</th></tr></thead>
        <tbody>
          {users.map(u => <tr key={u.user_id}>
            <td>{u.email}</td><td>{u.full_name}</td><td>{u.role}</td>
            <td><button onClick={async ()=> {
              const newPass = prompt('New password') || ''
              if (!newPass) return
              await api.post(`/api/admin/users/${u.user_id}/reset_password`, { password: newPass })
              alert('Password reset')
            }}>Reset Password</button></td>
          </tr>)}
        </tbody>
      </table>
      <h3>Create User</h3>
      <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input placeholder="Full Name" value={fullName} onChange={e => setFullName(e.target.value)} />
      <select value={role} onChange={e => setRole(e.target.value)}>
        <option>ADMIN</option>
        <option>EDITOR</option>
        <option>VIEWER</option>
      </select>
      <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button onClick={async ()=> {
        await api.post('/api/admin/users', { email, full_name: fullName, role, password })
        const r = await api.get('/api/admin/users')
        setUsers(r.data)
        setEmail(''); setFullName(''); setPassword('')
      }}>Create</button>
    </Layout>
  )
}

const root = createRoot(document.getElementById('root')!)
root.render(<App />)
