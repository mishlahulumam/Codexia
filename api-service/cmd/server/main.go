package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB        *pgxpool.Pool
	Minio     *minio.Client
	Bucket    string
	JWTSecret string
	MaxUpload int64
}

type User struct {
	UserID   string
	Email    string
	FullName string
	Role     string
	Password string
}

func main() {
	dbURL := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	corsOrigin := os.Getenv("CORS_ORIGIN")
	maxUploadStr := os.Getenv("MAX_UPLOAD_SIZE")
	minioEndpoint := os.Getenv("MINIO_ENDPOINT")
	minioAccess := os.Getenv("MINIO_ACCESS_KEY")
	minioSecret := os.Getenv("MINIO_SECRET_KEY")
	minioBucket := os.Getenv("MINIO_BUCKET")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		panic(err)
	}
	minioClient, err := minio.New(strings.TrimPrefix(minioEndpoint, "http://"), &minio.Options{
		Creds:  credentials.NewStaticV4(minioAccess, minioSecret, ""),
		Secure: false,
	})
	if err != nil {
		panic(err)
	}
	exists, err := minioClient.BucketExists(ctx, minioBucket)
	if err != nil {
		panic(err)
	}
	if !exists {
		err = minioClient.MakeBucket(ctx, minioBucket, minio.MakeBucketOptions{})
		if err != nil {
			panic(err)
		}
	}
	maxUpload, _ := strconv.ParseInt(maxUploadStr, 10, 64)
	app := &App{
		DB:        pool,
		Minio:     minioClient,
		Bucket:    minioBucket,
		JWTSecret: jwtSecret,
		MaxUpload: maxUpload,
	}
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{corsOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	r.GET("/api/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	r.POST("/api/auth/login", app.login)
	auth := r.Group("/api")
	auth.Use(app.authMiddleware())
	auth.GET("/me", app.me)
	auth.POST("/folders", app.createFolder)
	auth.GET("/folders", app.listFolders)
	auth.PATCH("/folders/:id", app.updateFolder)
	auth.DELETE("/folders/:id", app.deleteFolder)
	auth.POST("/documents", app.createDocument)
	auth.POST("/documents/:id/versions", app.addVersion)
	auth.GET("/documents", app.listDocuments)
	auth.GET("/documents/:id", app.getDocument)
	auth.GET("/documents/:id/download", app.downloadDocument)
	auth.GET("/documents/:id/preview", app.previewDocument)
	auth.PATCH("/documents/:id", app.updateDocument)
	auth.PUT("/documents/:id/metadata", app.putMetadata)
	auth.POST("/documents/:id/tags", app.addTag)
	auth.DELETE("/documents/:id/tags/:tag_id", app.removeTag)
	auth.POST("/documents/:id/share", app.shareDoc)
	auth.POST("/documents/:id/unshare", app.unshareDoc)
	auth.POST("/documents/:id/delete", app.softDelete)
	auth.POST("/documents/:id/restore", app.restore)
	auth.GET("/search", app.search)
	auth.GET("/audit", app.audit)
	auth.GET("/admin/users", app.adminListUsers)
	auth.POST("/admin/users", app.adminCreateUser)
	auth.POST("/admin/users/:id/reset_password", app.adminResetPassword)
	r.Run(":8080")
}

func (a *App) login(c *gin.Context) {
	type Req struct{ Email, Password string }
	var req Req
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	var id, email, full, role, hash string
	err := a.DB.QueryRow(ctx, "SELECT user_id,email,full_name,role,password_hash FROM users WHERE email=$1", req.Email).Scan(&id, &email, &full, &role, &hash)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(401, gin.H{"error": "invalid_credentials"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": id,
		"email":   email,
		"role":    role,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	s, _ := token.SignedString([]byte(a.JWTSecret))
	auditInsert(a.DB, ctx, nil, id, "LOGIN", `{"email":"`+email+`"}`, c.ClientIP())
	c.JSON(200, gin.H{"token": s})
}

func (a *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) { return []byte(a.JWTSecret), nil })
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("user_id", claims["user_id"])
		c.Set("email", claims["email"])
		c.Set("role", claims["role"])
		c.Next()
	}
}

func (a *App) me(c *gin.Context) {
	c.JSON(200, gin.H{"user_id": c.GetString("user_id"), "email": c.GetString("email"), "role": c.GetString("role")})
}

func (a *App) hasView(ctx context.Context, userID, role, docID string) bool {
	if role == "ADMIN" {
		return true
	}
	var owner string
	_ = a.DB.QueryRow(ctx, "SELECT owner_id FROM documents WHERE doc_id=$1", docID).Scan(&owner)
	if owner == userID {
		return true
	}
	var ok int
	_ = a.DB.QueryRow(ctx, "SELECT 1 FROM document_permissions WHERE doc_id=$1 AND ((subject_type='USER' AND subject_id=$2) OR (subject_type='ROLE' AND subject_id=$3)) AND (perm='VIEW' OR perm='EDIT') LIMIT 1", docID, userID, role).Scan(&ok)
	return ok == 1
}

func (a *App) hasEdit(ctx context.Context, userID, role, docID string) bool {
	if role == "ADMIN" {
		return true
	}
	var owner string
	_ = a.DB.QueryRow(ctx, "SELECT owner_id FROM documents WHERE doc_id=$1", docID).Scan(&owner)
	if owner == userID {
		return true
	}
	var ok int
	_ = a.DB.QueryRow(ctx, "SELECT 1 FROM document_permissions WHERE doc_id=$1 AND ((subject_type='USER' AND subject_id=$2) OR (subject_type='ROLE' AND subject_id=$3)) AND perm='EDIT' LIMIT 1", docID, userID, role).Scan(&ok)
	return ok == 1
}
func (a *App) createFolder(c *gin.Context) {
	type Req struct {
		ParentID *string `json:"parent_id"`
		Name     string  `json:"name"`
	}
	var req Req
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	var id string
	err := a.DB.QueryRow(ctx, "INSERT INTO folders(parent_id,name,created_by) VALUES($1,$2,$3) RETURNING folder_id", req.ParentID, req.Name, c.GetString("user_id")).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	auditInsert(a.DB, ctx, nil, c.GetString("user_id"), "MOVE_FOLDER", `{"name":"`+req.Name+`"}`, c.ClientIP())
	c.JSON(200, gin.H{"folder_id": id})
}

func (a *App) listFolders(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := a.DB.Query(ctx, "SELECT folder_id,parent_id,name FROM folders ORDER BY name")
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	defer rows.Close()
	type F struct{ FolderID, ParentID, Name string }
	var res []F
	for rows.Next() {
		var f F
		var pid *string
		if err := rows.Scan(&f.FolderID, &pid, &f.Name); err == nil {
			if pid != nil {
				f.ParentID = *pid
			}
			res = append(res, f)
		}
	}
	c.JSON(200, res)
}

func (a *App) updateFolder(c *gin.Context) {
	id := c.Param("id")
	type Req struct {
		Name     *string `json:"name"`
		ParentID *string `json:"parent_id"`
	}
	var req Req
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	_, err := a.DB.Exec(ctx, "UPDATE folders SET name=COALESCE($1,name), parent_id=$2 WHERE folder_id=$3", req.Name, req.ParentID, id)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) deleteFolder(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	var cnt int
	a.DB.QueryRow(ctx, "SELECT COUNT(*) FROM folders WHERE parent_id=$1", id).Scan(&cnt)
	if cnt > 0 {
		c.JSON(400, gin.H{"error": "not_empty"})
		return
	}
	a.DB.QueryRow(ctx, "SELECT COUNT(*) FROM documents WHERE folder_id=$1", id).Scan(&cnt)
	if cnt > 0 {
		c.JSON(400, gin.H{"error": "not_empty"})
		return
	}
	_, err := a.DB.Exec(ctx, "DELETE FROM folders WHERE folder_id=$1", id)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) createDocument(c *gin.Context) {
	if c.GetString("role") == "VIEWER" {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	if c.Request.ContentLength > a.MaxUpload && a.MaxUpload > 0 {
		c.JSON(413, gin.H{"error": "file_too_large"})
		return
	}
	title := c.PostForm("title")
	if title == "" {
		c.JSON(400, gin.H{"error": "title_required"})
		return
	}
	description := c.PostForm("description")
	folderID := c.PostForm("folder_id")
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "file_required"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(500, gin.H{"error": "file_open_error"})
		return
	}
	defer src.Close()
	ctx := c.Request.Context()
	var docID string
	err = a.DB.QueryRow(ctx, "INSERT INTO documents(title,description,folder_id,owner_id) VALUES($1,$2, NULLIF($3,'')::uuid, $4) RETURNING doc_id", title, description, folderID, c.GetString("user_id")).Scan(&docID)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	verNo := 1
	key := docID + "/" + "v1" + "/" + file.Filename
	uploadInfo, err := a.Minio.PutObject(ctx, a.Bucket, key, src, file.Size, minio.PutObjectOptions{ContentType: file.Header.Get("Content-Type")})
	if err != nil {
		c.JSON(500, gin.H{"error": "upload_error"})
		return
	}
	h := sha256.New()
	src2, _ := file.Open()
	defer src2.Close()
	_, _ = ioCopy(h, src2)
	checksum := hex.EncodeToString(h.Sum(nil))
	var verID string
	err = a.DB.QueryRow(ctx, "INSERT INTO document_versions(doc_id,version_no,original_filename,mime_type,size_bytes,bucket,key,checksum_sha256,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING ver_id",
		docID, verNo, file.Filename, file.Header.Get("Content-Type"), uploadInfo.Size, a.Bucket, key, checksum, c.GetString("user_id")).Scan(&verID)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	_, _ = a.DB.Exec(ctx, "INSERT INTO document_metadata(doc_id, meta_json, updated_by) VALUES($1, '{}'::jsonb, $2) ON CONFLICT (doc_id) DO NOTHING", docID, c.GetString("user_id"))
	auditInsert(a.DB, ctx, &docID, c.GetString("user_id"), "UPLOAD", `{"filename":"`+file.Filename+`"}`, c.ClientIP())
	jobID := enqueueJob(a.DB, ctx, docID, verID)
	http.Post(os.Getenv("WORKER_INDEX_URL"), "application/json", strings.NewReader(`{"job_id":"`+jobID+`","doc_id":"`+docID+`","ver_id":"`+verID+`","bucket":"`+a.Bucket+`","key":"`+key+`","mime_type":"`+file.Header.Get("Content-Type")+`"}`))
	c.JSON(200, gin.H{"doc_id": docID, "ver_id": verID})
}

func (a *App) addVersion(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "file_required"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(500, gin.H{"error": "file_open_error"})
		return
	}
	defer src.Close()
	ctx := c.Request.Context()
	var verNo int
	a.DB.QueryRow(ctx, "SELECT COALESCE(MAX(version_no),0)+1 FROM document_versions WHERE doc_id=$1", id).Scan(&verNo)
	key := id + "/v" + strconv.Itoa(verNo) + "/" + file.Filename
	uploadInfo, err := a.Minio.PutObject(ctx, a.Bucket, key, src, file.Size, minio.PutObjectOptions{ContentType: file.Header.Get("Content-Type")})
	if err != nil {
		c.JSON(500, gin.H{"error": "upload_error"})
		return
	}
	h := sha256.New()
	src2, _ := file.Open()
	defer src2.Close()
	_, _ = ioCopy(h, src2)
	checksum := hex.EncodeToString(h.Sum(nil))
	var verID string
	err = a.DB.QueryRow(ctx, "INSERT INTO document_versions(doc_id,version_no,original_filename,mime_type,size_bytes,bucket,key,checksum_sha256,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING ver_id",
		id, verNo, file.Filename, file.Header.Get("Content-Type"), uploadInfo.Size, a.Bucket, key, checksum, c.GetString("user_id")).Scan(&verID)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "NEW_VERSION", `{"filename":"`+file.Filename+`"}`, c.ClientIP())
	jobID := enqueueJob(a.DB, ctx, id, verID)
	http.Post(os.Getenv("WORKER_INDEX_URL"), "application/json", strings.NewReader(`{"job_id":"`+jobID+`","doc_id":"`+id+`","ver_id":"`+verID+`","bucket":"`+a.Bucket+`","key":"`+key+`","mime_type":"`+file.Header.Get("Content-Type")+`"}`))
	c.JSON(200, gin.H{"ver_id": verID})
}

func ioCopy(h interface{ Write([]byte) (int, error) }, r interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			return total, err
		}
	}
}

func enqueueJob(db *pgxpool.Pool, ctx context.Context, docID, verID string) string {
	var jobID string
	db.QueryRow(ctx, "INSERT INTO processing_jobs(doc_id,ver_id,job_type,status,started_at) VALUES($1,$2,'INDEX_TEXT','QUEUED',now()) RETURNING job_id", docID, verID).Scan(&jobID)
	return jobID
}

func auditInsert(db *pgxpool.Pool, ctx context.Context, docID *string, userID, action, detail, ip string) {
	db.Exec(ctx, "INSERT INTO audit_logs(doc_id,user_id,action,detail,ip_addr) VALUES($1,$2,$3,$4,$5)", docID, userID, action, detail, ip)
}

func (a *App) listDocuments(c *gin.Context) {
	ctx := c.Request.Context()
	fid := c.Query("folder_id")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize
	role := c.GetString("role")
	userID := c.GetString("user_id")
	query := "SELECT doc_id,title,description,status,folder_id,owner_id,created_at,updated_at FROM documents WHERE 1=1"
	var args []interface{}
	i := 1
	if fid != "" {
		query += " AND folder_id=$" + strconv.Itoa(i)
		args = append(args, fid)
		i++
	}
	if status != "" {
		query += " AND status=$" + strconv.Itoa(i)
		args = append(args, status)
		i++
	}
	if role != "ADMIN" {
		query += " AND (owner_id=$" + strconv.Itoa(i) + " OR EXISTS (SELECT 1 FROM document_permissions p WHERE p.doc_id=documents.doc_id AND ((p.subject_type='USER' AND p.subject_id=$" + strconv.Itoa(i) + ") OR (p.subject_type='ROLE' AND p.subject_id=$" + strconv.Itoa(i+1) + "))))"
		args = append(args, userID, role)
		i += 2
	}
	query += " ORDER BY updated_at DESC LIMIT $" + strconv.Itoa(i) + " OFFSET $" + strconv.Itoa(i+1)
	args = append(args, pageSize, offset)
	rows, err := a.DB.Query(ctx, query, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	defer rows.Close()
	type D struct{ DocID, Title, Description, Status, FolderID, OwnerID string }
	var res []D
	for rows.Next() {
		var d D
		var fidPtr *string
		if err := rows.Scan(&d.DocID, &d.Title, &d.Description, &d.Status, &fidPtr, &d.OwnerID, new(time.Time), new(time.Time)); err == nil {
			if fidPtr != nil {
				d.FolderID = *fidPtr
			}
			res = append(res, d)
		}
	}
	c.JSON(200, res)
}

func (a *App) getDocument(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	if !a.hasView(ctx, c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	type Doc struct {
		DocID       string
		Title       string
		Description string
		Status      string
		FolderID    string
	}
	var d Doc
	var fid *string
	err := a.DB.QueryRow(ctx, "SELECT doc_id,title,description,status,folder_id FROM documents WHERE doc_id=$1", id).Scan(&d.DocID, &d.Title, &d.Description, &d.Status, &fid)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	if fid != nil {
		d.FolderID = *fid
	}
	var verID, filename, mime string
	_ = a.DB.QueryRow(ctx, "SELECT ver_id,original_filename,mime_type FROM document_versions WHERE doc_id=$1 ORDER BY version_no DESC LIMIT 1", id).Scan(&verID, &filename, &mime)
	var meta string
	_ = a.DB.QueryRow(ctx, "SELECT meta_json::text FROM document_metadata WHERE doc_id=$1", id).Scan(&meta)
	rows, _ := a.DB.Query(ctx, "SELECT t.tag_id,t.name FROM document_tags dt JOIN tags t ON dt.tag_id=t.tag_id WHERE dt.doc_id=$1", id)
	defer rows.Close()
	var tags []map[string]string
	for rows.Next() {
		var tid, name string
		rows.Scan(&tid, &name)
		tags = append(tags, map[string]string{"tag_id": tid, "name": name})
	}
	var jobID, jobStatus string
	_ = a.DB.QueryRow(ctx, "SELECT job_id,status FROM processing_jobs WHERE doc_id=$1 ORDER BY started_at DESC LIMIT 1", id).Scan(&jobID, &jobStatus)
	c.JSON(200, gin.H{"doc": d, "latest_version": gin.H{"ver_id": verID, "filename": filename, "mime_type": mime}, "metadata": meta, "tags": tags, "latest_job": gin.H{"job_id": jobID, "status": jobStatus}})
}

func (a *App) updateDocument(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	type Req struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		FolderID    *string `json:"folder_id"`
	}
	var req Req
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	_, err := a.DB.Exec(ctx, "UPDATE documents SET title=COALESCE($1,title), description=COALESCE($2,description), folder_id=$3, updated_at=now() WHERE doc_id=$4", req.Title, req.Description, req.FolderID, id)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "UPDATE_META", "{}", c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) putMetadata(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	_, err := a.DB.Exec(ctx, "INSERT INTO document_metadata(doc_id,meta_json,updated_by,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT (doc_id) DO UPDATE SET meta_json=$2, updated_by=$3, updated_at=now()", id, body, c.GetString("user_id"))
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "UPDATE_META", "{}", c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) addTag(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	var tagID string
	_ = a.DB.QueryRow(ctx, "INSERT INTO tags(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING tag_id", body.Name).Scan(&tagID)
	if tagID == "" {
		_ = a.DB.QueryRow(ctx, "SELECT tag_id FROM tags WHERE name=$1", body.Name).Scan(&tagID)
	}
	_, _ = a.DB.Exec(ctx, "INSERT INTO document_tags(doc_id,tag_id) VALUES($1,$2) ON CONFLICT DO NOTHING", id, tagID)
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "ADD_TAG", `{"name":"`+body.Name+`"}`, c.ClientIP())
	c.JSON(200, gin.H{"tag_id": tagID})
}

func (a *App) removeTag(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	tagID := c.Param("tag_id")
	ctx := c.Request.Context()
	_, _ = a.DB.Exec(ctx, "DELETE FROM document_tags WHERE doc_id=$1 AND tag_id=$2", id, tagID)
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "REMOVE_TAG", `{"tag_id":"`+tagID+`"}`, c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) shareDoc(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	var body struct{ SubjectType, SubjectID, Perm string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	var owner string
	_ = a.DB.QueryRow(ctx, "SELECT owner_id FROM documents WHERE doc_id=$1", id).Scan(&owner)
	if owner != c.GetString("user_id") && c.GetString("role") != "ADMIN" {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	_, _ = a.DB.Exec(ctx, "INSERT INTO document_permissions(doc_id,subject_type,subject_id,perm,created_by) VALUES($1,$2,$3,$4,$5)", id, body.SubjectType, body.SubjectID, body.Perm, c.GetString("user_id"))
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "SHARE", "{}", c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) unshareDoc(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	var body struct{ SubjectType, SubjectID string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	ctx := c.Request.Context()
	_, _ = a.DB.Exec(ctx, "DELETE FROM document_permissions WHERE doc_id=$1 AND subject_type=$2 AND subject_id=$3", id, body.SubjectType, body.SubjectID)
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "UNSHARE", "{}", c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) softDelete(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	ctx := c.Request.Context()
	_, _ = a.DB.Exec(ctx, "UPDATE documents SET status='DELETED', deleted_at=now() WHERE doc_id=$1", id)
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "DELETE", "{}", c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) restore(c *gin.Context) {
	id := c.Param("id")
	if !a.hasEdit(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	ctx := c.Request.Context()
	_, _ = a.DB.Exec(ctx, "UPDATE documents SET status='ACTIVE', deleted_at=NULL WHERE doc_id=$1", id)
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "RESTORE", "{}", c.ClientIP())
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) downloadDocument(c *gin.Context) {
	id := c.Param("id")
	if !a.hasView(c.Request.Context(), c.GetString("user_id"), c.GetString("role"), id) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	verID := c.Query("ver_id")
	ctx := c.Request.Context()
	if verID == "" {
		_ = a.DB.QueryRow(ctx, "SELECT ver_id FROM document_versions WHERE doc_id=$1 ORDER BY version_no DESC LIMIT 1", id).Scan(&verID)
	}
	var key, filename string
	_ = a.DB.QueryRow(ctx, "SELECT key,original_filename FROM document_versions WHERE ver_id=$1", verID).Scan(&key, &filename)
	url, err := a.Minio.PresignedGetObject(ctx, a.Bucket, key, time.Minute*10, nil)
	if err != nil {
		c.JSON(500, gin.H{"error": "presign_error"})
		return
	}
	auditInsert(a.DB, ctx, &id, c.GetString("user_id"), "DOWNLOAD", `{"ver_id":"`+verID+`"}`, c.ClientIP())
	c.JSON(200, gin.H{"url": url.String(), "filename": filename})
}

func (a *App) previewDocument(c *gin.Context) {
	a.downloadDocument(c)
}

func (a *App) search(c *gin.Context) {
	ctx := c.Request.Context()
	q := c.Query("q")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize
	role := c.GetString("role")
	userID := c.GetString("user_id")
	query := "SELECT d.doc_id, d.title, ts_rank(di.search_vector, plainto_tsquery($1)) AS score, ts_headline('english', COALESCE(di.extracted_text,''), plainto_tsquery($1)) AS snippet FROM document_index di JOIN documents d ON d.doc_id=di.doc_id WHERE di.search_vector @@ plainto_tsquery($1)"
	var args []interface{}
	args = append(args, q)
	if role != "ADMIN" {
		query += " AND (d.owner_id=$2 OR EXISTS (SELECT 1 FROM document_permissions p WHERE p.doc_id=d.doc_id AND ((p.subject_type='USER' AND p.subject_id=$2) OR (p.subject_type='ROLE' AND p.subject_id=$3))))"
		args = append(args, userID, role)
	} else {
		// placeholders alignment
		args = append(args, pageSize, offset)
	}
	if role == "ADMIN" {
		rows, err := a.DB.Query(ctx, query+" ORDER BY score DESC LIMIT $2 OFFSET $3", args...)
		if err != nil {
			c.JSON(500, gin.H{"error": "db_error"})
			return
		}
		defer rows.Close()
		type R struct {
			DocID, Title, Snippet string
			Score                 float32
		}
		var res []R
		for rows.Next() {
			var r R
			rows.Scan(&r.DocID, &r.Title, &r.Score, &r.Snippet)
			res = append(res, r)
		}
		c.JSON(200, res)
		return
	}
	rows, err := a.DB.Query(ctx, query+" ORDER BY score DESC LIMIT $4 OFFSET $5", q, userID, role, pageSize, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	defer rows.Close()
	type R struct {
		DocID, Title, Snippet string
		Score                 float32
	}
	var res []R
	for rows.Next() {
		var r R
		rows.Scan(&r.DocID, &r.Title, &r.Score, &r.Snippet)
		res = append(res, r)
	}
	c.JSON(200, res)
}

func (a *App) audit(c *gin.Context) {
	ctx := c.Request.Context()
	docID := c.Query("doc_id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize
	query := "SELECT audit_id, user_id, action, detail::text, created_at, ip_addr FROM audit_logs WHERE 1=1"
	var args []interface{}
	i := 1
	role := c.GetString("role")
	userID := c.GetString("user_id")
	if docID != "" {
		query += " AND doc_id=$" + strconv.Itoa(i)
		args = append(args, docID)
		i++
	}
	if role != "ADMIN" {
		query += " AND (user_id=$" + strconv.Itoa(i) + " OR EXISTS (SELECT 1 FROM documents d WHERE d.doc_id=audit_logs.doc_id AND d.owner_id=$" + strconv.Itoa(i) + "))"
		args = append(args, userID)
		i++
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(i) + " OFFSET $" + strconv.Itoa(i+1)
	args = append(args, pageSize, offset)
	rows, err := a.DB.Query(ctx, query, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	defer rows.Close()
	type A struct {
		AuditID, UserID, Action, Detail, IP string
		CreatedAt                           time.Time
	}
	var res []A
	for rows.Next() {
		var aRec A
		rows.Scan(&aRec.AuditID, &aRec.UserID, &aRec.Action, &aRec.Detail, &aRec.CreatedAt, &aRec.IP)
		res = append(res, aRec)
	}
	c.JSON(200, res)
}

func (a *App) adminListUsers(c *gin.Context) {
	if c.GetString("role") != "ADMIN" {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	ctx := c.Request.Context()
	rows, err := a.DB.Query(ctx, "SELECT user_id,email,full_name,role,created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	defer rows.Close()
	type U struct {
		UserID, Email, FullName, Role string
		CreatedAt                     time.Time
	}
	var res []U
	for rows.Next() {
		var u U
		rows.Scan(&u.UserID, &u.Email, &u.FullName, &u.Role, &u.CreatedAt)
		res = append(res, u)
	}
	c.JSON(200, res)
}

func (a *App) adminCreateUser(c *gin.Context) {
	if c.GetString("role") != "ADMIN" {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	type Req struct{ Email, FullName, Role, Password string }
	var req Req
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.FullName == "" || req.Role == "" || req.Password == "" {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	ctx := c.Request.Context()
	var id string
	err := a.DB.QueryRow(ctx, "INSERT INTO users(email,password_hash,full_name,role) VALUES($1,$2,$3,$4) RETURNING user_id", req.Email, string(hash), req.FullName, req.Role).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	c.JSON(200, gin.H{"user_id": id})
}

func (a *App) adminResetPassword(c *gin.Context) {
	if c.GetString("role") != "ADMIN" {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	id := c.Param("id")
	var body struct{ Password string }
	if err := c.ShouldBindJSON(&body); err != nil || body.Password == "" {
		c.JSON(400, gin.H{"error": "bad_request"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	ctx := c.Request.Context()
	_, err := a.DB.Exec(ctx, "UPDATE users SET password_hash=$1 WHERE user_id=$2", string(hash), id)
	if err != nil {
		c.JSON(500, gin.H{"error": "db_error"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
