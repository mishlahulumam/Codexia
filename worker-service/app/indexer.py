import os
import io
from datetime import datetime
from minio import Minio
import psycopg2
from pdfminer.high_level import extract_text

def run(job_id: str, doc_id: str, ver_id: str, bucket: str, key: str, mime_type: str):
    db_url = os.environ.get("DB_URL")
    m = Minio(os.environ.get("MINIO_ENDPOINT", "minio:9000").replace("http://", ""), access_key=os.environ.get("MINIO_ACCESS_KEY"), secret_key=os.environ.get("MINIO_SECRET_KEY"), secure=False)
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("UPDATE processing_jobs SET status='RUNNING', started_at=%s WHERE job_id=%s", (datetime.utcnow(), job_id))
    try:
        resp = m.get_object(bucket, key)
        data = resp.read()
        resp.close()
        resp.release_conn()
        text = ""
        if mime_type.startswith("application/pdf"):
            text = extract_text(io.BytesIO(data)) or ""
        elif mime_type.startswith("text/"):
            text = data.decode("utf-8", errors="ignore")
        else:
            text = ""
        cur.execute("SELECT title FROM documents WHERE doc_id=%s", (doc_id,))
        title = cur.fetchone()[0]
        cur.execute("SELECT meta_json::text FROM document_metadata WHERE doc_id=%s", (doc_id,))
        meta_row = cur.fetchone()
        meta_text = meta_row[0] if meta_row else ""
        cur.execute("SELECT t.name FROM document_tags dt JOIN tags t ON dt.tag_id=t.tag_id WHERE dt.doc_id=%s", (doc_id,))
        tags = " ".join([r[0] for r in cur.fetchall()]) if cur.rowcount else ""
        cur.execute("INSERT INTO document_index(doc_id,ver_id,extracted_text,search_vector,updated_at) VALUES(%s,%s,%s, to_tsvector(%s||' '||%s||' '||%s), now()) ON CONFLICT (doc_id) DO UPDATE SET ver_id=%s, extracted_text=%s, search_vector=to_tsvector(%s||' '||%s||' '||%s), updated_at=now()", (doc_id, ver_id, text, title, tags, meta_text, ver_id, text, title, tags, meta_text))
        cur.execute("UPDATE processing_jobs SET status='SUCCESS', finished_at=%s WHERE job_id=%s", (datetime.utcnow(), job_id))
        conn.commit()
    except Exception as e:
        cur.execute("UPDATE processing_jobs SET status='FAILED', finished_at=%s, error_message=%s WHERE job_id=%s", (datetime.utcnow(), str(e), job_id))
        conn.commit()
    finally:
        cur.close()
        conn.close()
