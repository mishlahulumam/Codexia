from fastapi import FastAPI
from pydantic import BaseModel
import os
from redis import Redis
from rq import Queue

class IndexReq(BaseModel):
    job_id: str
    doc_id: str
    ver_id: str
    bucket: str
    key: str
    mime_type: str

app = FastAPI()
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis = Redis.from_url(redis_url)
queue = Queue("index", connection=redis)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/internal/index")
def index(req: IndexReq):
    queue.enqueue("app.indexer.run", req.job_id, req.doc_id, req.ver_id, req.bucket, req.key, req.mime_type, job_id=req.job_id)
    return {"accepted": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))
