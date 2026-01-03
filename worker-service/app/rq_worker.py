import os
from rq import Worker, Connection
from redis import Redis

redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
conn = Redis.from_url(redis_url)

if __name__ == "__main__":
    with Connection(conn):
        w = Worker(["index"])
        w.work()
