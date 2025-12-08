from fastapi import FastAPI
app = FastAPI(title="Password Defense Lab")

@app.get("/health")
def health():
    return {"status": "ok"}