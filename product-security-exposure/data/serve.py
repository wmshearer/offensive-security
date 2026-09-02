"""A minimal model-metadata service.

It accepts a GGUF model file and returns what the header says about it. This is
the shape of a real internal service: something uploads a model, something else
needs to know its architecture and quantisation before scheduling it.

The security-relevant line is the GGUFReader call. It parses a file that came
from outside, which is what makes a parser bug in gguf-py an exposure question
rather than a library trivia question.
"""
from fastapi import FastAPI, UploadFile
import tempfile, os

app = FastAPI()


@app.post("/inspect")
async def inspect(f: UploadFile):
    from gguf.gguf_reader import GGUFReader

    path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as t:
            t.write(await f.read())
            path = t.name
        r = GGUFReader(path)          # <-- parses untrusted input
        return {"fields": len(r.fields), "tensors": len(r.tensors)}
    finally:
        if path and os.path.exists(path):
            os.unlink(path)
