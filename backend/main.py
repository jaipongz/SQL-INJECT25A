from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shlex
import re
import asyncio
import os
import shutil

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CurlCommand(BaseModel):
    curl: str
    level: int = 3
    risk: int = 2
    tamper: str | None = None
    random_agent: bool = False

def parse_curl(curl_command: str):
    tokens = shlex.split(curl_command)
    url = ""
    method = "GET"
    headers = {}
    data = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "curl":
            i += 1
            continue
        elif token in ("-X", "--request"):
            method = tokens[i + 1]
            i += 2
        elif token in ("-H", "--header"):
            header = tokens[i + 1]
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
            i += 2
        elif token in ("-d", "--data", "--data-raw", "--data-binary"):
            data = tokens[i + 1]
            i += 2
        elif re.match(r'^https?://', token):
            url = token
            i += 1
        else:
            i += 1
    return url, method, headers, data

def build_sqlmap_command(url, method="GET", headers=None, data=None, level=3, risk=2, tamper=None, random_agent=False):
    sqlmap_path = shutil.which("sqlmap")
    if sqlmap_path is None:
        sqlmap_path = os.path.join(os.getcwd(), "sqlmap", "sqlmap.py")
        cmd = ["python3", sqlmap_path]
    else:
        cmd = [sqlmap_path]

    cmd += ["-u", url]
    if method.upper() != "GET":
        cmd += ["--method", method.upper()]
    if data:
        cmd += ["--data", data]
    if headers:
        for k, v in headers.items():
            cmd += ["--header", f"{k}: {v}"]
    cmd += ["--level", str(level), "--risk", str(risk), "--batch"]

    if tamper:
        cmd += ["--tamper", tamper]
    if random_agent:
        cmd += ["--random-agent"]

    return cmd

@app.post("/run")
async def run_sqlmap(curl: CurlCommand):
    url, method, headers, data = parse_curl(curl.curl)
    if not url:
        raise HTTPException(status_code=400, detail="URL not found in curl command")

    print("📥 Received input:")
    print(f"curl: {data}")
    print(f"tamper: {curl.tamper}")
    print(f"level: {curl.level}")
    print(f"risk: {curl.risk}")
    print(f"random_agent: {curl.random_agent}")

    sqlmap_cmd = build_sqlmap_command(
        url, method, headers, data,
        level=curl.level, risk=curl.risk,
        tamper=curl.tamper, random_agent=curl.random_agent
    )

    async def stream_output():
        process = await asyncio.create_subprocess_exec(
            *sqlmap_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        try:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                yield line.decode(errors="ignore")
            await process.wait()
        except Exception as e:
            yield f"\n[Error] {str(e)}\n"

    return StreamingResponse(stream_output(), media_type="text/plain")

@app.get("/vuln")
def vulnerable(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    print("DEBUG QUERY:", query)
    try:
        return {"result": query}
    except Exception as e:
        return {"error": str(e)}