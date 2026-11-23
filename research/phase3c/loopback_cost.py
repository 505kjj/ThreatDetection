"""Measure lower-bound serialization and loopback transport overhead on synthetic counts."""

import argparse
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from statistics import median
from threading import Thread
from time import perf_counter_ns

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiment_data import private_path, read_json, sha256, write_json


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--phase3b-models", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    root = private_path(args.phase3b_models)
    source = root / "logistic_regression.joblib"
    if sha256(source) != read_json(root / "frozen.json")["models"]["logistic_regression"]["sha256"]:
        raise ValueError("Frozen artifact checksum differs")
    model = joblib.load(source)
    vector = [0, 0, 24, 3, 2, 1, 16, 1]
    payload = json.dumps(vector).encode("ascii")
    query = np.asarray([vector], dtype=np.float32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.path != "/probe" or int(self.headers.get("Content-Length", 0)) != len(payload):
                self.send_error(400)
                return
            if self.rfile.read(len(payload)) != payload:
                self.send_error(400)
                return
            value = model.predict_proba(np.asarray([json.loads(payload)], dtype=np.float32))[0, 1]
            reply = json.dumps(float(value)).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    def time_us(operation):
        elapsed = []
        for index in range(100):
            start = perf_counter_ns()
            operation()
            if index >= 10:
                elapsed.append((perf_counter_ns() - start) / 1000)
        return {"p50Us": median(elapsed), "p95Us": float(np.percentile(elapsed, 95))}

    with threadpool_limits(limits=1), HTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=3)

        def request():
            conn.request("POST", "/probe", body=payload, headers={"Content-Type": "application/json"})
            reply = conn.getresponse()
            if reply.status != 200:
                raise ValueError("Loopback fixture rejected the numeric vector")
            return json.loads(reply.read())

        try:
            local = time_us(lambda: model.predict_proba(query))
            http = time_us(request)
        finally:
            conn.close()
            server.shutdown()
            worker.join()
    write_json(private_path(args.output), {"model": "frozen logistic regression", "directPython": local,
        "loopbackHttp": http, "scope": "Synthetic numeric vector, separate local HTTP requests, no TLS, WAN, or production service"})


if __name__ == "__main__":
    main()
