"""Async fuzz-job manager for the MCP server.

Each job runs `der_mcp.fuzz_runner` as a subprocess with its CWD set to a
per-job run directory. The runner writes status.json / findings.json there;
this manager reconciles those with the live process state. Large evidence
(boofuzz DBs, pcaps) stays in the run dir and is referenced by path -- never
streamed back through the tool result.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from der_common.runstore import DEFAULT_RUNS_ROOT, new_run_dir


@dataclass
class Job:
    id: str
    protocol: str
    target: str
    run_dir: str
    proc: subprocess.Popen | None = None


class JobManager:
    def __init__(self, runs_root: Path | str = DEFAULT_RUNS_ROOT):
        self.runs_root = Path(runs_root)
        self._jobs: dict[str, Job] = {}

    def start(self, argv: list[str], protocol: str, target: str) -> str:
        job_id = "job-" + uuid.uuid4().hex[:12]
        run_dir = new_run_dir(job_id, self.runs_root)
        log = open(run_dir / "runner.log", "w")
        proc = subprocess.Popen(argv, cwd=str(run_dir), stdout=log, stderr=subprocess.STDOUT)
        self._jobs[job_id] = Job(id=job_id, protocol=protocol, target=target,
                                 run_dir=str(run_dir), proc=proc)
        return job_id

    def _read(self, job: Job, name: str):
        p = Path(job.run_dir) / name
        if p.exists():
            try:
                return json.loads(p.read_text())
            except Exception:
                return None
        return None

    def _state(self, job: Job) -> str:
        st = self._read(job, "status.json") or {}
        if job.proc is None:
            return st.get("state", "unknown")
        rc = job.proc.poll()
        if rc is None:
            return "running"
        # process exited; trust a terminal runner state if present, else infer
        if st.get("state") in ("done", "failed"):
            return st["state"]
        return "done" if rc == 0 else "failed"

    def status(self, job_id: str) -> dict:
        job = self._get(job_id)
        st = self._read(job, "status.json") or {}
        return {
            "job_id": job.id,
            "protocol": job.protocol,
            "target": job.target,
            "state": self._state(job),
            "run_dir": job.run_dir,
            "summary": st.get("summary"),
            "error": st.get("error"),
        }

    def list(self) -> list[dict]:
        return [self.status(jid) for jid in self._jobs]

    def stop(self, job_id: str) -> dict:
        job = self._get(job_id)
        if job.proc is not None and job.proc.poll() is None:
            job.proc.terminate()
        return self.status(job_id)

    def findings(self, job_id: str) -> list[dict]:
        job = self._get(job_id)
        return self._read(job, "findings.json") or []

    def _get(self, job_id: str) -> Job:
        if job_id not in self._jobs:
            raise KeyError(f"unknown job {job_id}")
        return self._jobs[job_id]
