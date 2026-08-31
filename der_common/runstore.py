"""Run-directory management for long-running / artifact-heavy operations.

Fuzz runs (especially boofuzz for DNP3) produce large databases and pcaps. Those
land in a per-job run directory under ``runs/`` and are referenced by path from
:class:`der_common.schema.FuzzFinding`, never inlined into results.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_RUNS_ROOT = Path("runs")


def new_run_dir(job_id: str, root: Path | str = DEFAULT_RUNS_ROOT) -> Path:
    """Create and return ``<root>/<job_id>/`` for a job's artifacts."""
    d = Path(root) / job_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_result(run_dir: Path, name: str, obj) -> Path:
    """Serialize a pydantic model or dict to JSON inside the run dir."""
    path = Path(run_dir) / name
    data = obj.model_dump() if hasattr(obj, "model_dump") else obj
    path.write_text(json.dumps(data, indent=2, default=str))
    return path
