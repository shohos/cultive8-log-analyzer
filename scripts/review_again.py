"""Re-review a fully processed job after a prompt update; keep chunk checkpoints.

Stop the backend first, run this command, then restart with scripts/run.py.
Existing findings remain visible as partial until each candidate is adjudicated.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import store

parser=argparse.ArgumentParser()
parser.add_argument("job_id")
args=parser.parse_args()
job=store.job_row(args.job_id)
if not job or job["status"] not in ("completed","failed") or job["cursor"] <= job["total_lines"]:
    raise SystemExit("Requires a completed source pass and a settled job")
with store.connect() as db:
    db.execute("DELETE FROM reviews WHERE job=?",(args.job_id,))
    db.execute("UPDATE jobs SET status='queued',phase='correlation',error=NULL WHERE id=?",(args.job_id,))
print("Queued final review; completed source calls and their audit records are preserved.")
