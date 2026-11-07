"""Verify an actual supplied-log run and export evidence. No mock model is used."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import store
from app.model import CONTEXT, INPUT_LIMIT, OUTPUT


def main():
    parser=argparse.ArgumentParser();parser.add_argument("job_id");args=parser.parse_args()
    report=store.report(args.job_id)
    assert report and report['complete'], "Job must be completed"
    sample=ROOT/'samples/Cultive8_Workspace_Agrigen_Server.log'
    assert report['sha256']==hashlib.sha256(sample.read_bytes()).hexdigest()
    with store.connect() as db:
        calls=[dict(r) for r in db.execute('SELECT * FROM calls WHERE job=? ORDER BY seq',(args.job_id,))]
    chunks=[r for r in calls if r['phase']=='chunks']
    reconstructed=''.join(e['text'] for c in chunks for e in json.loads(c['payload'])['log_entries'])
    assert reconstructed==sample.read_text(encoding='utf-8'), "Source coverage must be exact"
    for c in calls:
        m=json.loads(c['metrics'])
        assert m['input_tokens']<=INPUT_LIMIT and m['output_tokens']<=OUTPUT
        assert m['input_tokens']+m['output_tokens']<=CONTEXT
    expected={'Possible account compromise','SQL injection','Scanning','Unauthorized access','Unusual request rate','Prompt injection'}
    assert {f['type'] for f in report['findings']}==expected
    assert not any(f['entity'] in {'192.0.2.10','198.51.100.96'} for f in report['findings'])
    auth=next(f for f in report['findings'] if f['type']=='Possible account compromise')
    assert {5,123,196,198,201}<=set(auth['lines']) and auth['cross_chunk']
    sql=next(f for f in report['findings'] if f['type']=='SQL injection')
    assert sql['facts']['unique_attempts']==4 and 223 not in sql['lines']
    for f in report['findings']:
        assert set(f['model_cited_lines'])<=set(f['lines'])
        assert all(e['entity']==f['entity'] for e in f['evidence'])
    (ROOT/'docs/sample-report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    metrics=[json.loads(c['metrics']) for c in calls]
    summary={'job':args.job_id,'source_sha256':report['sha256'],'lines':report['total_lines'],'duplicates':report['duplicates'],'chunk_calls':len(chunks),'review_calls_including_revisions':len(calls)-len(chunks),'total_saved_calls':len(calls),'findings':len(report['findings']),'max_input_tokens':max(m['input_tokens'] for m in metrics),'max_output_tokens':max(m['output_tokens'] for m in metrics),'max_actual_total_tokens':max(m['input_tokens']+m['output_tokens'] for m in metrics),'sum_model_seconds':round(sum(m['seconds'] for m in metrics),2),'peak_sampled_rss_mib':report['peak_rss_mb'],'retries':report['retries'],'exact_source_coverage':True}
    (ROOT/'docs/validation-metrics.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    main()
