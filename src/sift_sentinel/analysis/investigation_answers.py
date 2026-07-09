"""Dataset-agnostic investigation-answers resolver (Sentinel Qwen Ensemble, report).

Anchors on the malicious findings' own entities and pivots through the
typed-fact indexes to answer the canonical DFIR questions:
WHO / WHAT / WHERE / HOW / WHEN. No case-specific value is hardcoded; every
answer is evidence-derived or explicitly 'not established'.
"""
from __future__ import annotations
import re, ipaddress, collections

_PATH = re.compile(r'(?:[A-Za-z]:\\|\\\\)[^\s",;|]+')
_IP = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
_TS = re.compile(r'(\d{4})-(\d{2})-(\d{2})[ T](\d{2}:\d{2}:\d{2})')
_SRC = ('.lnk', '.automaticdestinations', '.customdestinations', '\\recent\\')
_DOC = ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.zip',
        '.rar', '.7z', '.tar', '.gz', '.eml', '.msg', '.sln', '.vcxproj',
        '.key', '.pem', '.sql', '.bak', '.dwg', '.psd')
_DIRS = ('\\documents\\', '\\desktop\\', '\\projects\\', '\\source\\',
         '\\repos\\', '\\downloads\\', '\\onedrive\\')
_STOLEN = ('.zip', '.rar', '.7z', '.tar', '.gz', '.doc', '.docx', '.xls',
           '.xlsx', '.pdf', '.sln', '.vcxproj', '.key', '.pem', '.sql')
_MAL_BUCKETS = ('confirmed_malicious_atomic', 'suspicious_needs_review')


def _texts(f):
    v = []
    for x in f.values():
        if isinstance(x, str):
            v.append(x)
        elif isinstance(x, list):
            v += [str(i) for i in x if isinstance(i, str)]
    r = f.get('raw_excerpt')
    if isinstance(r, dict):
        v += [str(i) for i in r.values() if isinstance(i, str)]
    elif isinstance(r, str):
        v.append(r)
    return v


def _doc_paths(facts):
    s = set()
    for f in facts:
        if not isinstance(f, dict):
            continue
        for t in _texts(f):
            for m in _PATH.findall(t):
                c = m.rstrip('".,);').replace('\\\\', '\\')
                low = c.lower()
                if low.startswith(('\\..', '..')):
                    continue
                if any(x in low for x in _SRC):
                    continue
                if low.endswith(_DOC) or any(d in low for d in _DIRS):
                    s.add(c)
    return sorted(s)


def resolve(evidence_db, buckets):
    """Return investigation answers for one case. Pure read, no side effects."""
    tf = (evidence_db or {}).get('typed_facts') or {}
    idx = (evidence_db or {}).get('indexes') or {}
    buckets = buckets or {}

    def facts(*types):
        o = []
        for t in types:
            o += (tf.get(t) or [])
        return o

    fid = {}
    for fs in tf.values():
        if isinstance(fs, list):
            for f in fs:
                if isinstance(f, dict) and f.get('fact_id'):
                    fid[f['fact_id']] = f

    users = sorted({str(f.get('username')) for f in facts('user_account_fact')
                    if f.get('username')})
    # SIFT_PRINCIPAL_BY_ACTIVITY_V1 -- rank principals by structural activity
    # (owned PIDs + paths touched + event/RDP/PowerShell volume), not alphabetical.
    # Pure evidence-derived; no case-specific or vocab values.
    _ua = [f for f in facts('user_account_fact')
           if isinstance(f, dict) and f.get('username')]
    def _uscore(f):
        def _n(k):
            v = f.get(k)
            if isinstance(v, (list, tuple, set)):
                return len(v)
            return v if isinstance(v, (int, float)) else 0
        return (_n('owned_pids') + _n('paths_seen') + _n('event_count')
                + _n('rdp_count') + _n('powershell_count'))
    principals = [str(f.get('username'))
                  for f in sorted(_ua, key=lambda g: (-_uscore(g),
                                                      str(g.get('username'))))]
    principal = principals[0] if principals else None

    projects = _doc_paths(facts('jumplist_fact', 'lnk_execution_fact'))
    stolen = sorted({p for p in projects if p.lower().endswith(_STOLEN)})

    mal_pids = set()
    for bk in _MAL_BUCKETS:
        for f in (buckets.get(bk) or []):
            if not isinstance(f, dict):
                continue
            for c in (f.get('claims') or []):
                if isinstance(c, dict):
                    v = c.get('pid') or c.get('value')
                    if v not in (None, '') and str(v).strip().isdigit():
                        mal_pids.add(str(v).strip())

    ext = set()
    by_pid = idx.get('by_pid') or {}
    for p in mal_pids:
        for i in (by_pid.get(p) or []):
            f = fid.get(i)
            if f and f.get('fact_type') == 'network_connection_fact':
                for t in _texts(f):
                    for tok in _IP.findall(t):
                        try:
                            if ipaddress.ip_address(tok).is_global:
                                ext.add(tok)
                        except ValueError:
                            pass
    ext = sorted([x for x in ext if x.count('.') == 3],
                 key=lambda s: tuple(int(p) if p.isdigit() else 999
                                     for p in s.split('.')))

    sig = collections.Counter()
    for v in buckets.values():
        if isinstance(v, list):
            for f in v:
                if isinstance(f, dict):
                    for s in (f.get('malicious_semantic_signals') or []):
                        sig[str(s)] += 1
    techniques = [s for s, _ in sig.most_common(10)]

    tss = []
    for f in facts('event_log_fact', 'session_fact', 'network_connection_fact',
                   'process_fact', 'registry_persistence_fact'):
        for t in _texts(f):
            for y, mo, d, hms in _TS.findall(t):
                if 2007 <= int(y) <= 2030:
                    tss.append('%s-%s-%s %s' % (y, mo, d, hms))
    # SIFT_ACTIVITY_WINDOW_DENSE_V1 -- report the DENSE activity window, not raw min/max
    # (min/max is polluted by sparse outlier timestamps: MFT epoch / bogus future dates).
    # Universal: keep days at >= 0.05x the peak day's volume; window = span of those days.
    _dc = collections.Counter(t[:10] for t in tss)
    if _dc:
        _peak = max(_dc.values())
        _dense = sorted(d for d, c in _dc.items() if c >= max(2, _peak * 0.05))
        if _dense:
            _lo = min(t for t in tss if t[:10] == _dense[0])
            _hi = max(t for t in tss if t[:10] == _dense[-1])
            window = [_lo, _hi]
        else:
            window = [min(tss), max(tss)]
    else:
        window = None
    busiest = collections.Counter(t[:10] for t in tss).most_common(6)

    return {'principal': principal, 'principals': principals,
            'projects_files': projects,
            'candidate_stolen': stolen, 'external_endpoints': ext,
            'techniques': techniques, 'activity_window': window,
            'busiest_dates': busiest}


def render(a):
    who = a.get('principal') or 'the primary account'
    out = ['INVESTIGATION ANSWERS', '=====================',
           'WHO (principal): %s' % who]
    _ps = a.get('principals') or []
    if len(_ps) > 1:
        out.append('   accounts observed (by activity): %s' % ', '.join(_ps))

    def block(title, items, n=15):
        out.append('')
        out.append(title)
        if not items:
            out.append('   not established')
            return
        for x in items[:n]:
            out.append('   - %s' % x)
        if len(items) > n:
            out.append('   (+%d more)' % (len(items) - n))

    block('WHAT projects/files were accessed:', a.get('projects_files') or [])
    block('WHAT was (candidate) stolen:', a.get('candidate_stolen') or [])
    block('WHERE it went (external endpoints):', a.get('external_endpoints') or [])
    block('HOW (technique chain):', a.get('techniques') or [])
    out.append('')
    w = a.get('activity_window')
    out.append('WHEN: %s' % ('%s  ->  %s' % (w[0], w[1]) if w else 'not established'))
    bd = a.get('busiest_dates') or []
    if bd:
        out.append('   busiest dates: %s' %
                   ', '.join('%s(%d)' % (d, n) for d, n in bd))
    return '\n'.join(out)


def main():
    import json, os, sys
    run_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('ST', '.')
    db = json.load(open(os.path.join(run_dir, 'evidence_db.json')))
    bp = os.path.join(run_dir, 'finding_disposition_buckets.json')
    buckets = json.load(open(bp)) if os.path.exists(bp) else {}
    print(render(resolve(db, buckets)))


if __name__ == '__main__':
    main()
