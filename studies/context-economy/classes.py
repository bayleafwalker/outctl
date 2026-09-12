import json, glob, os, re, collections
root = os.path.expanduser('~/.claude/projects')
BOUND = re.compile(r'\|\s*(head|tail|grep|wc|cut|awk|sed -n|sort \| uniq|jq|rg)\b|--stat|--oneline|\bhead -|\btail -|\bgrep -c|-maxdepth')
CLASSES = [
 ('k8s/flux/infra', re.compile(r'\b(kubectl|flux|talosctl|helm|journalctl|systemctl|nixos-rebuild|nix (build|eval|flake)|ssh |docker|podman|zfs|zpool|restic)\b')),
 ('tests/lint/build', re.compile(r'\b(pytest|ruff|mypy|uv run|go test|go build|cargo|npm|pnpm|mise run|make)\b')),
 ('git', re.compile(r'\bgit\b|\bgh\b|\bfj\b')),
 ('file-read', re.compile(r'\b(cat|sed -n|head|tail|less|bat)\b|<<')),
 ('search/list', re.compile(r'\b(grep|rg|find|ls|tree|wc|du|df)\b')),
 ('python/scripts', re.compile(r'\bpython3?\b|\bjq\b|\bcurl\b')),
]
def cls(c):
    for n, r in CLASSES:
        if r.search(c): return n
    return 'other'
by = collections.Counter(); nby = collections.Counter(); bb = collections.Counter(); retr = 0; reads_tr = 0
ctx_cal = []
for f in glob.glob(root + '/**/*.jsonl', recursive=True):
    name = {}; cmd = {}; chars = 0; last = None
    for line in open(f, errors='replace'):
        try: d = json.loads(line)
        except Exception: continue
        m = d.get('message')
        if not isinstance(m, dict): continue
        if d.get('type') == 'assistant' and m.get('usage'): last = m['usage']
        c = m.get('content')
        if isinstance(c, str): chars += len(c); continue
        if not isinstance(c, list): continue
        for b in c:
            if not isinstance(b, dict): continue
            if b.get('type') == 'tool_use':
                inp = b.get('input') or {}; name[b['id']] = b.get('name'); chars += len(json.dumps(inp))
                s = json.dumps(inp)
                if 'tool-results/' in s: retr += 1
                if b.get('name') == 'Bash': cmd[b['id']] = inp.get('command','') or ''
            elif b.get('type') == 'tool_result':
                cc = b.get('content'); s = ''.join(x.get('text','') for x in cc if isinstance(x, dict)) if isinstance(cc, list) else (cc if isinstance(cc, str) else '')
                chars += len(s)
                if name.get(b.get('tool_use_id')) == 'Bash':
                    c0 = cmd.get(b['tool_use_id'], ''); k = cls(c0); by[k] += len(s); nby[k] += 1
                    bb['bounded' if BOUND.search(c0) else 'unbounded'] += len(s)
            elif b.get('type') in ('text','thinking'): chars += len(b.get(b['type'],''))
    if last and '/subagents/' not in f:
        tot = last.get('input_tokens',0)+last.get('cache_read_input_tokens',0)+last.get('cache_creation_input_tokens',0)
        if tot > 200000: ctx_cal.append(chars/tot)
T = sum(by.values())
print("Bash result bytes by command class (first matching class wins):")
for k, v in by.most_common(): print(f"  {k:18} {v/1e6:5.2f}M {v/T*100:4.0f}%  calls={nby[k]}  avg={v//max(nby[k],1)}")
print("bounded vs unbounded bytes:", {k: f"{v/1e6:.2f}M ({v/T*100:.0f}%)" for k,v in bb.items()})
print("tool_use inputs referencing tool-results/ (spool retrievals):", retr)
print("chars-per-context-token calibration (sessions >200k):", [round(x,2) for x in ctx_cal])
