import json, glob, os, re, sys, collections, statistics
root = os.path.expanduser('~/.claude/projects')
files = glob.glob(root + '/**/*.jsonl', recursive=True)
BOUND = re.compile(r'\|\s*(head|tail|grep|wc|cut|awk|sed -n|sort \| uniq|jq|rg)\b|--stat|--oneline|\bhead -|\btail -|\bgrep -c|-maxdepth|\b(limit|head|tail)\s*[:=]')
TRUNC = re.compile(r'\[?(output )?truncated|characters truncated|lines truncated|\.\.\. \[\d+ more|exceeds maximum', re.I)
ONLYYOU = 'Only you see that command'
sess = []
allres = []
bashres = []
big_cmds = []
for f in files:
    is_sub = '/subagents/' in f
    name_of = {}
    cmd_of = {}
    tot_by_tool = collections.Counter()
    n_by_tool = collections.Counter()
    text_chars = 0
    n_bash = n_bash_bounded = n_trunc = n_onlyyou = 0
    compactions = 0
    last_usage = None
    first_ts = None
    n_msgs = 0
    for line in open(f, errors='replace'):
        try: d = json.loads(line)
        except Exception: continue
        ts = d.get('timestamp'); 
        if ts and not first_ts: first_ts = ts[:10]
        if d.get('isCompactSummary') or d.get('type') == 'summary': compactions += 1
        m = d.get('message')
        if not isinstance(m, dict): continue
        n_msgs += 1
        u = m.get('usage')
        if u and d.get('type') == 'assistant': last_usage = u
        c = m.get('content')
        if isinstance(c, str):
            text_chars += len(c); continue
        if not isinstance(c, list): continue
        for b in c:
            if not isinstance(b, dict): continue
            t = b.get('type')
            if t == 'text': text_chars += len(b.get('text',''))
            elif t == 'thinking': text_chars += len(b.get('thinking',''))
            elif t == 'tool_use':
                name_of[b.get('id')] = b.get('name'); inp = b.get('input') or {}
                cmd_of[b.get('id')] = inp.get('command','') if isinstance(inp, dict) else ''
                text_chars += len(json.dumps(inp))
                if b.get('name') == 'Bash':
                    n_bash += 1
                    if BOUND.search(inp.get('command','') or ''): n_bash_bounded += 1
            elif t == 'tool_result':
                cc = b.get('content')
                if isinstance(cc, list): s = ''.join(x.get('text','') for x in cc if isinstance(x, dict))
                else: s = cc if isinstance(cc, str) else json.dumps(cc)
                tn = name_of.get(b.get('tool_use_id'), '?')
                L = len(s)
                tot_by_tool[tn] += L; n_by_tool[tn] += 1; allres.append(L)
                if tn == 'Bash':
                    bashres.append(L)
                    if TRUNC.search(s): n_trunc += 1
                    if ONLYYOU in s: n_onlyyou += 1
                    if L > 10000: big_cmds.append((L, (cmd_of.get(b.get('tool_use_id'),'') or '').strip().split('\n')[0][:110], os.path.basename(f)[:8]))
    tool_total = sum(tot_by_tool.values())
    sess.append(dict(f=os.path.relpath(f, root), sub=is_sub, date=first_ts, msgs=n_msgs, text=text_chars, tools=tool_total,
        bash=tot_by_tool['Bash'], read=tot_by_tool['Read'], nbash=n_bash, nbound=n_bash_bounded, trunc=n_trunc, onlyyou=n_onlyyou,
        comp=compactions, ctx=(last_usage or {}).get('input_tokens',0)+(last_usage or {}).get('cache_read_input_tokens',0)+(last_usage or {}).get('cache_creation_input_tokens',0),
        bytool=dict(tot_by_tool)))
def pct(a, q): 
    a = sorted(a); return a[min(len(a)-1, int(q*len(a)))] if a else 0
top = [s for s in sess if not s['sub']]
subs = [s for s in sess if s['sub']]
print(f"files={len(files)} top={len(top)} sub={len(subs)} dates={min(s['date'] for s in sess if s['date'])}..{max(s['date'] for s in sess if s['date'])}")
for label, grp in (('TOP-LEVEL', top), ('SUBAGENTS', subs), ('ALL', sess)):
    T = sum(s['text'] for s in grp); TL = sum(s['tools'] for s in grp); B = sum(s['bash'] for s in grp); R = sum(s['read'] for s in grp)
    print(f"\n== {label}: msg_text={T/1e6:.1f}M chars tool_results={TL/1e6:.1f}M bash={B/1e6:.1f}M read={R/1e6:.1f}M | bash share of (text+tools)={B/(T+TL)*100:.1f}% of tool_results={B/max(TL,1)*100:.1f}%")
    nb = sum(s['nbash'] for s in grp); nbb = sum(s['nbound'] for s in grp)
    print(f"   bash calls={nb} self-bounded={nbb} ({nbb/max(nb,1)*100:.0f}%) trunc-marked results={sum(s['trunc'] for s in grp)} only-you-notes={sum(s['onlyyou'] for s in grp)} compactions={sum(s['comp'] for s in grp)}")
agg = collections.Counter()
for s in sess:
    for k,v in s['bytool'].items(): agg[k]+=v
print("\ntool_result chars by tool (all):", ', '.join(f"{k}={v/1e6:.2f}M" for k,v in agg.most_common(8)))
print(f"\nBash result size: n={len(bashres)} p50={pct(bashres,.5)} p90={pct(bashres,.9)} p99={pct(bashres,.99)} max={max(bashres)} >10K={sum(1 for x in bashres if x>10000)} >30K={sum(1 for x in bashres if x>30000)} >50K={sum(1 for x in bashres if x>50000)}")
print(f"All result size: n={len(allres)} p50={pct(allres,.5)} p90={pct(allres,.9)} p99={pct(allres,.99)} max={max(allres)}")
b10 = sum(x for x in bashres if x>10000); print(f"share of bash bytes in results >10K: {b10/sum(bashres)*100:.0f}%  >30K: {sum(x for x in bashres if x>30000)/sum(bashres)*100:.0f}%")
print("\nPer top-level session (sorted by end context):")
print(f"{'date':10} {'msgs':>5} {'endctx':>7} {'comp':>4} {'bash%ctx':>8} {'bashK':>6} {'toolsK':>7} {'textK':>6} {'nbash':>5} {'bound%':>6} file")
for s in sorted(top, key=lambda s:-s['ctx']):
    tot = s['text']+s['tools']
    print(f"{str(s['date']):10} {s['msgs']:5} {s['ctx']//1000:6}k {s['comp']:4} {s['bash']/max(tot,1)*100:7.0f}% {s['bash']//1000:6} {s['tools']//1000:7} {s['text']//1000:6} {s['nbash']:5} {s['nbound']/max(s['nbash'],1)*100:5.0f}% {s['f'][:50]}")
print("\nLargest Bash results (>10K chars):")
for L, c, f in sorted(big_cmds, reverse=True)[:40]: print(f"{L:7} {f} {c}")
