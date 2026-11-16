import pathlib,subprocess,json,re,datetime,shutil
out={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def run(a):
 try:
  p=subprocess.run(a,capture_output=True,text=True,timeout=12);return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-500:]}
 except FileNotFoundError:return {'unavailable':True}
 except Exception as e:return {'error':type(e).__name__}
def sanitize(s):
 return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',lambda m:m[0] if m[0] in ['89.125.90.101','188.120.254.223','10.66.77.1','10.66.77.2','127.0.0.1','0.0.0.0','9.9.9.9','1.1.1.1','8.8.8.8'] else '<ip>',s)
interfaces=json.loads(run(['ip','-j','-d','link','show'])['stdout']);out['links']=[];out['tc']={}
for link in interfaces:
 name=link['ifname'];out['links'].append({k:v for k,v in link.items() if k in ['ifname','mtu','qdisc','operstate','flags','xdp','linkinfo']})
 if name=='lo' or name.startswith(('veth','br-','docker')):continue
 out['tc'][name]={direction:run(['tc','-j','filter','show','dev',name,direction]) for direction in ['ingress','egress']}
 out['tc'][name]['qdisc']=run(['tc','-j','qdisc','show','dev',name])
 out['tc'][name]['offload']=run(['ethtool','-k',name])
out['nft']=run(['nft','-a','list','ruleset']);out['iptables']=run(['iptables-save','-c'])
out['policy_rules']=run(['ip','rule','show']);out['routes']=run(['ip','route','show','table','all'])
out['bpf_net']=run(['bpftool','net']);out['bpf_cgroup']=run(['bpftool','cgroup','tree'])
out['bpf_pins']=[str(p) for p in pathlib.Path('/sys/fs/bpf').rglob('*')][:100]
out['network_stats']=run(['ip','-s','link','show']);out['queues']=run(['cat','/proc/net/netfilter/nfnetlink_queue'])
out['sysctl']=run(['sysctl','net.ipv4.conf.all.rp_filter','net.ipv4.conf.default.rp_filter','net.ipv4.tcp_mtu_probing','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.ipv4.tcp_syncookies','net.netfilter.nf_conntrack_count','net.netfilter.nf_conntrack_max'])
out['services']={}
for unit in ['nginx.service','mnebydns-dot.service','mnebydns-gemini.service','mnebydns-googlepilot.service','mnebydns-de89-public-quic-20261115.service','telegram-foreign-nfqws.service']:
 props=['ActiveState','NRestarts','MainPID','MemoryCurrent','MemoryMax','LimitNOFILE','CPUQuotaPerSecUSec','ControlGroup'];q=run(['systemctl','show',unit,*['-p'+k for k in props]]);data=dict(line.split('=',1) for line in q.get('stdout','').splitlines() if '=' in line)
 group=data.get('ControlGroup','')
 if group:
  for name in ['cpu.stat','cpu.max','memory.events','memory.current']:
   p=pathlib.Path('/sys/fs/cgroup'+group)/name
   if p.exists():data[name]=p.read_text()
 data['recent_errors']=run(['journalctl','-u',unit,'--since','15 minutes ago','--no-pager','-p','warning','-o','cat'])
 out['services'][unit]=data
out['done']=True
print(sanitize(json.dumps(out)))
