"""External normal SmartDNS regression check; no secrets or server changes."""
import ast,json,pathlib,subprocess,sys
source=pathlib.Path('scripts/smartdns-vpn-video-origin-dns-20261116.py').read_text();tree=ast.parse(source)
node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROBE' for t in n.targets));probe=ast.literal_eval(node.value)
rows=[]
for host in ['rr1---sn-gxuo03g-3c2z.googlevideo.com','rr2---sn-gxuo03g-vqnl.googlevideo.com','rr4---sn-gxuo03g-vqnl.googlevideo.com']:
 for qtype in [1,28]:
  result=subprocess.run(['python3','-','89.125.90.101','853',host,str(qtype)],input=probe,text=True,capture_output=True,timeout=12,check=True);r=json.loads(result.stdout)
  assert r['rcode']==0
  if qtype==1:assert r['ipv4']==['89.125.90.101']
  else:assert r['answers']==0
  rows.append(r)
path=pathlib.Path('output')/('external-'+sys.argv[1]+'.json');path.write_text(json.dumps(rows,indent=2));print('EXTERNAL_NORMAL_SMARTDNS_'+sys.argv[1].upper()+'=PASS')
