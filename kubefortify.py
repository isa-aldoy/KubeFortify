import argparse,json
from pathlib import Path
import yaml

def scan(doc):
    spec=doc.get("spec",{})
    kind=doc.get("kind")
    if kind in ("Deployment","DaemonSet","StatefulSet","Job"):spec=spec.get("template",{}).get("spec",{})
    elif kind=="CronJob":spec=spec.get("jobTemplate",{}).get("spec",{}).get("template",{}).get("spec",{})
    elif kind!="Pod":return []
    findings=[]
    def flag(rule):findings.append({"rule":rule,"resource":doc.get("metadata",{}).get("name","unknown")})
    if spec.get("hostNetwork"):flag("host-network")
    if spec.get("hostPID"):flag("host-pid")
    for c in spec.get("containers",[]):
        security=c.get("securityContext",{})
        if security.get("privileged"):flag("privileged")
        if security.get("allowPrivilegeEscalation") is not False:flag("privilege-escalation-not-disabled")
        if not security.get("readOnlyRootFilesystem"):flag("writable-root-filesystem")
        if c.get("image","").endswith(":latest") or ":" not in c.get("image",""):flag("mutable-image")
    return findings
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("manifest");a=p.parse_args()
    findings=[]
    for doc in yaml.safe_load_all(Path(a.manifest).read_text()):
        if isinstance(doc,dict):findings.extend(scan(doc))
    print(json.dumps(findings,indent=2));raise SystemExit(bool(findings))
