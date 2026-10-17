"""Independent adversarial review attacks (17 Oct 2026), kept as a regression script.
Each attack starts from the PASS baseline and plants one fault. Run: python tests/adversarial_review_attacks.py"""
import sys, json, hashlib, copy, tempfile, traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datetime import datetime, timezone, timedelta
from crasme.demo import build_baseline, FAKE_KEV_ID
from crasme.gate import evaluate
from crasme.scanstatus import ScanManifest, classify
J=lambda p: json.loads(Path(p).read_text()); W=lambda p,o: Path(p).write_text(json.dumps(o))
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def scan(b, name, **kw):
    m=ScanManifest.load(b/"scan-status.json")
    for s in m.scans:
        if s.name==name:
            for k,v in kw.items(): setattr(s,k,v)
    m.save(b/"scan-status.json")
def resign(b, name, fname):  # recompute digest, as anyone editing the bundle can
    scan(b, name, output_path=fname, output_digest=sha(b/fname))
def add_vuln(b, vid, sev, pkg="lodash"):
    v=J(b/"vulns.json"); v["Results"][0]["Vulnerabilities"].append({"VulnerabilityID":vid,"PkgName":pkg,"InstalledVersion":"1","Severity":sev}); W(b/"vulns.json",v)
    resign(b,"vulns","vulns.json")
    m=J(b/"evidence-manifest.json")
    for r in m["records"]:
        if r["evidence_uri"]=="vulns.json": r["evidence_sha256"]=sha(b/"vulns.json")
    W(b/"evidence-manifest.json",m)
def units(b, fn):
    u=J(b/"trace-units.json"); u=fn(u) or u; W(b/"trace-units.json",u)
def appr(b, fn):
    a=J(b/"approvals.json"); a=fn(a) or a; W(b/"approvals.json",a)

A={}
def atk(name):
    def d(f): A[name]=f; return f
    return d

@atk("kev scan record points at vulns.json (no KEV ids)")
def _(b,c,p): resign(b,"kev","vulns.json"); add_vuln(b,FAKE_KEV_ID,"LOW"); resign(b,"kev","vulns.json")
@atk("kev.json emptied, digest recomputed (status still OK)")
def _(b,c,p): W(b/"kev.json",{"catalogVersion":"x","vulnerabilities":[]}); resign(b,"kev","kev.json"); add_vuln(b,FAKE_KEV_ID,"LOW")
@atk("vulns record points at sbom.cdx.json")
def _(b,c,p): add_vuln(b,FAKE_KEV_ID,"CRITICAL"); resign(b,"vulns","sbom.cdx.json")
@atk("trivy report with Results=[] classified OK by run_scan/classify")
def _(b,c,p):
    W(b/"vulns.json",{"SchemaVersion":2,"ArtifactName":"sbom","Results":[]})
    print("   classify ->", classify("action","trivy",None,b/"vulns.json",step_outcome="success"))
    resign(b,"vulns","vulns.json")
    m=J(b/"evidence-manifest.json")
    for r in m["records"]:
        if r["evidence_uri"]=="vulns.json": r["evidence_sha256"]=sha(b/"vulns.json")
    W(b/"evidence-manifest.json",m)
@atk("conditional obligation OSS-01: trace unit deleted")
def _(b,c,p): units(b, lambda u:[x for x in u if x["requirement_id"]!="OSS-01"])
@atk("conditional OSS-01 N/A, no reviewer")
def _(b,c,p): units(b, lambda u:[dict(x,reviewer="") if x["requirement_id"]=="OSS-01" else x for x in u])
@atk("mandatory Y row N/A, unit bound to other product/build")
def _(b,c,p):
    def f(u):
        x=next(x for x in u if x["applicable"]); x.update(applicable=False, status="not_applicable",product_id="OTHER",build_id="0"*40)
    units(b,f)
@atk("VEX under_investigation for HIGH finding")
def _(b,c,p): add_vuln(b,"CVE-0000-00009","HIGH"); W(b/"vex.json",{"statements":[{"vulnerability":{"name":"CVE-0000-00009"},"status":"under_investigation"}]})
@atk("VEX garbage status 'whatever' for CRITICAL finding")
def _(b,c,p): add_vuln(b,"CVE-0000-00009","CRITICAL"); W(b/"vex.json",{"statements":[{"vulnerability":{"name":"CVE-0000-00009"},"status":"whatever"}]})
@atk("VEX 'fixed' for KEV finding still detected in build")
def _(b,c,p): add_vuln(b,FAKE_KEV_ID,"HIGH"); W(b/"vex.json",{"statements":[{"vulnerability":{"name":FAKE_KEV_ID},"status":"fixed"}]})
@atk("VEX for another product (product field ignored)")
def _(b,c,p): add_vuln(b,FAKE_KEV_ID,"HIGH"); W(b/"vex.json",{"statements":[{"vulnerability":{"name":FAKE_KEV_ID},"products":[{"@id":"pkg:OTHER"}],"status":"not_affected","justification":"component_not_present"}]})
@atk("CRITICAL finding with VEX affected (non-KEV)")
def _(b,c,p): add_vuln(b,"CVE-0000-00009","CRITICAL"); W(b/"vex.json",{"statements":[{"vulnerability":{"name":"CVE-0000-00009"},"status":"affected"}]})
@atk("severity UNKNOWN finding untriaged")
def _(b,c,p): add_vuln(b,"CVE-0000-00009","UNKNOWN")
@atk("KEV id in finding with trailing space / lowercase")
def _(b,c,p): add_vuln(b,FAKE_KEV_ID.lower()+" ","LOW")
@atk("KEV CVE only as GHSA primary id with no CVE alias (trivy)")
def _(b,c,p): add_vuln(b,"GHSA-xxxx-yyyy-zzzz","LOW")
@atk("approvals: same build_sha, wrong product_id")
def _(b,c,p): appr(b, lambda a:[dict(x,product_id="OTHER-999") for x in a])
@atk("approvals: same person for both roles, no approved_at")
def _(b,c,p): appr(b, lambda a:[dict({k:v for k,v in x.items() if k!="approved_at"},reviewer="Mallory") for x in a])
@atk("approvals: approved_at AFTER as_of (future-dated)")
def _(b,c,p): appr(b, lambda a:[dict(x,approved_at="2030-01-01T00:00:00Z") for x in a])
@atk("approvals: expires_at year 9999")
def _(b,c,p): appr(b, lambda a:[dict(x,expires_at="9999-12-31T00:00:00Z") for x in a])
@atk("approvals: good + revoked for OTHER build same role")
def _(b,c,p): appr(b, lambda a:a+[dict(a[0],build_sha="0"*40,revoked=True)])
@atk("policy require_verified_legal_mapping=false + unverified catalogue")
def _(b,c,p):
    p["require_verified_legal_mapping"]=False
    for r in c: r["legal_status"]="unverified"
@atk("policy obligation_gates=[event-driven]")
def _(b,c,p): p["obligation_gates"]=["event-driven"]
@atk("policy untriaged_review_severities=[] + CRITICAL")
def _(b,c,p): p["untriaged_review_severities"]=[]; add_vuln(b,"CVE-0000-00009","CRITICAL")
@atk("policy required_approval_roles=[security_lead] only")
def _(b,c,p): p["required_approval_roles"]=["security_lead"]
@atk("empty catalogue (header-only CSV)")
def _(b,c,p): c.clear()
@atk("catalogue gate 'Pre-market' (case) + unit missing")
def _(b,c,p):
    r=next(r for r in c if r["gate"]=="pre-market" and r["mandatory"]=="Y" and r["applies_from"].startswith("2027"))
    r["gate"]="Pre-market"; units(b, lambda u:[x for x in u if x["requirement_id"]!=r["req_id"]])
@atk("catalogue mandatory 'N' for a mandatory row + unit missing")
def _(b,c,p):
    r=next(r for r in c if r["gate"]=="pre-market" and r["mandatory"]=="Y" and r["applies_from"].startswith("2027"))
    r["mandatory"]="N"; units(b, lambda u:[x for x in u if x["requirement_id"]!=r["req_id"]])
@atk("evidence age rule, generated_at missing (old evidence)")
def _(b,c,p):
    p["evidence_max_age_days"]={"default":1}
    m=J(b/"evidence-manifest.json"); [r.pop("generated_at") for r in m["records"]]; W(b/"evidence-manifest.json",m)
@atk("evidence generated_at in future")
def _(b,c,p):
    p["evidence_max_age_days"]={"default":1}
    m=J(b/"evidence-manifest.json"); [r.update(generated_at="2099-01-01T00:00:00Z") for r in m["records"]]; W(b/"evidence-manifest.json",m)
@atk("lockfile changed but product.json lacks input_digests")
def _(b,c,p):
    pr=J(b/"product.json"); pr.pop("input_digests"); W(b/"product.json",pr)
    m=J(b/"evidence-manifest.json"); [r.update(input_digests={"lockfile":"99"*32}) for r in m["records"]]; W(b/"evidence-manifest.json",m)
@atk("one manifest record claims ALL requirement ids (sbom as evidence for everything)")
def _(b,c,p):
    m=J(b/"evidence-manifest.json"); allr=[x["requirement_id"] for x in J(b/"trace-units.json")]
    sb=next(r for r in m["records"] if r["evidence_uri"]=="sbom.cdx.json"); sb["requirement_ids"]=allr; W(b/"evidence-manifest.json",m)
    units(b, lambda u:[dict(x,evidence_sha256=sb["evidence_sha256"],evidence_uri="nonexistent.pdf") if x["applicable"] else x for x in u])
@atk("manifest record review_status 'unreviewed' + unit reviewed_at garbage/before evidence")
def _(b,c,p):
    m=J(b/"evidence-manifest.json"); [r.update(review_status="unreviewed") for r in m["records"]]; W(b/"evidence-manifest.json",m)
    units(b, lambda u:[dict(x,reviewed_at="not-a-date") for x in u])
@atk("evidence_uri path traversal ../../x/evidence-...md")
def _(b,c,p):
    m=J(b/"evidence-manifest.json"); r=m["records"][3]; r["evidence_uri"]="../../../tmp/"+r["evidence_uri"]; W(b/"evidence-manifest.json",m)
@atk("fs (secret) scan OK with live secret findings")
def _(b,c,p):
    W(b/"trivy-fs.json",{"SchemaVersion":2,"ArtifactName":".","Results":[{"Target":"x","Secrets":[{"RuleID":"aws","Severity":"CRITICAL","Match":"***"}]}]})
    m=ScanManifest.load(b/"scan-status.json"); s=copy.deepcopy(m.scans[1]); s.name="fs"; s.output_path="trivy-fs.json"; s.output_digest=sha(b/"trivy-fs.json"); m.scans.append(s); m.save(b/"scan-status.json")
@atk("scan record finished 2 years before as_of (stale vulns + KEV)")
def _(b,c,p):
    for n in ("vulns","kev","sbom"): scan(b,n,finished_at="2025-01-01T00:00:00Z",started_at="2025-01-01T00:00:00Z")
@atk("as_of with -05:00 offset just before 2027-12-11 UTC midnight crossing")
def _(b,c,p): return datetime(2027,12,10,23,0,tzinfo=timezone(timedelta(hours=-5)))
@atk("duplicate scan names: FAILED kev + OK kev")
def _(b,c,p):
    m=ScanManifest.load(b/"scan-status.json"); s=copy.deepcopy([x for x in m.scans if x.name=="kev"][0]); s.execution_status="FAILED"; m.scans.insert(0,s); m.save(b/"scan-status.json")
@atk("required scan recorded required=False")
def _(b,c,p): scan(b,"kev",required=False,execution_status="FAILED")

for name,f in A.items():
    with tempfile.TemporaryDirectory() as td:
        b,c,p,as_of=build_baseline(td)
        assert evaluate(b,copy.deepcopy(p),as_of,copy.deepcopy(c))["decision"]=="PASS"
        try:
            r=f(b,c,p)
            if isinstance(r,datetime): as_of=r
            d=evaluate(b,p,as_of,c)
            print(("FALSE-PASS " if d["decision"]=="PASS" else "ok         ")+f"{d['decision']:16} {name}  {d['reasons'][:3]}")
        except Exception as e:
            print("ERR", name, e); traceback.print_exc()
