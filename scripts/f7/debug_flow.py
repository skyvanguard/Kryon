"""Debug helper — inspect flows for a single CPG."""
from __future__ import annotations

import ast
import json
import re
import sys

from cpgqls_client import CPGQLSClient

CPG = sys.argv[1]
KIND = sys.argv[2] if len(sys.argv) > 2 else "121"

if KIND == "121":
    src, sink = "recv|read|fgets|atoi|scanf|fscanf", '"<operator>.indirectIndexAccess").argument(2)'
else:
    src, sink = "fscanf|scanf|recv|read|fgets|atoi", '"<operator>.addition|<operator>.multiplication|<operator>.subtraction").argument'

q = f"""
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
val sources = cpg.call.name("{src}").l
val sinks   = cpg.call.name({sink}.l
val flows   = sinks.reachableByFlows(sources.argument).l
val js = ujson.Arr.from(flows.map {{ f =>
  val methodName = f.elements.collectFirst {{ case n: CfgNode => n.method.name }}.getOrElse("?")
  ujson.Obj("method" -> methodName, "path" -> ujson.Arr.from(f.elements.map {{ n =>
    ujson.Obj("line" -> n.lineNumber.map(_.toInt).getOrElse(-1), "label" -> n.label, "code" -> n.code.take(200))
  }}))
}})
ujson.write(js)
"""

c = CPGQLSClient("127.0.0.1:8080")
c.execute("close")
c.execute(f'importCpg("{CPG}")')
r = c.execute(q)
s = re.sub(r"\x1b\[[0-9;]*m", "", r.get("stdout", ""))
m = re.search(r"val\s+res\d+:\s*String\s*=\s*", s)
if not m:
    print("no result string"); print(s[-400:]); sys.exit(1)
raw = ast.literal_eval(s[m.end():].strip())
data = json.loads(raw)
print(f"total flows: {len(data)}")
by_method: dict[str, list] = {}
for f in data:
    by_method.setdefault(f["method"], []).append(f)
for m_name, flows in by_method.items():
    print(f"\n=== method: {m_name} ({len(flows)} flows) ===")
    # dedup path tuples to avoid printing repetitive flows
    unique_paths = set()
    for f in flows:
        key = tuple((n["line"], n["label"], n["code"][:40]) for n in f["path"])
        if key in unique_paths:
            continue
        unique_paths.add(key)
        print(f"-- flow ({len(f['path'])} nodes) --")
        for n in f["path"]:
            code = n["code"][:70].replace("\n", " ")
            print(f"   {n['label']:20s} L{n['line']:>4}  {code}")
