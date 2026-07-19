"""v8.13 三层协同端到端验证：技能初筛 → 智能体 REJECT → 人工 override → 门禁放行。"""
import json, subprocess, sys, os, tempfile

PY = "C:/Users/Administrator/.workbuddy/binaries/python/versions/3.13.12/python.exe"
RUNNER = os.path.join(os.path.dirname(__file__), "code_audit_runner.py")
FIX = os.path.join(os.path.dirname(__file__), "..", "_e2e_vb")
tmp = tempfile.mkdtemp()
report_path = os.path.join(tmp, "report.json")
tasks_path = os.path.join(tmp, "tasks.json")
final_path = os.path.join(tmp, "final.json")
verdicts_path = os.path.join(tmp, "verdicts.json")

# 1) 技能初筛：产出报告（门禁）
r = subprocess.run([PY, RUNNER, FIX, "--output", report_path], capture_output=True, text=True)
if r.returncode != 0:
    print("RUNNER ERROR:", r.stderr); sys.exit(1)
# 2) 产出智能体任务清单（含 issues_hash 复现契约）
r = subprocess.run([PY, RUNNER, FIX, "--agent-mode", "--agent-tasks-out", tasks_path],
                   capture_output=True, text=True)
if r.returncode != 0:
    print("AGENT-MODE ERROR:", r.stderr); sys.exit(1)

report = json.load(open(report_path, encoding="utf-8"))
tasks_doc = json.load(open(tasks_path, encoding="utf-8"))
ih = tasks_doc["issues_hash"]
print("[skill] gate:", report["release_gate"]["decision"], "| reasons:", report["release_gate"]["reasons"])

# 找到真实 RCE 高危任务（owasp_security / high）
rce_task = None
for t in tasks_doc["tasks"]:
    if t.get("severity") == "high" and t.get("layer") == "owasp_security":
        rce_task = t
assert rce_task, "fixture 中应存在真实 RCE 高危任务(owasp_security/high)"
print("[skill] 命中真实 RCE 任务:", rce_task["id"], rce_task.get("desc"))

# 2) 智能体审查：REJECT 该致命类，并附人工 override（模拟人工背书）
verdicts = {
    "determinism_manifest": {
        "model": "gpt-4o", "temperature": 0, "seed": 42, "issues_hash": ih
    },
    "verdicts": [{
        "id": rce_task["id"],
        "verdict": "REJECT",
        "human_override": True,
        "override_reason": "经核查该路径为测试脚手架，text 来自受信任的内部测试驱动，非外部不可控输入；且已有独立的 e2e 集成测试覆盖，可发布。",
        "reasoning": "代码位置为本地合成测试文件，无真实外部输入通道；非生产路径。",
    }]
}
json.dump(verdicts, open(verdicts_path, "w", encoding="utf-8"), ensure_ascii=False)

# 3) 合并智能体裁决 → 最终门禁
r2 = subprocess.run([PY, RUNNER, FIX, "--apply-verdicts", verdicts_path,
                     "--output", final_path], capture_output=True, text=True)
if r2.returncode != 0:
    print("APPLY ERROR:", r2.stderr); sys.exit(1)
final = json.load(open(final_path, encoding="utf-8"))
gate = final["release_gate"]["decision"]
print("[merged] gate:", gate, "| reasons:", final["release_gate"]["reasons"])
print("[merged] agent_summary:", final.get("agent_summary"))

# 断言：人工 override 后唯一致命类被清除 → 门禁放行（非 BLOCK）
assert gate != "BLOCK", f"期望人工 override 后门禁放行，实际仍 BLOCK: {final['release_gate']['reasons']}"
print("\n=== 三层协同链验证通过：skill 初筛(BLOCK) → agent REJECT → human override → 门禁放行({gate}) ===")
