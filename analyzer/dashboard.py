"""
dashboard.py

분석 결과를 바탕으로 HTML 대시보드를 생성하고 브라우저로 자동으로 연다.
main.py 마지막에서 호출된다.
"""

import json
import webbrowser
from pathlib import Path
from typing import Any, Dict, List


def generate_dashboard(
    detection_results: Dict[str, Any],
    comparison_results: List[Dict[str, Any]],
    graph: Dict[str, Any],
    project_dir: str
) -> str:

    ast_results       = detection_results.get("ast_results", [])
    dynamic_results   = detection_results.get("dynamic_results", [])
    install_results   = detection_results.get("install_script_results", [])
    typo_results      = detection_results.get("typosquatting_results", [])
    confusion_results = detection_results.get("dependency_confusion_results", [])

    # ── 위험도 분류 ────────────────────────────────────────────────────────────
    high    = [r for r in comparison_results if r.get("risk_level") == "HIGH"]
    medium  = [r for r in comparison_results if r.get("risk_level") == "MEDIUM"]
    low     = [r for r in comparison_results if r.get("risk_level") == "LOW"]
    unknown = [r for r in comparison_results if r.get("risk_level") == "UNKNOWN"]
    high_names   = {r["package"] for r in high}
    medium_names = {r["package"] for r in medium}

    # ── 최종 판정 ─────────────────────────────────────────────────────────────
    if high:
        verdict, verdict_color, verdict_bg = "위험", "#E24B4A", "rgba(226,75,74,0.12)"
    elif install_results or typo_results or confusion_results:
        verdict, verdict_color, verdict_bg = "주의", "#BA7517", "rgba(186,117,23,0.12)"
    else:
        verdict, verdict_color, verdict_bg = "안전", "#1D9E75", "rgba(29,158,117,0.12)"

    # ── 메트릭 ────────────────────────────────────────────────────────────────
    nodes_raw  = graph.get("nodes", {})
    edges_raw  = graph.get("edges", [])
    pkg_count  = len([n for n in nodes_raw.values() if n.get("path", "") != ""])
    edge_count = len(edges_raw)
    total_static  = sum(len(p.get("findings", [])) for p in ast_results)
    static_pkgs   = len([p for p in ast_results if p.get("findings")])
    total_dynamic = sum(
        len(pkg.get(k, []))
        for pkg in dynamic_results
        for k in ["env_access", "process_execution", "filesystem", "network"]
    )
    dynamic_pkgs = sum(
        1 for p in dynamic_results
        if any(len(p.get(k, [])) > 0 for k in ["env_access", "process_execution", "filesystem", "network"])
    )

    # ── 정적 탐지 유형별 ──────────────────────────────────────────────────────
    TYPE_KO = {
        "obfuscation":              "난독화 패턴",
        "dynamic_execution":        "동적 코드 실행",
        "system_info_access":       "시스템 정보 접근",
        "external_communication":   "외부 통신",
        "system_command_execution": "시스템 명령 실행",
    }
    TYPE_COLOR = {
        "난독화 패턴":      "#378ADD",
        "동적 코드 실행":   "#1D9E75",
        "시스템 정보 접근": "#D4537E",
        "외부 통신":       "#BA7517",
        "시스템 명령 실행": "#E24B4A",
    }
    type_counter: Dict[str, int] = {}
    for pkg in ast_results:
        for f in pkg.get("findings", []):
            t = TYPE_KO.get(f.get("type", ""), f.get("type", ""))
            type_counter[t] = type_counter.get(t, 0) + 1
    static_labels = list(type_counter.keys())
    static_counts = list(type_counter.values())
    static_colors = [TYPE_COLOR.get(l, "#378ADD") for l in static_labels]

    # ── 동적 행위 유형별 ──────────────────────────────────────────────────────
    DYN_KO    = {"env_access": "환경변수 접근", "process_execution": "프로세스 실행", "filesystem": "파일 시스템", "network": "네트워크"}
    DYN_COLOR = {"env_access": "#7F77DD", "process_execution": "#D85A30", "filesystem": "#1D9E75", "network": "#378ADD"}
    dyn_counter: Dict[str, int] = {"env_access": 0, "process_execution": 0, "filesystem": 0, "network": 0}
    for pkg in dynamic_results:
        for cat in dyn_counter:
            dyn_counter[cat] += len(pkg.get(cat, []))
    dyn_labels = [DYN_KO[k] for k, v in dyn_counter.items() if v > 0]
    dyn_counts = [v for v in dyn_counter.values() if v > 0]
    dyn_colors = [DYN_COLOR[k] for k, v in dyn_counter.items() if v > 0]

    # ── 상위 패키지 ───────────────────────────────────────────────────────────
    pkgs_sorted = sorted(
        [p for p in ast_results if p.get("findings")],
        key=lambda p: len(p.get("findings", [])), reverse=True
    )[:10]
    top_labels = [p["package"] for p in pkgs_sorted]
    top_counts = [len(p.get("findings", [])) for p in pkgs_sorted]
    top_colors = [
        "#E24B4A" if p["package"] in high_names
        else "#BA7517" if p["package"] in medium_names
        else "#378ADD"
        for p in pkgs_sorted
    ]

    # ── HIGH 카드 HTML ────────────────────────────────────────────────────────
    high_cards_html = ""
    for r in high:
        reasons_html = "".join(f"<li>{reason}</li>" for reason in r.get("risk_reasons", []))
        s = r.get("summary", {})
        high_cards_html += f"""
        <div class="high-card">
          <div class="high-card-header">
            <div><span class="pkg-name">{r['package']}</span> <span class="pkg-ver">@ {r['version']}</span></div>
            <span class="badge-high">HIGH</span>
          </div>
          <ul class="reason-list">{reasons_html}</ul>
          <div class="high-card-stats">
            <span>정적 {s.get('static_finding_count',0)}건</span>
            <span>동적 {'발생' if s.get('dynamic_executed') else '없음'}</span>
          </div>
        </div>"""

    # ── 1단계 행 HTML ─────────────────────────────────────────────────────────
    def step1_row(ok, label, items):
        color  = "#1D9E75" if ok else "#E24B4A"
        bg     = "rgba(29,158,117,0.08)" if ok else "rgba(226,75,74,0.08)"
        icon   = "✓" if ok else "!"
        detail = ""
        if not ok and items:
            detail = "".join(f'<div class="step1-item">{i["package"]} @ {i.get("version","?")}</div>' for i in items[:3])
            if len(items) > 3:
                detail += f'<div class="step1-item muted">... 외 {len(items)-3}개</div>'
        return f"""<div class="step1-row" style="border-color:{color};background:{bg};">
          <div class="step1-left"><span class="step1-icon" style="color:{color};">{icon}</span><span class="step1-label">{label}</span></div>
          <div class="step1-right">{detail if detail else '<span class="muted">이상 없음</span>'}</div>
        </div>"""

    step1_html  = step1_row(not install_results,   "Install Script",      install_results)
    step1_html += step1_row(not typo_results,      "Typosquatting",       typo_results)
    step1_html += step1_row(not confusion_results, "Dependency Confusion", confusion_results)

    # ── 네트워크 그래프 데이터 ────────────────────────────────────────────────
    node_list = []
    for nid, ninfo in nodes_raw.items():
        name = ninfo.get("name", "")
        if name in high_names:        color, r = "#E24B4A", 9
        elif name in medium_names:    color, r = "#BA7517", 7
        elif ninfo.get("path","")=="": color, r = "#888780", 14
        else:                          color, r = "#4a80b5", 5
        node_list.append({"id": nid, "name": name, "color": color, "r": r})
    edge_list = [{"from": e["from"], "to": e["to"]} for e in edges_raw]

    project_name = Path(project_dir).name

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{project_name} · 보안 분석</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Noto+Sans+KR:wght@300;400;500&display=swap');
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
  :root{{
    --bg:#0c0e11;--bg2:#13161c;--bg3:#1c2028;
    --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.13);
    --text:#dde1ea;--text2:#7c8394;--text3:#3e4450;
    --mono:'IBM Plex Mono',monospace;--sans:'Noto Sans KR',sans-serif;
    --high:#E24B4A;--med:#BA7517;--low:#1D9E75;--acc:#378ADD;--purple:#7F77DD;
  }}
  body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-weight:300;min-height:100vh;}}
  header{{padding:1.4rem 2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:1rem;background:var(--bg2);}}
  .hdr-left h1{{font-family:var(--mono);font-size:0.9rem;font-weight:500;color:var(--acc);letter-spacing:0.03em;}}
  .hdr-left p{{font-size:0.72rem;color:var(--text2);margin-top:3px;font-family:var(--mono);}}
  .verdict{{font-family:var(--mono);font-size:0.95rem;font-weight:500;padding:5px 18px;border-radius:3px;border:1px solid;color:{verdict_color};border-color:{verdict_color};background:{verdict_bg};letter-spacing:0.06em;}}
  main{{padding:1.4rem 2rem;max-width:1440px;}}
  .metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1.2rem;}}
  .row2{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px;}}
  .row3{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;}}
  .card{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:1rem 1.2rem;}}
  .card-title{{font-family:var(--mono);font-size:0.66rem;color:var(--text2);letter-spacing:0.08em;text-transform:uppercase;margin-bottom:.9rem;display:flex;align-items:center;gap:6px;}}
  .card-title::before{{content:'';display:inline-block;width:2px;height:10px;background:var(--acc);border-radius:1px;}}
  .metric{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:1rem 1.2rem;}}
  .metric-label{{font-family:var(--mono);font-size:0.63rem;color:var(--text3);letter-spacing:0.09em;text-transform:uppercase;margin-bottom:6px;}}
  .metric-value{{font-family:var(--mono);font-size:1.9rem;font-weight:500;line-height:1;}}
  .metric-sub{{font-size:0.68rem;color:var(--text2);margin-top:4px;}}
  .v-acc{{color:var(--acc);}}.v-warn{{color:var(--med);}}.v-purple{{color:var(--purple);}}.v-high{{color:var(--high);}}.v-low{{color:var(--low);}}
  .step1-row{{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:9px 11px;border-radius:4px;border-left:2px solid;margin-bottom:7px;}}
  .step1-left{{display:flex;align-items:center;gap:7px;flex-shrink:0;}}
  .step1-icon{{font-family:var(--mono);font-weight:500;font-size:0.85rem;}}
  .step1-label{{font-family:var(--mono);font-size:0.76rem;color:var(--text);}}
  .step1-right{{font-size:0.7rem;color:var(--text2);text-align:right;}}
  .step1-item{{margin-bottom:2px;font-family:var(--mono);font-size:0.68rem;}}
  .muted{{color:var(--text3);}}
  .donut-wrap{{position:relative;}}
  .donut-center{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none;}}
  .donut-num{{font-family:var(--mono);font-size:1.5rem;font-weight:500;color:var(--text);}}
  .donut-sub{{font-size:0.62rem;color:var(--text2);margin-top:1px;font-family:var(--mono);}}
  .high-card{{background:rgba(226,75,74,0.05);border:1px solid rgba(226,75,74,0.22);border-radius:5px;padding:11px 13px;margin-bottom:7px;}}
  .high-card-header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:7px;}}
  .pkg-name{{font-family:var(--mono);font-size:0.82rem;font-weight:500;color:var(--text);}}
  .pkg-ver{{font-family:var(--mono);font-size:0.72rem;color:var(--text2);}}
  .badge-high{{font-family:var(--mono);font-size:0.6rem;padding:2px 7px;border-radius:2px;background:rgba(226,75,74,0.14);color:var(--high);border:1px solid rgba(226,75,74,0.28);letter-spacing:0.05em;}}
  .reason-list{{list-style:none;margin-bottom:7px;}}
  .reason-list li{{font-size:0.7rem;color:var(--text2);padding:2px 0 2px 12px;position:relative;}}
  .reason-list li::before{{content:'→';position:absolute;left:0;color:var(--high);font-size:0.62rem;top:3px;}}
  .high-card-stats{{display:flex;gap:10px;font-family:var(--mono);font-size:0.66rem;color:var(--text3);}}
  .legend{{display:flex;flex-wrap:wrap;gap:9px;margin-bottom:9px;}}
  .legend span{{font-size:0.66rem;color:var(--text2);display:flex;align-items:center;gap:4px;font-family:var(--mono);}}
  .legend-dot{{width:7px;height:7px;border-radius:1px;flex-shrink:0;}}
  #net-canvas{{width:100%;display:block;border-radius:4px;cursor:crosshair;}}
  .tip{{position:fixed;background:var(--bg3);border:1px solid var(--border2);border-radius:4px;padding:4px 9px;font-family:var(--mono);font-size:0.7rem;color:var(--text);pointer-events:none;display:none;z-index:999;}}
</style>
</head>
<body>

<header>
  <div class="hdr-left">
    <h1>npm security analyzer &nbsp;/&nbsp; {project_name}</h1>
    <p>packages: {pkg_count} &nbsp;·&nbsp; edges: {edge_count} &nbsp;·&nbsp; static: {total_static}건 &nbsp;·&nbsp; dynamic: {total_dynamic}건</p>
  </div>
  <div class="verdict">{verdict}</div>
</header>

<main>

  <div class="metrics">
    <div class="metric">
      <div class="metric-label">총 패키지</div>
      <div class="metric-value v-acc">{pkg_count}</div>
      <div class="metric-sub">의존성 엣지 {edge_count}개</div>
    </div>
    <div class="metric">
      <div class="metric-label">정적 탐지</div>
      <div class="metric-value v-warn">{total_static}<span style="font-size:.9rem;color:var(--text2)">건</span></div>
      <div class="metric-sub">{static_pkgs}개 패키지</div>
    </div>
    <div class="metric">
      <div class="metric-label">동적 행위</div>
      <div class="metric-value v-purple">{total_dynamic}<span style="font-size:.9rem;color:var(--text2)">건</span></div>
      <div class="metric-sub">{dynamic_pkgs}개 패키지</div>
    </div>
    <div class="metric" style="{'border-color:rgba(226,75,74,0.35);' if high else ''}">
      <div class="metric-label">HIGH 위험</div>
      <div class="metric-value {'v-high' if high else 'v-low'}">{len(high)}<span style="font-size:.9rem;color:var(--text2)">개</span></div>
      <div class="metric-sub">{'수동 확인 필요' if high else '위험 없음'}</div>
    </div>
  </div>

  <div class="row2">
    <div class="card">
      <div class="card-title">1단계 · 메타데이터 분석</div>
      {step1_html}
    </div>
    <div class="card">
      <div class="card-title">위험도 분포</div>
      <div class="legend">
        <span><span class="legend-dot" style="background:#E24B4A"></span>HIGH {len(high)}</span>
        <span><span class="legend-dot" style="background:#BA7517"></span>MEDIUM {len(medium)}</span>
        <span><span class="legend-dot" style="background:#1D9E75"></span>LOW {len(low)}</span>
        {'<span><span class="legend-dot" style="background:#7c8394"></span>UNKNOWN '+str(len(unknown))+'</span>' if unknown else ''}
      </div>
      <div class="donut-wrap" style="height:190px;position:relative;">
        <canvas id="donutChart" role="img" aria-label="위험도 분포"></canvas>
        <div class="donut-center">
          <div class="donut-num">{pkg_count}</div>
          <div class="donut-sub">packages</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">HIGH 위험 패키지</div>
      {high_cards_html if high_cards_html else '<div style="font-size:.76rem;color:var(--text2);text-align:center;padding:2rem 0;">위험 패키지 없음</div>'}
    </div>
  </div>

  <div class="row3">
    <div class="card">
      <div class="card-title">2단계 · 정적 탐지 유형별</div>
      <div class="legend">{''.join(f'<span><span class="legend-dot" style="background:{TYPE_COLOR.get(l,"#378ADD")}"></span>{l}</span>' for l in static_labels)}</div>
      <div style="position:relative;width:100%;height:{max(120,len(static_labels)*36)}px;">
        <canvas id="staticChart" role="img" aria-label="정적 탐지 유형별 건수"></canvas>
      </div>
    </div>
    <div class="card">
      <div class="card-title">3단계 · 동적 행위 유형별</div>
      <div class="legend">{''.join(f'<span><span class="legend-dot" style="background:{DYN_COLOR.get(k,"#378ADD")}"></span>{DYN_KO[k]}</span>' for k,v in dyn_counter.items() if v>0)}</div>
      <div style="position:relative;width:100%;height:{max(120,len(dyn_labels)*44)}px;">
        <canvas id="dynChart" role="img" aria-label="동적 행위 유형별 건수"></canvas>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:12px;">
    <div class="card-title">정적 탐지 상위 패키지 TOP 10</div>
    <div class="legend">
      <span><span class="legend-dot" style="background:#378ADD"></span>일반</span>
      <span><span class="legend-dot" style="background:#BA7517"></span>MEDIUM</span>
      <span><span class="legend-dot" style="background:#E24B4A"></span>HIGH</span>
    </div>
    <div style="position:relative;width:100%;height:{max(200,len(top_labels)*32)}px;">
      <canvas id="topChart" role="img" aria-label="정적 탐지 상위 패키지"></canvas>
    </div>
  </div>

  <div class="card">
    <div class="card-title">의존성 그래프 · {pkg_count}개 노드 / {edge_count}개 엣지</div>
    <div class="legend">
      <span><span class="legend-dot" style="background:#888780"></span>루트</span>
      <span><span class="legend-dot" style="background:#4a80b5"></span>일반</span>
      <span><span class="legend-dot" style="background:#BA7517"></span>MEDIUM</span>
      <span><span class="legend-dot" style="background:#E24B4A"></span>HIGH</span>
    </div>
    <canvas id="net-canvas" role="img" aria-label="의존성 네트워크 그래프" height="500"></canvas>
  </div>

</main>

<div class="tip" id="tip"></div>

<script>
const gc='rgba(255,255,255,0.05)', tc='#7c8394';

new Chart(document.getElementById('donutChart'),{{
  type:'doughnut',
  data:{{labels:['HIGH','MEDIUM','LOW','UNKNOWN'],datasets:[{{data:[{len(high)},{len(medium)},{len(low)},{len(unknown)}],backgroundColor:['#E24B4A','#BA7517','#1D9E75','#7c8394'],borderWidth:0,hoverOffset:4}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'68%',plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>' '+ctx.raw+'개'}}}}}}}}
}});

new Chart(document.getElementById('staticChart'),{{
  type:'bar',
  data:{{labels:{json.dumps(static_labels,ensure_ascii=False)},datasets:[{{data:{json.dumps(static_counts)},backgroundColor:{json.dumps(static_colors)},borderRadius:3,barThickness:22}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>' '+ctx.raw+'건'}}}}}},scales:{{x:{{grid:{{color:gc}},ticks:{{color:tc,font:{{size:11}}}}}},y:{{grid:{{display:false}},ticks:{{color:tc,font:{{size:11}}}}}}}}}}
}});

new Chart(document.getElementById('dynChart'),{{
  type:'bar',
  data:{{labels:{json.dumps(dyn_labels,ensure_ascii=False)},datasets:[{{data:{json.dumps(dyn_counts)},backgroundColor:{json.dumps(dyn_colors)},borderRadius:3,barThickness:28}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>' '+ctx.raw+'건'}}}}}},scales:{{x:{{grid:{{color:gc}},ticks:{{color:tc,font:{{size:11}}}}}},y:{{grid:{{display:false}},ticks:{{color:tc,font:{{size:11}}}}}}}}}}
}});

new Chart(document.getElementById('topChart'),{{
  type:'bar',
  data:{{labels:{json.dumps(top_labels,ensure_ascii=False)},datasets:[{{data:{json.dumps(top_counts)},backgroundColor:{json.dumps(top_colors)},borderRadius:3,barThickness:20}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>' '+ctx.raw+'건'}}}}}},scales:{{x:{{grid:{{color:gc}},ticks:{{color:tc,font:{{size:11}}}}}},y:{{grid:{{display:false}},ticks:{{color:tc,font:{{size:10}}}}}}}}}}
}});

(function(){{
  const canvas=document.getElementById('net-canvas');
  const ctx=canvas.getContext('2d');
  const W=canvas.offsetWidth||1000, H=500;
  canvas.width=W; canvas.height=H;
  const tip=document.getElementById('tip');
  const nodeList={json.dumps(node_list,ensure_ascii=False)};
  const edgeList={json.dumps(edge_list,ensure_ascii=False)};
  const idToIdx={{}};
  nodeList.forEach((n,i)=>{{idToIdx[n.id]=i;}});
  const rng=s=>{{let x=s;return()=>{{x=(x*16807)%2147483647;return(x-1)/2147483646;}}}};
  const rand=rng(42);
  const nodes=nodeList.map((n,i)=>{{
    const a=(i/nodeList.length)*Math.PI*2;
    const d=n.r>=12?0:50+rand()*210;
    return{{...n,x:n.r>=12?W/2:W/2+Math.cos(a)*d,y:n.r>=12?H/2:H/2+Math.sin(a)*d,vx:(rand()-.5)*.8,vy:(rand()-.5)*.8}};
  }});
  const edges=edgeList.map(e=>[idToIdx[e.from],idToIdx[e.to]]).filter(([a,b])=>a!==undefined&&b!==undefined);
  function draw(){{
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle='#0c0e11';ctx.fillRect(0,0,W,H);
    ctx.globalAlpha=0.12;ctx.strokeStyle='#7c8394';ctx.lineWidth=0.7;
    edges.forEach(([a,b])=>{{ctx.beginPath();ctx.moveTo(nodes[a].x,nodes[a].y);ctx.lineTo(nodes[b].x,nodes[b].y);ctx.stroke();}});
    ctx.globalAlpha=1;
    nodes.forEach(n=>{{
      ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
      ctx.fillStyle=n.color;ctx.globalAlpha=.9;ctx.fill();ctx.globalAlpha=1;
      if(n.r>=7){{ctx.strokeStyle='rgba(255,255,255,0.15)';ctx.lineWidth=1.2;ctx.stroke();}}
      if(n.r>=9){{ctx.fillStyle='#dde1ea';ctx.font='500 9px IBM Plex Mono,monospace';ctx.textAlign='center';ctx.fillText(n.name.length>18?n.name.slice(0,17)+'…':n.name,n.x,n.y+n.r+11);}}
    }});
  }}
  let frame=0;
  function animate(){{
    nodes.forEach(n=>{{
      if(n.r>=12)return;
      n.x+=n.vx;n.y+=n.vy;
      const dx=n.x-W/2,dy=n.y-H/2,d=Math.sqrt(dx*dx+dy*dy);
      if(d>230){{n.vx-=dx/d*.4;n.vy-=dy/d*.4;}}
      if(n.x<14||n.x>W-14)n.vx*=-.8;
      if(n.y<14||n.y>H-14)n.vy*=-.8;
      n.vx*=.97;n.vy*=.97;
      n.vx+=(rand()-.5)*.04;n.vy+=(rand()-.5)*.04;
    }});
    draw();
    if(++frame<280)requestAnimationFrame(animate);
    else{{nodes.forEach(n=>{{n.vx=0;n.vy=0;}});draw();}}
  }}
  animate();
  canvas.addEventListener('mousemove',e=>{{
    const rect=canvas.getBoundingClientRect();
    const mx=e.clientX-rect.left,my=e.clientY-rect.top;
    let hit=null;
    nodes.forEach(n=>{{if(Math.sqrt((n.x-mx)**2+(n.y-my)**2)<n.r+5)hit=n;}});
    if(hit){{tip.style.display='block';tip.style.left=(e.clientX+12)+'px';tip.style.top=(e.clientY-8)+'px';tip.textContent=hit.name;}}
    else tip.style.display='none';
  }});
  canvas.addEventListener('mouseleave',()=>tip.style.display='none');
}})();
</script>
</body>
</html>"""

    output_path = Path(project_dir) / "dashboard.html"
    with output_path.open("w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  대시보드 생성 완료 : {output_path}")
    webbrowser.open(f"file://{output_path.resolve()}")
    return str(output_path)
