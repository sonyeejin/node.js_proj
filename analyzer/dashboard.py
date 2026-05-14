"""
dashboard.py — 분석 결과 HTML 대시보드 생성
main.py 마지막에서 호출된다.
"""

import json
import os
import http.server
import threading
import time
import subprocess
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

    high    = [r for r in comparison_results if r.get("risk_level") == "HIGH"]
    medium  = [r for r in comparison_results if r.get("risk_level") == "MEDIUM"]
    low     = [r for r in comparison_results if r.get("risk_level") == "LOW"]
    unknown = [r for r in comparison_results if r.get("risk_level") == "UNKNOWN"]
    high_names   = {r["package"] for r in high}
    medium_names = {r["package"] for r in medium}

    if high:
        verdict, verdict_color, verdict_bg = "위험", "#E24B4A", "rgba(226,75,74,0.12)"
    elif install_results or typo_results or confusion_results:
        verdict, verdict_color, verdict_bg = "주의", "#BA7517", "rgba(186,117,23,0.12)"
    else:
        verdict, verdict_color, verdict_bg = "안전", "#1D9E75", "rgba(29,158,117,0.12)"

    nodes_raw  = graph.get("nodes", {})
    edges_raw  = graph.get("edges", [])
    pkg_count  = len([n for n in nodes_raw.values() if n.get("path", "") != ""])
    edge_count = len(edges_raw)
    total_static  = sum(len(p.get("findings", [])) for p in ast_results)
    static_pkgs   = len([p for p in ast_results if p.get("findings")])
    total_dynamic = sum(len(pkg.get(k, [])) for pkg in dynamic_results for k in ["env_access","process_execution","filesystem","network"])
    dynamic_pkgs  = sum(1 for p in dynamic_results if any(len(p.get(k,[])) > 0 for k in ["env_access","process_execution","filesystem","network"]))

    TYPE_KO    = {"obfuscation":"난독화 패턴","dynamic_execution":"동적 코드 실행","system_info_access":"시스템 정보 접근","external_communication":"외부 통신","system_command_execution":"시스템 명령 실행"}
    TYPE_COLOR = {"난독화 패턴":"#378ADD","동적 코드 실행":"#1D9E75","시스템 정보 접근":"#D4537E","외부 통신":"#BA7517","시스템 명령 실행":"#E24B4A"}
    type_counter: Dict[str, int] = {}
    for pkg in ast_results:
        for f in pkg.get("findings", []):
            t = TYPE_KO.get(f.get("type",""), f.get("type",""))
            type_counter[t] = type_counter.get(t, 0) + 1
    static_labels = list(type_counter.keys())
    static_counts = list(type_counter.values())
    static_colors = [TYPE_COLOR.get(l,"#378ADD") for l in static_labels]

    DYN_KO    = {"env_access":"환경변수 접근","process_execution":"프로세스 실행","filesystem":"파일 시스템","network":"네트워크"}
    DYN_COLOR = {"env_access":"#7F77DD","process_execution":"#D85A30","filesystem":"#1D9E75","network":"#378ADD"}
    dyn_counter: Dict[str,int] = {"env_access":0,"process_execution":0,"filesystem":0,"network":0}
    for pkg in dynamic_results:
        for cat in dyn_counter: dyn_counter[cat] += len(pkg.get(cat,[]))
    dyn_labels = [DYN_KO[k] for k,v in dyn_counter.items() if v>0]
    dyn_counts = [v for v in dyn_counter.values() if v>0]
    dyn_colors = [DYN_COLOR[k] for k,v in dyn_counter.items() if v>0]

    pkgs_sorted = sorted([p for p in ast_results if p.get("findings")], key=lambda p: len(p.get("findings",[])), reverse=True)[:10]
    top_labels  = [p["package"] for p in pkgs_sorted]
    top_counts  = [len(p.get("findings",[])) for p in pkgs_sorted]
    top_colors  = ["#E24B4A" if p["package"] in high_names else "#BA7517" if p["package"] in medium_names else "#378ADD" for p in pkgs_sorted]

    # HIGH 카드
    high_cards_html = ""
    for r in high:
        reasons_html = "".join(f"<li>{reason}</li>" for reason in r.get("risk_reasons",[]))
        s = r.get("summary", {})
        high_cards_html += f"""<div class="high-card">
          <div class="hc-header">
            <div><span class="pkg-name">{r['package']}</span> <span class="pkg-ver">@ {r['version']}</span></div>
            <span class="badge-high">HIGH</span>
          </div>
          <ul class="reason-list">{reasons_html}</ul>
          <div class="hc-stats"><span>정적 {s.get('static_finding_count',0)}건</span><span>동적 {'발생' if s.get('dynamic_executed') else '없음'}</span></div>
        </div>"""

    # 1단계 행
    def step1_row(ok, label, items):
        color = "#1D9E75" if ok else "#E24B4A"
        bg    = "rgba(29,158,117,0.08)" if ok else "rgba(226,75,74,0.08)"
        icon  = "✓" if ok else "!"
        detail = ""
        if not ok and items:
            detail = "".join(f'<div class="s1-item">{i["package"]} @ {i.get("version","?")}</div>' for i in items[:3])
            if len(items) > 3: detail += f'<div class="s1-item muted">... 외 {len(items)-3}개</div>'
        return f"""<div class="s1-row" style="border-color:{color};background:{bg};">
          <div class="s1-left"><span style="color:{color};font-family:var(--mono);font-weight:500;">{icon}</span><span class="s1-label">{label}</span></div>
          <div class="s1-right">{detail if detail else '<span class="muted">이상 없음</span>'}</div>
        </div>"""

    step1_html  = step1_row(not install_results,   "Install Script",      install_results)
    step1_html += step1_row(not typo_results,      "Typosquatting",       typo_results)
    step1_html += step1_row(not confusion_results, "Dependency Confusion", confusion_results)

    # 네트워크 그래프 데이터
    node_list = []
    for nid, ninfo in nodes_raw.items():
        name = ninfo.get("name","")
        if name in high_names:           color, r = "#E24B4A", 9
        elif name in medium_names:       color, r = "#BA7517", 7
        elif ninfo.get("path","") == "": color, r = "#888780", 14
        else:                             color, r = "#4a80b5", 5
        node_list.append({"id": nid, "name": name, "color": color, "r": r})
    edge_list = [{"from": e["from"], "to": e["to"]} for e in edges_raw]

    project_name = Path(project_dir).name

    j_nodes   = json.dumps(node_list, ensure_ascii=False)
    j_edges   = json.dumps(edge_list, ensure_ascii=False)
    j_slabels = json.dumps(static_labels, ensure_ascii=False)
    j_scounts = json.dumps(static_counts)
    j_scolors = json.dumps(static_colors)
    j_dlabels = json.dumps(dyn_labels, ensure_ascii=False)
    j_dcounts = json.dumps(dyn_counts)
    j_dcolors = json.dumps(dyn_colors)
    j_tlabels = json.dumps(top_labels, ensure_ascii=False)
    j_tcounts = json.dumps(top_counts)
    j_tcolors = json.dumps(top_colors)
    j_high    = str(len(high))
    j_medium  = str(len(medium))
    j_low     = str(len(low))
    j_unknown = str(len(unknown))

    html = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>""" + project_name + """ · 보안 분석</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{
  --bg:#0c0e11;--bg2:#13161c;--bg3:#1c2028;
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.13);
  --text:#dde1ea;--text2:#7c8394;--text3:#3e4450;
  --mono:'IBM Plex Mono',monospace;--sans:system-ui,sans-serif;
  --high:#E24B4A;--med:#BA7517;--low:#1D9E75;--acc:#378ADD;--purple:#7F77DD;
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;}
header{padding:1.2rem 2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:var(--bg2);}
.h1{font-family:var(--mono);font-size:0.9rem;font-weight:500;color:var(--acc);}
.hsub{font-size:0.7rem;color:var(--text2);margin-top:3px;font-family:var(--mono);}
main{padding:1.4rem 2rem;overflow-x:hidden;}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1.2rem;}
.metric{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:1rem 1.2rem;}
.mlabel{font-family:var(--mono);font-size:0.62rem;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;}
.mval{font-family:var(--mono);font-size:1.9rem;font-weight:500;line-height:1;}
.msub{font-size:0.68rem;color:var(--text2);margin-top:4px;}
.v-acc{color:var(--acc);}.v-warn{color:var(--med);}.v-purple{color:var(--purple);}.v-high{color:var(--high);}.v-low{color:var(--low);}
.row2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(0,1fr);gap:12px;margin-bottom:12px;}
.row3{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:1rem 1.2rem;}
.ctitle{font-family:var(--mono);font-size:0.65rem;color:var(--text2);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:.9rem;display:flex;align-items:center;justify-content:space-between;}
.ctitle-l{display:flex;align-items:center;gap:6px;}
.ctitle-l::before{content:'';width:2px;height:10px;background:var(--acc);border-radius:1px;display:inline-block;}
.s1-row{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:8px 10px;border-radius:4px;border-left:2px solid;margin-bottom:7px;}
.s1-left{display:flex;align-items:center;gap:7px;flex-shrink:0;}
.s1-label{font-family:var(--mono);font-size:0.75rem;color:var(--text);}
.s1-right{font-size:0.7rem;color:var(--text2);text-align:right;}
.s1-item{margin-bottom:2px;font-family:var(--mono);font-size:0.68rem;}
.muted{color:var(--text3);}
.donut-wrap{position:relative;}
.donut-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none;}
.donut-num{font-family:var(--mono);font-size:1.5rem;font-weight:500;}
.donut-sub{font-size:0.62rem;color:var(--text2);font-family:var(--mono);}
.high-card{background:rgba(226,75,74,0.05);border:1px solid rgba(226,75,74,0.2);border-radius:5px;padding:10px 13px;margin-bottom:7px;}
.hc-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:7px;}
.pkg-name{font-family:var(--mono);font-size:0.82rem;font-weight:500;}
.pkg-ver{font-family:var(--mono);font-size:0.72rem;color:var(--text2);}
.badge-high{font-family:var(--mono);font-size:0.6rem;padding:2px 7px;border-radius:2px;background:rgba(226,75,74,0.14);color:var(--high);border:1px solid rgba(226,75,74,0.28);}
.reason-list{list-style:none;margin-bottom:7px;}
.reason-list li{font-size:0.7rem;color:var(--text2);padding:2px 0 2px 12px;position:relative;}
.reason-list li::before{content:'→';position:absolute;left:0;color:var(--high);font-size:0.62rem;top:3px;}
.hc-stats{display:flex;gap:10px;font-family:var(--mono);font-size:0.66rem;color:var(--text3);}
.legend{display:flex;flex-wrap:wrap;gap:9px;margin-bottom:9px;}
.legend span{font-size:0.66rem;color:var(--text2);display:flex;align-items:center;gap:4px;font-family:var(--mono);}
.ldot{width:7px;height:7px;border-radius:1px;flex-shrink:0;}
#net-canvas{width:100%;display:block;border-radius:4px;cursor:grab;}
.reset-btn{font-family:var(--mono);font-size:0.65rem;padding:3px 10px;border-radius:3px;border:1px solid var(--border2);background:var(--bg3);color:var(--text2);cursor:pointer;}
.reset-btn:hover{color:var(--text);}
#node-popup{position:fixed;background:#1c2028;border:1px solid rgba(255,255,255,0.15);border-radius:6px;z-index:9999;display:none;min-width:160px;box-shadow:0 4px 20px rgba(0,0,0,0.6);overflow:hidden;}
.np-header{padding:8px 14px;border-bottom:1px solid rgba(255,255,255,0.08);}
.np-name{font-family:var(--mono);font-size:0.78rem;font-weight:500;}
.np-badge{font-family:var(--mono);font-size:0.6rem;padding:1px 6px;border-radius:2px;margin-left:6px;}
.np-links a{display:block;padding:8px 14px;font-family:var(--mono);font-size:0.7rem;color:var(--text2);text-decoration:none;}
.np-links a:hover{background:rgba(255,255,255,0.06);color:var(--text);}
</style>
</head>
<body>
<header>
  <div>
    <div class="h1">npm security analyzer &nbsp;/&nbsp; """ + project_name + """</div>
    <div class="hsub">packages: """ + str(pkg_count) + """ &nbsp;·&nbsp; edges: """ + str(edge_count) + """ &nbsp;·&nbsp; static: """ + str(total_static) + """건 &nbsp;·&nbsp; dynamic: """ + str(total_dynamic) + """건</div>
  </div>
  <div style="font-family:var(--mono);font-size:0.95rem;font-weight:500;padding:5px 18px;border-radius:3px;border:1px solid """ + verdict_color + """;color:""" + verdict_color + """;background:""" + verdict_bg + """;">""" + verdict + """</div>
</header>
<main>
  <div class="metrics">
    <div class="metric"><div class="mlabel">총 패키지</div><div class="mval v-acc">""" + str(pkg_count) + """</div><div class="msub">의존성 엣지 """ + str(edge_count) + """개</div></div>
    <div class="metric"><div class="mlabel">정적 탐지</div><div class="mval v-warn">""" + str(total_static) + """<span style="font-size:.9rem;color:var(--text2)">건</span></div><div class="msub">""" + str(static_pkgs) + """개 패키지</div></div>
    <div class="metric"><div class="mlabel">동적 행위</div><div class="mval v-purple">""" + str(total_dynamic) + """<span style="font-size:.9rem;color:var(--text2)">건</span></div><div class="msub">""" + str(dynamic_pkgs) + """개 패키지</div></div>
    <div class="metric" """ + ('style="border-color:rgba(226,75,74,0.35);"' if high else '') + """><div class="mlabel">HIGH 위험</div><div class="mval """ + ('v-high' if high else 'v-low') + """" style="font-size:1.2rem;">""" + str(len(high)) + """개</div><div class="msub">""" + ('수동 확인 필요' if high else '위험 없음') + """</div></div>
  </div>

  <div class="row2">
    <div class="card">
      <div class="ctitle"><span class="ctitle-l">1단계 · 메타데이터 분석</span></div>
      """ + step1_html + """
    </div>
    <div class="card">
      <div class="ctitle"><span class="ctitle-l">위험도 분포</span></div>
      <div class="legend">
        <span><span class="ldot" style="background:#E24B4A"></span>HIGH """ + str(len(high)) + """</span>
        <span><span class="ldot" style="background:#BA7517"></span>MEDIUM """ + str(len(medium)) + """</span>
        <span><span class="ldot" style="background:#1D9E75"></span>LOW """ + str(len(low)) + """</span>
      </div>
      <div class="donut-wrap" style="height:190px;position:relative;">
        <canvas id="donutChart"></canvas>
        <div class="donut-center"><div class="donut-num">""" + str(pkg_count) + """</div><div class="donut-sub">packages</div></div>
      </div>
    </div>
    <div class="card">
      <div class="ctitle"><span class="ctitle-l">HIGH 위험 패키지</span></div>
      """ + (high_cards_html if high_cards_html else '<div style="font-size:.76rem;color:var(--text2);text-align:center;padding:2rem 0;">위험 패키지 없음</div>') + """
    </div>
  </div>

  <div class="row3">
    <div class="card">
      <div class="ctitle"><span class="ctitle-l">2단계 · 정적 탐지 유형별</span></div>
      <div style="position:relative;width:100%;height:180px;"><canvas id="staticChart"></canvas></div>
    </div>
    <div class="card">
      <div class="ctitle"><span class="ctitle-l">3단계 · 동적 행위 유형별</span></div>
      <div style="position:relative;width:100%;height:180px;"><canvas id="dynChart"></canvas></div>
    </div>
  </div>

  <div class="card" style="margin-bottom:12px;">
    <div class="ctitle"><span class="ctitle-l">정적 탐지 상위 패키지 TOP 10</span></div>
    <div style="position:relative;width:100%;height:""" + str(max(200, len(top_labels)*32)) + """px;"><canvas id="topChart"></canvas></div>
  </div>

  <div class="card">
    <div class="ctitle">
      <span class="ctitle-l">의존성 그래프 · """ + str(pkg_count) + """개 노드 / """ + str(edge_count) + """개 엣지</span>
      <button class="reset-btn" id="net-reset">리셋</button>
    </div>
    <div class="legend">
      <span><span class="ldot" style="background:#888780"></span>루트</span>
      <span><span class="ldot" style="background:#4a80b5"></span>일반</span>
      <span><span class="ldot" style="background:#BA7517"></span>MEDIUM</span>
      <span><span class="ldot" style="background:#E24B4A"></span>HIGH</span>
      <span style="margin-left:auto;font-size:0.63rem;color:var(--text3);">빨강·주황 클릭: CVE 조회 &nbsp;·&nbsp; 휠: 줌 &nbsp;·&nbsp; 드래그: 이동</span>
    </div>
    <canvas id="net-canvas" height="600"></canvas>
  </div>
</main>

<div id="node-popup">
  <div class="np-header" id="np-header"></div>
  <div class="np-links" id="np-links"></div>
</div>

<script>
var gc='rgba(255,255,255,0.05)',tc='#7c8394';

new Chart(document.getElementById('donutChart'),{type:'doughnut',data:{labels:['HIGH','MEDIUM','LOW','UNKNOWN'],datasets:[{data:[""" + j_high + "," + j_medium + "," + j_low + "," + j_unknown + """],backgroundColor:['#E24B4A','#BA7517','#1D9E75','#7c8394'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,cutout:'68%',plugins:{legend:{display:false}}}});
new Chart(document.getElementById('staticChart'),{type:'bar',data:{labels:""" + j_slabels + """,datasets:[{data:""" + j_scounts + """,backgroundColor:""" + j_scolors + """,borderRadius:3,barThickness:22}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:gc},ticks:{color:tc,font:{size:11}}},y:{grid:{display:false},ticks:{color:tc,font:{size:11}}}}}});
new Chart(document.getElementById('dynChart'),{type:'bar',data:{labels:""" + j_dlabels + """,datasets:[{data:""" + j_dcounts + """,backgroundColor:""" + j_dcolors + """,borderRadius:3,barThickness:28}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:gc},ticks:{color:tc,font:{size:11}}},y:{grid:{display:false},ticks:{color:tc,font:{size:11}}}}}});
new Chart(document.getElementById('topChart'),{type:'bar',data:{labels:""" + j_tlabels + """,datasets:[{data:""" + j_tcounts + """,backgroundColor:""" + j_tcolors + """,borderRadius:3,barThickness:20}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:gc},ticks:{color:tc,font:{size:11}}},y:{grid:{display:false},ticks:{color:tc,font:{size:10}}}}}});

(function(){
  var canvas = document.getElementById('net-canvas');
  var ctx    = canvas.getContext('2d');
  var popup  = document.getElementById('node-popup');
  var npHdr  = document.getElementById('np-header');
  var npLnk  = document.getElementById('np-links');

  var W = canvas.offsetWidth || 1000;
  var H = 600;
  canvas.width  = W;
  canvas.height = H;

  var nodeData = """ + j_nodes + """;
  var edgeData = """ + j_edges + """;

  var idMap = {};
  for(var i=0;i<nodeData.length;i++) idMap[nodeData[i].id]=i;

  var seed=42;
  function rng(){seed=(seed*16807)%2147483647;return(seed-1)/2147483646;}

  var nodes=[];
  for(var i=0;i<nodeData.length;i++){
    var n=nodeData[i];
    var a=(i/nodeData.length)*Math.PI*2;
    var d=n.r>=12?0:60+rng()*220;
    nodes.push({name:n.name,color:n.color,r:n.r,
      x:n.r>=12?W/2:W/2+Math.cos(a)*d,
      y:n.r>=12?H/2:H/2+Math.sin(a)*d,
      vx:(rng()-0.5)*0.8,vy:(rng()-0.5)*0.8});
  }

  var edges=[];
  for(var i=0;i<edgeData.length;i++){
    var a=idMap[edgeData[i].from],b=idMap[edgeData[i].to];
    if(a!==undefined&&b!==undefined) edges.push([a,b]);
  }

  var scale=1,offX=0,offY=0;
  var panning=false,panX=0,panY=0;
  var dragN=null,dragDX=0,dragDY=0;
  var mdX=0,mdY=0,dragged=false;
  var animating=true,frameN=0;

  // 마우스 호버 월드 좌표 (반발력용)
  var mouseWX=null,mouseWY=null;

  function toCanvas(ex,ey){
    var r=canvas.getBoundingClientRect();
    var sx=canvas.width/r.width;
    var sy=canvas.height/r.height;
    return{x:(ex-r.left)*sx,y:(ey-r.top)*sy};
  }

  function toWorld(cx,cy){
    return{x:(cx-W/2-offX)/scale,y:(cy-H/2-offY)/scale};
  }

  function hitNode(wx,wy){
    for(var i=nodes.length-1;i>=0;i--){
      var n=nodes[i];
      var dx=n.x-wx,dy=n.y-wy;
      if(Math.sqrt(dx*dx+dy*dy)<n.r+5) return n;
    }
    return null;
  }

  function showPopup(n,sx,sy){
    var color=n.color==='#E24B4A'?'#E24B4A':'#BA7517';
    var label=n.color==='#E24B4A'?'HIGH':'MEDIUM';
    npHdr.innerHTML='<span class="np-name">'+n.name+'</span>'
      +'<span class="np-badge" style="background:'+color+'22;color:'+color+';border:1px solid '+color+'44;">'+label+'</span>';
    npLnk.innerHTML='<a href="https://osv.dev/list?q='+encodeURIComponent(n.name)+'" target="_blank">OSV.dev 검색 →</a>';
    popup.style.left=(sx+170>window.innerWidth?sx-170:sx+8)+'px';
    popup.style.top =(sy+120>window.innerHeight?sy-120:sy+8)+'px';
    popup.style.display='block';
  }

  document.addEventListener('mousedown',function(e){
    if(!popup.contains(e.target)&&e.target!==canvas) popup.style.display='none';
  });

  function draw(){
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle='#0c0e11';ctx.fillRect(0,0,W,H);
    ctx.save();
    ctx.translate(W/2+offX,H/2+offY);
    ctx.scale(scale,scale);
    ctx.globalAlpha=0.13;ctx.strokeStyle='#7c8394';ctx.lineWidth=0.7/scale;
    for(var i=0;i<edges.length;i++){
      ctx.beginPath();
      ctx.moveTo(nodes[edges[i][0]].x,nodes[edges[i][0]].y);
      ctx.lineTo(nodes[edges[i][1]].x,nodes[edges[i][1]].y);
      ctx.stroke();
    }
    ctx.globalAlpha=1;
    for(var i=0;i<nodes.length;i++){
      var n=nodes[i];
      ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
      ctx.fillStyle=n.color;ctx.globalAlpha=0.9;ctx.fill();ctx.globalAlpha=1;
      if(n.r>=5){ctx.strokeStyle='rgba(255,255,255,0.15)';ctx.lineWidth=1.2/scale;ctx.stroke();}
      var lt=0.5;
      if(scale>=lt||n.r>=9){
        var fs=Math.max(7,Math.min(11,9/scale));
        ctx.fillStyle=n.r>=9?'#f0f2f5':'#8090a8';
        ctx.font=(n.r>=9?'500 ':'400 ')+fs+'px monospace';
        ctx.textAlign='center';
        ctx.globalAlpha=Math.min(1,(scale-lt+0.4)*2.5);
        ctx.fillText(n.name.length>22?n.name.slice(0,21)+'...':n.name,n.x,n.y+n.r+fs+2);
        ctx.globalAlpha=1;
      }
    }
    ctx.restore();
  }

  // ── 시뮬레이션 — 마우스 반발력 추가 (약하게) ──────────────────────────────
  function simulate(){
    for(var i=0;i<nodes.length;i++){
      var n=nodes[i];
      if(n===dragN||n.r>=12) continue;
      n.x+=n.vx;n.y+=n.vy;
      var d=Math.sqrt(n.x*n.x+n.y*n.y);
      if(d>260){n.vx-=n.x/d*0.5;n.vy-=n.y/d*0.5;}

      n.vx*=0.97;n.vy*=0.97;
      n.vx+=(rng()-0.5)*0.05;n.vy+=(rng()-0.5)*0.05;
    }
  }

  function loop(){
    if(animating&&frameN<280){simulate();frameN++;}
    else animating=false;
    draw();
    requestAnimationFrame(loop);
  }
  loop();

  canvas.addEventListener('wheel',function(e){
    e.preventDefault();
    var c=toCanvas(e.clientX,e.clientY);
    var d=e.deltaY>0?0.85:1.18;
    var ns=Math.max(0.2,Math.min(8,scale*d));
    offX=c.x-W/2-(c.x-W/2-offX)*(ns/scale);
    offY=c.y-H/2-(c.y-H/2-offY)*(ns/scale);
    scale=ns;
  },{passive:false});

  canvas.addEventListener('mousedown',function(e){
    mdX=e.clientX;mdY=e.clientY;dragged=false;
    popup.style.display='none';
    var c=toCanvas(e.clientX,e.clientY);
    var w=toWorld(c.x,c.y);
    var hit=hitNode(w.x,w.y);
    // animating=false 제거 — 클릭해도 시뮬레이션 계속 동작
    if(hit){dragN=hit;dragDX=hit.x-w.x;dragDY=hit.y-w.y;}
    else{panning=true;panX=e.clientX-offX;panY=e.clientY-offY;}
  });

  canvas.addEventListener('mousemove',function(e){
    if(Math.abs(e.clientX-mdX)>8||Math.abs(e.clientY-mdY)>3) dragged=true;
    var c=toCanvas(e.clientX,e.clientY);
    var w=toWorld(c.x,c.y);

    // 마우스 월드 좌표 업데이트 + 시뮬레이션 재개
    mouseWX=w.x; mouseWY=w.y;
    if(!animating){animating=true; frameN=0;}

    if(dragN){dragN.x=w.x+dragDX;dragN.y=w.y+dragDY;return;}
    if(panning){offX=e.clientX-panX;offY=e.clientY-panY;return;}
    var hit=hitNode(w.x,w.y);
    canvas.style.cursor=hit?(hit.color==='#E24B4A'||hit.color==='#BA7517'?'pointer':'default'):'grab';
  });

  canvas.addEventListener('mouseup',function(e){
    var c=toCanvas(e.clientX,e.clientY);
    var w=toWorld(c.x,c.y);
    if(!dragged){
      var hit=hitNode(w.x,w.y);
      if(hit&&(hit.color==='#E24B4A'||hit.color==='#BA7517')){
        showPopup(hit,e.clientX,e.clientY);
      }
    }
    dragN=null;panning=false;
    canvas.style.cursor='grab';
  });

  canvas.addEventListener('mouseleave',function(){
    dragN=null;panning=false;
    // 마우스 벗어나면 반발력 제거
    mouseWX=null;mouseWY=null;
  });

  document.getElementById('net-reset').addEventListener('click',function(){
    scale=1;offX=0;offY=0;
  });
})();
</script>
</body>
</html>"""

    output_path = Path(project_dir) / "dashboard.html"
    with output_path.open("w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  대시보드 생성 완료 : {output_path}")

    os.chdir(str(output_path.parent))
    server_ready = threading.Event()

    def serve():
        handler = http.server.SimpleHTTPRequestHandler
        handler.log_message = lambda *args: None
        with http.server.HTTPServer(("", 8765), handler) as httpd:
            server_ready.set()
            httpd.serve_forever()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    server_ready.wait(timeout=3)

    try:
        subprocess.run([
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "--disable-extensions",
            "http://localhost:8765/dashboard.html"
        ])
    except Exception:
        subprocess.run(["open", "http://localhost:8765/dashboard.html"])

    print("  서버 실행 중... (Ctrl+C로 종료)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  서버 종료")

    return str(output_path)


def generate_dashboard_html(
    detection_results: Dict[str, Any],
    comparison_results: List[Dict[str, Any]],
    graph: Dict[str, Any],
    project_dir: str
) -> str:
    """HTML 파일만 생성하고 브라우저/서버는 실행하지 않음 (웹 UI용)"""
    output_path = Path(project_dir) / "dashboard.html"

    class StopServer(Exception):
        pass

    original_chdir = os.chdir
    def patched_chdir(path):
        original_chdir(path)
        raise StopServer()

    os.chdir = patched_chdir
    try:
        generate_dashboard(detection_results, comparison_results, graph, project_dir)
    except StopServer:
        pass
    finally:
        os.chdir = original_chdir

    return str(output_path)
