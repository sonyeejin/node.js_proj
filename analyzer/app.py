"""
app.py — npm 패키지 보안 분석 시스템 웹 UI
실행: python3 app.py
접속: http://localhost:5000
"""

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

app = Flask(__name__)

# 분석 로그 큐 (스레드 간 통신)
log_queue: queue.Queue = queue.Queue()
analysis_done = threading.Event()
analysis_result = {"status": "idle", "project_dir": ""}

# ── HTML 템플릿 ──────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>npm security analyzer</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Noto+Sans+KR:wght@300;400;500&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  :root{
    --bg:#0c0e11;--bg2:#13161c;--bg3:#1c2028;
    --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.13);
    --text:#dde1ea;--text2:#7c8394;--text3:#3e4450;
    --mono:'IBM Plex Mono',monospace;--sans:'Noto Sans KR',sans-serif;
    --acc:#378ADD;--high:#E24B4A;--low:#1D9E75;--warn:#BA7517;
  }
  body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;display:flex;flex-direction:column;}
  header{padding:1.2rem 2rem;border-bottom:1px solid var(--border);background:var(--bg2);display:flex;align-items:center;gap:12px;}
  .logo{font-family:var(--mono);font-size:1rem;font-weight:500;color:var(--acc);}
  .logo span{color:var(--text2);}
  main{flex:1;display:flex;align-items:center;justify-content:center;padding:2rem;}

  /* 입력 화면 */
  .input-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:2.5rem;width:100%;max-width:560px;}
  .input-title{font-family:var(--mono);font-size:1.1rem;font-weight:500;color:var(--text);margin-bottom:8px;}
  .input-sub{font-size:0.78rem;color:var(--text2);margin-bottom:2rem;line-height:1.6;}
  .input-label{font-family:var(--mono);font-size:0.72rem;color:var(--text2);letter-spacing:0.06em;text-transform:uppercase;margin-bottom:8px;display:block;}
  .input-field{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:4px;padding:10px 14px;font-family:var(--mono);font-size:0.85rem;color:var(--text);outline:none;transition:border-color 0.15s;}
  .input-field:focus{border-color:var(--acc);}
  .btn-primary{width:100%;margin-top:1.2rem;padding:11px;background:var(--acc);border:none;border-radius:4px;font-family:var(--mono);font-size:0.85rem;font-weight:500;color:#fff;cursor:pointer;transition:opacity 0.15s;}
  .btn-primary:hover{opacity:0.85;}
  .btn-primary:disabled{opacity:0.4;cursor:not-allowed;}

  /* 분석 화면 */
  .analysis-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;width:100%;max-width:860px;overflow:hidden;display:none;}
  .analysis-header{padding:1.2rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
  .analysis-title{font-family:var(--mono);font-size:0.9rem;font-weight:500;color:var(--text);}
  .status-badge{font-family:var(--mono);font-size:0.7rem;padding:3px 10px;border-radius:2px;border:1px solid;}
  .status-running{color:var(--acc);border-color:var(--acc);background:rgba(55,138,221,0.1);}
  .status-done{color:var(--low);border-color:var(--low);background:rgba(29,158,117,0.1);}
  .status-error{color:var(--high);border-color:var(--high);background:rgba(226,75,74,0.1);}
  .log-area{padding:1.2rem 1.5rem;height:420px;overflow-y:auto;font-family:var(--mono);font-size:0.78rem;line-height:1.7;background:var(--bg);}
  .log-line{margin-bottom:2px;}
  .log-ok{color:var(--low);}
  .log-warn{color:var(--warn);}
  .log-high{color:var(--high);}
  .log-info{color:var(--text2);}
  .log-default{color:var(--text);}
  .analysis-footer{padding:1rem 1.5rem;border-top:1px solid var(--border);display:flex;gap:10px;}
  .btn-dashboard{padding:9px 20px;background:var(--low);border:none;border-radius:4px;font-family:var(--mono);font-size:0.8rem;font-weight:500;color:#fff;cursor:pointer;display:none;}
  .btn-dashboard:hover{opacity:0.85;}
  .btn-reset{padding:9px 20px;background:transparent;border:1px solid var(--border2);border-radius:4px;font-family:var(--mono);font-size:0.8rem;color:var(--text2);cursor:pointer;}
  .btn-reset:hover{color:var(--text);}

  /* 스피너 */
  .spinner{width:14px;height:14px;border:2px solid rgba(55,138,221,0.3);border-top-color:var(--acc);border-radius:50%;animation:spin 0.7s linear infinite;display:inline-block;margin-right:8px;vertical-align:middle;}
  @keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
<header>
  <div class="logo">npm security analyzer <span>/ web ui</span></div>
</header>
<main>

  <!-- 입력 화면 -->
  <div class="input-card" id="inputCard">
    <div class="input-title">Node.js 패키지 보안 분석</div>
    <div class="input-sub">분석할 Node.js 프로젝트 경로를 입력하세요.<br>package-lock.json과 node_modules가 있는 폴더여야 합니다.</div>
    <label class="input-label">프로젝트 경로</label>
    <input class="input-field" id="projectPath" type="text" placeholder="../test_projects/sample-app" value="../test_projects/sample-app">
    <button class="btn-primary" id="startBtn" onclick="startAnalysis()">분석 시작</button>
  </div>

  <!-- 분석 화면 -->
  <div class="analysis-card" id="analysisCard">
    <div class="analysis-header">
      <div class="analysis-title" id="analysisTitle">분석 중...</div>
      <span class="status-badge status-running" id="statusBadge"><span class="spinner"></span>실행 중</span>
    </div>
    <div class="log-area" id="logArea"></div>
    <div class="analysis-footer">
      <button class="btn-dashboard" id="dashboardBtn" onclick="openDashboard()">대시보드 열기</button>
      <button class="btn-reset" onclick="resetUI()">다시 분석</button>
    </div>
  </div>

</main>
<script>
var projectDir = '';
var eventSource = null;

function startAnalysis() {
  var path = document.getElementById('projectPath').value.trim();
  if (!path) { alert('프로젝트 경로를 입력해주세요.'); return; }

  projectDir = path;
  document.getElementById('inputCard').style.display = 'none';
  document.getElementById('analysisCard').style.display = 'block';
  document.getElementById('analysisTitle').textContent = path + ' 분석 중...';
  document.getElementById('logArea').innerHTML = '';
  document.getElementById('dashboardBtn').style.display = 'none';
  document.getElementById('statusBadge').className = 'status-badge status-running';
  document.getElementById('statusBadge').innerHTML = '<span class="spinner"></span>실행 중';

  // 분석 시작 요청
  fetch('/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({project_dir: path})
  });

  // 로그 스트리밍
  eventSource = new EventSource('/logs');
  eventSource.onmessage = function(e) {
    var data = JSON.parse(e.data);
    if (data.type === 'done') {
      eventSource.close();
      document.getElementById('statusBadge').className = 'status-badge status-done';
      document.getElementById('statusBadge').innerHTML = '완료';
      document.getElementById('analysisTitle').textContent = path + ' 분석 완료';
      document.getElementById('dashboardBtn').style.display = 'block';
    } else if (data.type === 'error') {
      eventSource.close();
      document.getElementById('statusBadge').className = 'status-badge status-error';
      document.getElementById('statusBadge').innerHTML = '오류';
    } else {
      appendLog(data.text);
    }
  };
}

function appendLog(text) {
  var area = document.getElementById('logArea');
  var div = document.createElement('div');
  div.className = 'log-line ' + getLogClass(text);
  div.textContent = text;
  area.appendChild(div);
  area.scrollTop = area.scrollHeight;
}

function getLogClass(text) {
  if (text.includes('[OK]') || text.includes('이상 없음') || text.includes('안전')) return 'log-ok';
  if (text.includes('[!!]') || text.includes('[위험]')) return 'log-high';
  if (text.includes('[주의]')) return 'log-warn';
  if (text.includes('-  ') || text.includes('=====')) return 'log-info';
  return 'log-default';
}

function openDashboard() {
  window.open('/dashboard', '_blank');
}

function resetUI() {
  if (eventSource) { eventSource.close(); eventSource = null; }
  document.getElementById('analysisCard').style.display = 'none';
  document.getElementById('inputCard').style.display = 'block';
}
</script>
</body>
</html>"""


# ── Flask 라우트 ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/start", methods=["POST"])
def start():
    data = request.get_json()
    project_dir = data.get("project_dir", "").strip()

    if not project_dir:
        return jsonify({"error": "project_dir required"}), 400

    analysis_result["status"] = "running"
    analysis_result["project_dir"] = project_dir
    analysis_done.clear()

    # 큐 비우기
    while not log_queue.empty():
        try: log_queue.get_nowait()
        except: break

    # 분석 스레드 실행
    t = threading.Thread(target=run_analysis, args=(project_dir,), daemon=True)
    t.start()

    return jsonify({"status": "started"})


@app.route("/logs")
def logs():
    """Server-Sent Events로 실시간 로그 스트리밍"""
    def generate():
        while True:
            try:
                item = log_queue.get(timeout=30)
                if item is None:  # 종료 신호
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                elif isinstance(item, dict) and item.get('type') == 'error':
                    yield f"data: {json.dumps(item)}\n\n"
                    break
                else:
                    yield f"data: {json.dumps({'type': 'log', 'text': item})}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/dashboard")
def dashboard():
    """생성된 dashboard.html 반환"""
    project_dir = analysis_result.get("project_dir", "")
    if not project_dir:
        return "분석을 먼저 실행해주세요.", 400

    dashboard_path = Path(project_dir) / "dashboard.html"
    if not dashboard_path.exists():
        return "dashboard.html을 찾을 수 없습니다.", 404

    return dashboard_path.read_text(encoding="utf-8")


# ── 분석 실행 ─────────────────────────────────────────────────────────────────

def run_analysis(project_dir: str):
    """별도 스레드에서 main.py 로직 실행 후 로그를 큐에 넣음"""
    try:
        analyzer_dir = Path(__file__).resolve().parent

        proc = subprocess.Popen(
            [sys.executable, str(analyzer_dir / "main_cli.py"), project_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(analyzer_dir)
        )

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log_queue.put(line)

        proc.wait()

        if proc.returncode == 0:
            log_queue.put(None)  # 완료
        else:
            log_queue.put({"type": "error", "text": f"분석 실패 (exit code: {proc.returncode})"})

    except Exception as e:
        log_queue.put({"type": "error", "text": str(e)})


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  npm security analyzer — Web UI")
    print("  http://localhost:5001 에서 접속하세요")
    print("="*50 + "\n")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
