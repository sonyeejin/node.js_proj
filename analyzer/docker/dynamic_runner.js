"use strict";

/**
 * dynamic_runner.js
 *
 * Docker 컨테이너 안에서 실행되는 동적 분석기.
 * Node.js 핵심 모듈을 후킹하여 패키지 실행 중 발생하는 실제 행위를 수집한다.
 *
 * 실행 방식:
 *   node dynamic_runner.js <패키지_경로>
 *
 * 마운트 구조:
 *   /pkg          → 분석 대상 패키지 (읽기 전용)
 *   /node_modules → 전체 node_modules (의존성 해결용, 읽기 전용)
 */

const fs     = require("fs");
const path   = require("path");
const Module = require("module");

// ─── 분석 결과 저장소 ─────────────────────────────────────────────────────────

const findings = {
  network:           [],
  filesystem:        [],
  process_execution: [],
  env_access:        [],
  errors:            [],
  metadata: {
    package:          null,
    version:          null,
    start_time:       new Date().toISOString(),
    end_time:         null,
    analysis_timeout: false
  }
};

const seen = {
  network:           new Set(),
  filesystem:        new Set(),
  process_execution: new Set(),
  env_access:        new Set()
};

function dedup(category, key, item) {
  if (seen[category].has(key)) return;
  seen[category].add(key);
  findings[category].push(item);
}

function getTimestamp() {
  return new Date().toISOString();
}

// ─── 패키지 정보 로드 ─────────────────────────────────────────────────────────

function loadPackageInfo(packagePath) {
  const pkgJsonPath = path.join(packagePath, "package.json");
  try {
    const raw = fs.readFileSync(pkgJsonPath, "utf-8");
    const pkg = JSON.parse(raw);
    findings.metadata.package = pkg.name || path.basename(packagePath);
    findings.metadata.version = pkg.version || "unknown";
    return pkg;
  } catch (_) {
    findings.metadata.package = path.basename(packagePath);
    findings.metadata.version = "unknown";
    return null;
  }
}

// ─── 후킹: http / https ───────────────────────────────────────────────────────
// [수정] Module._load 방식 대신 모듈 캐시를 직접 교체하는 방식으로 변경
// → 패키지가 require("http") 할 때 반드시 후킹된 버전을 받도록 보장

function buildHttpHook(moduleName) {
  const original = require(moduleName);

  function interceptRequest(method, args) {
    let url = "";
    const firstArg = args[0];

    if (typeof firstArg === "string") {
      url = firstArg;
    } else if (firstArg && typeof firstArg === "object") {
      const protocol = firstArg.protocol || `${moduleName}:`;
      const host     = firstArg.hostname || firstArg.host || "";
      const port     = firstArg.port ? `:${firstArg.port}` : "";
      const p        = firstArg.path || "/";
      url = `${protocol}//${host}${port}${p}`;
    }

    dedup("network", `${method}:${url}`, {
      type:      "http_request",
      method,
      url,
      module:    moduleName,
      timestamp: getTimestamp()
    });
  }

  // 원본 객체에 직접 메서드만 덮어쓰기
  // Object.create 방식은 EventEmitter 기반 http 모듈 내부 상태를 깨뜨릴 수 있음
  const originalGet     = original.get.bind(original);
  const originalRequest = original.request.bind(original);

  original.get = function(...args) {
    interceptRequest("GET", args);
    return originalGet.apply(this, args);
  };

  original.request = function(...args) {
    interceptRequest("REQUEST", args);
    return originalRequest.apply(this, args);
  };

  return original;
}

function hookHttpModules() {
  // http/https를 먼저 require해서 캐시에 올린 뒤 exports 교체
  ["http", "https"].forEach(moduleName => {
    try {
      require(moduleName); // 캐시에 올리기
      const cacheKey = require.resolve(moduleName);
      if (require.cache[cacheKey]) {
        require.cache[cacheKey].exports = buildHttpHook(moduleName);
      }
    } catch (_) {}
  });
}

// ─── 후킹: fs ────────────────────────────────────────────────────────────────

function hookFs(packagePath) {
  const originalFs = require("fs");

  const FS_HOOKS = {
    readFileSync:  { argIndex: 0, action: "read" },
    writeFileSync: { argIndex: 0, action: "write" },
    appendFileSync:{ argIndex: 0, action: "append" },
    unlinkSync:    { argIndex: 0, action: "delete" },
    readFile:      { argIndex: 0, action: "read" },
    writeFile:     { argIndex: 0, action: "write" },
    appendFile:    { argIndex: 0, action: "append" },
    unlink:        { argIndex: 0, action: "delete" },
    existsSync:    { argIndex: 0, action: "exists_check" },
    mkdirSync:     { argIndex: 0, action: "mkdir" },
    mkdir:         { argIndex: 0, action: "mkdir" },
    readdirSync:   { argIndex: 0, action: "readdir" },
    copyFileSync:  { argIndex: 0, action: "copy" },
  };

  // [수정] 제외 경로 강화
  // - /analysis: 분석기 자체 경로
  // - /proc /sys /dev: 시스템 경로
  // - /node_modules: 의존성 로드 (정상 동작)
  // - packagePath 자체의 단순 읽기는 제외하고 쓰기/삭제만 기록
  const EXCLUDED_PREFIXES = ["/analysis", "/proc", "/sys", "/dev", "/node_modules"];

  function shouldExclude(filePath, action) {
    if (typeof filePath !== "string") return true;
    if (EXCLUDED_PREFIXES.some(ep => filePath.startsWith(ep))) return true;

    // 패키지 내부 파일 읽기는 제외 (단순 모듈 로드 노이즈)
    // 쓰기/삭제/mkdir은 패키지 경로여도 기록 (실제 악성 행위 가능성)
    if (filePath.startsWith("/pkg") && action === "read") return true;
    if (filePath.startsWith("/pkg") && action === "exists_check") return true;
    if (filePath.startsWith("/pkg") && action === "readdir") return true;

    return false;
  }

  for (const [funcName, { argIndex, action }] of Object.entries(FS_HOOKS)) {
    const original = originalFs[funcName];
    if (typeof original !== "function") continue;

    originalFs[funcName] = function(...args) {
      const targetPath = args[argIndex];
      if (!shouldExclude(targetPath, action)) {
        dedup("filesystem", `${action}:${targetPath}`, {
          action,
          path:      targetPath,
          timestamp: getTimestamp()
        });
      }
      return original.apply(originalFs, args);
    };
  }
}

// ─── 후킹: child_process ─────────────────────────────────────────────────────

function hookChildProcess() {
  const originalCp = require("child_process");
  const CP_HOOKS   = ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"];

  for (const funcName of CP_HOOKS) {
    const original = originalCp[funcName];
    if (typeof original !== "function") continue;

    originalCp[funcName] = function(...args) {
      const command = typeof args[0] === "string" ? args[0] : JSON.stringify(args[0]);
      const cmdArgs = Array.isArray(args[1]) ? args[1].join(" ") : "";

      dedup("process_execution", `${funcName}:${command}`, {
        function:  funcName,
        command,
        args:      cmdArgs,
        timestamp: getTimestamp()
      });

      return original.apply(originalCp, args);
    };
  }
}

// ─── 후킹: process.env ───────────────────────────────────────────────────────

function hookProcessEnv() {
  const originalEnv = process.env;

  // [수정] Docker 컨테이너 기본 env + npm 내부 env 필터 강화
  const NOISE_ENVS = new Set([
    "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "PWD", "OLDPWD",
    "NODE_ENV", "NODE_PATH", "NODE_VERSION", "NODE_V8_COVERAGE",
    "npm_lifecycle_event", "npm_package_name", "npm_package_version",
    "npm_config_cache", "npm_execpath", "npm_node_execpath",
    "HOSTNAME", "YARN_VERSION",                    // Docker 기본 env
    "npm_config_user_agent", "npm_command"
  ]);

  process.env = new Proxy(originalEnv, {
    get(target, prop) {
      if (typeof prop !== "string") return target[prop];

      if (!NOISE_ENVS.has(prop)) {
        dedup("env_access", prop, {
          key:          prop,
          value_exists: prop in target,
          timestamp:    getTimestamp()
        });
      }

      return target[prop];
    }
  });
}

// ─── Node.js 모듈 경로 설정 ──────────────────────────────────────────────────
// /node_modules를 마운트했을 때 패키지가 의존성을 찾을 수 있도록 경로 추가

function setupModulePaths() {
  // Node.js가 모듈을 탐색하는 경로 목록에 /node_modules 추가
  if (!Module.globalPaths.includes("/node_modules")) {
    Module.globalPaths.unshift("/node_modules");
  }

  // 현재 프로세스의 모듈 경로에도 추가
  process.env.NODE_PATH = "/node_modules" + (process.env.NODE_PATH ? ":" + process.env.NODE_PATH : "");
  Module._initPaths();
}

// ─── install script 실행 ─────────────────────────────────────────────────────

function runInstallScript(pkg, packagePath) {
  if (!pkg || !pkg.scripts) return;

  const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];

  for (const scriptName of INSTALL_SCRIPTS) {
    const script = pkg.scripts[scriptName];
    if (!script) continue;

    try {
      const { execSync } = require("child_process");
      execSync(script, {
        cwd:     packagePath,
        timeout: 10000,
        stdio:   "pipe",
        env: {
          ...process.env,
          PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          NODE_PATH: "/node_modules"
        }
      });
    } catch (err) {
      findings.errors.push({
        type:      "install_script_error",
        script:    scriptName,
        command:   script,
        message:   err.message?.split("\n")[0] || "unknown error", // 첫 줄만 저장
        timestamp: getTimestamp()
      });
    }
  }
}

// ─── 메인 모듈 실행 ───────────────────────────────────────────────────────────
// [수정] exports 필드 (ESM) 및 다양한 진입점 후보를 순서대로 시도

function resolveMainEntry(pkg, packagePath) {
  const candidates = [];

  // exports 필드에서 문자열 진입점만 추출하는 헬퍼
  function extractStringEntry(value) {
    if (typeof value === "string") return value;
    if (value && typeof value === "object") {
      // 우선순위: require > node > default
      for (const key of ["require", "node", "default"]) {
        const v = extractStringEntry(value[key]);
        if (v) return v;
      }
    }
    return null;
  }

  // 1순위: exports 필드
  if (pkg?.exports) {
    const exp = pkg.exports;
    let entry = null;

    if (typeof exp === "string") {
      entry = exp;
    } else if (exp["."]) {
      entry = extractStringEntry(exp["."]);
    } else {
      entry = extractStringEntry(exp);
    }

    if (entry) candidates.push(entry);
  }

  // 2순위: main 필드
  if (pkg?.main) candidates.push(pkg.main);

  // 3순위: 기본 파일명 후보
  candidates.push("index.js", "index.cjs", "index.mjs");

  for (const candidate of candidates) {
    const resolved = path.resolve(packagePath, candidate);
    if (fs.existsSync(resolved)) return resolved;
  }

  return null;
}

function runMainModule(pkg, packagePath) {
  const mainPath = resolveMainEntry(pkg, packagePath);

  if (!mainPath) {
    findings.errors.push({
      type:      "main_not_found",
      tried:     ["exports", pkg?.main, "index.js"].filter(Boolean),
      timestamp: getTimestamp()
    });
    return;
  }

  try {
    require(mainPath);
  } catch (err) {
    findings.errors.push({
      type:      "runtime_error",
      path:      mainPath,
      message:   err.message?.split("\n")[0] || "unknown error",
      timestamp: getTimestamp()
    });
  }
}

// ─── 진입점 ──────────────────────────────────────────────────────────────────

async function main() {
  const packagePath = process.argv[2];

  if (!packagePath) {
    console.error(JSON.stringify({ error: "package_path argument is required" }));
    process.exit(1);
  }

  if (!fs.existsSync(packagePath)) {
    console.error(JSON.stringify({ error: `Package path not found: ${packagePath}` }));
    process.exit(1);
  }

  const TIMEOUT_MS = 30000;
  const timeoutHandle = setTimeout(() => {
    findings.metadata.analysis_timeout = true;
    findings.metadata.end_time = getTimestamp();
    console.log(JSON.stringify(findings, null, 2));
    process.exit(0);
  }, TIMEOUT_MS);

  try {
    // 1. 의존성 경로 설정
    setupModulePaths();

    // 2. 후킹 먼저 적용 (loadPackageInfo 포함 모든 실행 전에 후킹 완료)
    hookFs(packagePath);
    hookChildProcess();
    hookProcessEnv();
    hookHttpModules();

    // 3. 패키지 정보 로드 (후킹 완료 후 실행)
    const pkg = loadPackageInfo(packagePath);

    // 4. install script 실행
    runInstallScript(pkg, packagePath);

    // 5. 메인 모듈 실행
    runMainModule(pkg, packagePath);

    // 6. 비동기 작업 완료 대기
    await new Promise(resolve => setTimeout(resolve, 1000)); // [성능] 3초 → 1초

  } catch (err) {
    findings.errors.push({
      type:      "analysis_error",
      message:   err.message,
      timestamp: getTimestamp()
    });
  } finally {
    clearTimeout(timeoutHandle);
    findings.metadata.end_time = getTimestamp();
    console.log(JSON.stringify(findings, null, 2));
  }
}

main();
