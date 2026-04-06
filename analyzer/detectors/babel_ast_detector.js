const fs = require("fs");
const path = require("path");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

// ─── 상수 정의 ───────────────────────────────────────────────────────────────

const JS_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx"]);

const CHILD_PROCESS_FUNCS = new Set([
  "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"
]);

const HTTP_MODULES = new Set(["http", "https"]);

const SYSTEM_INFO_OS_FUNCS = new Set([
  "userInfo", "hostname", "networkInterfaces", "cpus", "totalmem", "freemem", "platform", "arch"
]);

const SENSITIVE_PROCESS_PROPS = new Set([
  "argv", "platform", "arch", "pid", "ppid", "uid", "gid", "cwd"
]);

const HTTP_CLIENT_METHODS = new Set(["get", "post", "put", "patch", "delete", "request"]);
const KNOWN_HTTP_CLIENTS = new Set(["axios", "got", "superagent", "needle", "request", "node-fetch"]);

// 난독화에 자주 쓰이는 인코딩/디코딩 패턴
const OBFUSCATION_PATTERNS = new Set([
  "Buffer.from",
  "String.fromCharCode",
  "atob",
  "btoa"
]);

const EXCLUDED_DIR_NAMES = new Set([
  "test", "tests", "__tests__", "coverage"
]);

// [성능] 1MB 초과 파일 스킵 (번들된 대형 파일 제외)
const MAX_FILE_SIZE = 1024 * 1024;

// ─── 경로 필터 ────────────────────────────────────────────────────────────────

function shouldExcludePath(fullPath) {
  const normalized = fullPath.split(path.sep).join("/");
  return (
    normalized.includes("/test/") ||
    normalized.includes("/tests/") ||
    normalized.includes("/__tests__/") ||
    normalized.includes("/coverage/")
  );
}

// ─── 파일 수집 ────────────────────────────────────────────────────────────────
// [성능 개선] 재귀 대신 스택 기반 반복 탐색 → 콜스택 깊이 제한 방지

function collectJsFiles(projectDir) {
  const results = [];
  const stack = [projectDir];

  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;

    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_) {
      continue; // 권한 없는 디렉토리 스킵
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (EXCLUDED_DIR_NAMES.has(entry.name)) continue;
        if (shouldExcludePath(fullPath)) continue;
        stack.push(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (!JS_EXTENSIONS.has(ext)) continue;
        if (!fullPath.split(path.sep).includes("node_modules")) continue;
        if (shouldExcludePath(fullPath)) continue;
        results.push(fullPath);
      }
    }
  }

  return results;
}

// ─── AST 유틸 ─────────────────────────────────────────────────────────────────

function getMemberName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    const obj = getMemberName(node.object);
    const prop = getMemberName(node.property);
    if (obj && prop) return `${obj}.${prop}`;
    return obj || prop;
  }
  return "";
}

function isRequireOf(node, moduleName) {
  if (!node) return false;
  if (node.type !== "CallExpression") return false;
  if (!node.callee || node.callee.type !== "Identifier") return false;
  if (node.callee.name !== "require") return false;
  if (!node.arguments || node.arguments.length === 0) return false;
  const first = node.arguments[0];
  return first.type === "StringLiteral" && first.value === moduleName;
}

function isDynamicRequire(node) {
  if (!node) return false;
  if (node.type !== "CallExpression") return false;
  if (!node.callee || node.callee.type !== "Identifier") return false;
  if (node.callee.name !== "require") return false;
  if (!node.arguments || node.arguments.length === 0) return false;
  const first = node.arguments[0];
  return first.type !== "StringLiteral";
}

// ─── 모듈 바인딩 추적 ─────────────────────────────────────────────────────────

function extractModuleBindings(ast) {
  const childProcessObjects = new Set();
  const childProcessDirectFuncs = new Set();
  const httpObjects = new Set();
  const osObjects = new Set();

  traverse(ast, {
    VariableDeclarator(nodePath) {
      const node = nodePath.node;

      if (isRequireOf(node.init, "child_process")) {
        const id = node.id;
        if (id.type === "Identifier") {
          childProcessObjects.add(id.name);
        } else if (id.type === "ObjectPattern") {
          for (const prop of id.properties) {
            if (prop.type !== "ObjectProperty") continue;
            if (prop.key.type !== "Identifier") continue;
            const importedName = prop.key.name;
            if (!CHILD_PROCESS_FUNCS.has(importedName)) continue;
            const localName = (prop.value && prop.value.type === "Identifier")
              ? prop.value.name : importedName;
            childProcessDirectFuncs.add(localName);
          }
        }
      }

      if (isRequireOf(node.init, "http") && node.id.type === "Identifier") httpObjects.add(node.id.name);
      if (isRequireOf(node.init, "https") && node.id.type === "Identifier") httpObjects.add(node.id.name);
      if (isRequireOf(node.init, "os") && node.id.type === "Identifier") osObjects.add(node.id.name);
    },

    ImportDeclaration(nodePath) {
      const node = nodePath.node;
      const source = node.source?.value;
      if (!source || typeof source !== "string") return;

      for (const specifier of node.specifiers) {
        if (source === "child_process") {
          if (
            specifier.type === "ImportNamespaceSpecifier" ||
            specifier.type === "ImportDefaultSpecifier"
          ) {
            childProcessObjects.add(specifier.local.name);
          } else if (specifier.type === "ImportSpecifier") {
            const importedName = specifier.imported?.name;
            if (importedName && CHILD_PROCESS_FUNCS.has(importedName)) {
              childProcessDirectFuncs.add(specifier.local.name);
            }
          }
        }

        if (
          HTTP_MODULES.has(source) &&
          (specifier.type === "ImportNamespaceSpecifier" ||
            specifier.type === "ImportDefaultSpecifier")
        ) {
          httpObjects.add(specifier.local.name);
        }

        if (
          source === "os" &&
          (specifier.type === "ImportNamespaceSpecifier" ||
            specifier.type === "ImportDefaultSpecifier")
        ) {
          osObjects.add(specifier.local.name);
        }
      }
    }
  });

  return { childProcessObjects, childProcessDirectFuncs, httpObjects, osObjects };
}

// ─── 난독화 서브트리 탐지 ─────────────────────────────────────────────────────

function findObfuscationInNode(node) {
  const found = [];
  traverse(node, {
    noScope: true,
    CallExpression(innerPath) {
      const calleeName = getMemberName(innerPath.node.callee);
      if (OBFUSCATION_PATTERNS.has(calleeName)) found.push(calleeName);
    }
  });
  return found;
}

// ─── 후처리 ──────────────────────────────────────────────────────────────────

function deduplicateFindings(findings) {
  const seen = new Set();
  const unique = [];
  for (const item of findings) {
    const key = JSON.stringify([item.file, item.line, item.type, item.subtype || "", item.pattern, item.description]);
    if (!seen.has(key)) { seen.add(key); unique.push(item); }
  }
  return unique;
}

function filterRedundantProcessEnv(findings) {
  const grouped = new Map();
  for (const item of findings) {
    const key = JSON.stringify([item.file, item.line, item.type]);
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(item);
  }

  const filtered = [];
  for (const items of grouped.values()) {
    const hasSpecificEnv = items.some(
      (item) => typeof item.pattern === "string" && item.pattern.startsWith("process.env.")
    );
    for (const item of items) {
      if (hasSpecificEnv && item.pattern === "process.env") continue;
      filtered.push(item);
    }
  }
  return filtered;
}

// ─── 패키지 정보 추출 ─────────────────────────────────────────────────────────

function getPackageRootInfo(filePath) {
  const normalized = filePath.split(path.sep);
  const nodeModulesIndex = normalized.lastIndexOf("node_modules");
  if (nodeModulesIndex === -1 || nodeModulesIndex === normalized.length - 1) return null;

  let packageName = normalized[nodeModulesIndex + 1];
  let packageRootParts;

  if (packageName && packageName.startsWith("@")) {
    const scopeName = normalized[nodeModulesIndex + 2];
    if (!scopeName) return null;
    packageName = `${packageName}/${scopeName}`;
    packageRootParts = normalized.slice(0, nodeModulesIndex + 3);
  } else {
    packageRootParts = normalized.slice(0, nodeModulesIndex + 2);
  }

  const packageRoot = packageRootParts.join(path.sep);
  const relativeFile = path.relative(packageRoot, filePath).split(path.sep).join("/");

  let version = "unknown";
  const packageJsonPath = path.join(packageRoot, "package.json");
  try {
    if (fs.existsSync(packageJsonPath)) {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
      version = pkg.version || version;
      packageName = pkg.name || packageName;
    }
  } catch (_) {}

  return { package: packageName, version, packageRoot, relativeFile };
}

// ─── 핵심: 파일 단위 분석 ────────────────────────────────────────────────────

function analyzeFile(filePath) {
  const findings = [];
  const parseErrors = [];
  const packageInfo = getPackageRootInfo(filePath);

  function addFinding(obj) {
    findings.push({ file: packageInfo ? packageInfo.relativeFile : filePath, ...obj });
  }

  // [성능] 파일 크기 체크 - 1MB 초과 스킵
  let code;
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      return { packageInfo, findings: [], parse_errors: [] };
    }
    code = fs.readFileSync(filePath, "utf-8");
  } catch (error) {
    parseErrors.push({
      file: packageInfo ? packageInfo.relativeFile : filePath,
      type: "read_error",
      pattern: "file read failed",
      description: error.message
    });
    return { packageInfo, findings: [], parse_errors: parseErrors };
  }

  try {
    const ast = parser.parse(code, {
      sourceType: "unambiguous",
      plugins: [
        "jsx", "typescript",
        "classProperties", "classPrivateProperties", "classPrivateMethods",
        "optionalChaining", "nullishCoalescingOperator",
        "dynamicImport", "objectRestSpread", "topLevelAwait"
      ],
      errorRecovery: true
    });

    if (ast.errors && ast.errors.length > 0) {
      for (const err of ast.errors) {
        parseErrors.push({
          file: packageInfo ? packageInfo.relativeFile : filePath,
          type: "parse_warning",
          pattern: "AST parse warning",
          description: err.message || String(err)
        });
      }
    }

    const { childProcessObjects, childProcessDirectFuncs, httpObjects, osObjects }
      = extractModuleBindings(ast);

    traverse(ast, {

      // ── [1~11] CallExpression ────────────────────────────────────────────
      CallExpression(nodePath) {
        const node = nodePath.node;
        const calleeName = getMemberName(node.callee);
        const line = node.loc?.start?.line ?? null;

        // [1] eval()
        if (calleeName === "eval") {
          addFinding({ line, type: "dynamic_execution", subtype: "eval", pattern: "eval(...)", description: "동적 코드 실행" });
          const firstArg = node.arguments?.[0];
          if (firstArg) {
            for (const pat of findObfuscationInNode(firstArg)) {
              addFinding({ line, type: "dynamic_execution", subtype: "obfuscated_eval", pattern: `eval(${pat}(...))`, description: `${pat} 기반 복원 후 eval 실행 의심 (난독화)` });
            }
          }
        }

        // [2] Function()
        if (node.callee?.type === "Identifier" && node.callee.name === "Function") {
          addFinding({ line, type: "dynamic_execution", subtype: "Function_constructor", pattern: "Function(...)", description: "Function 생성자를 통한 동적 코드 실행 가능" });
        }

        // [3] setTimeout / setInterval
        if ((calleeName === "setTimeout" || calleeName === "setInterval") && node.arguments?.length > 0) {
          const firstArg = node.arguments[0];
          if (firstArg.type === "StringLiteral") {
            addFinding({ line, type: "dynamic_execution", subtype: "string_timer", pattern: `${calleeName}(string)`, description: "문자열 기반 동적 실행 가능 (eval과 동일한 효과)" });
          }
          if (firstArg.type === "Identifier") {
            addFinding({ line, type: "dynamic_execution", subtype: "variable_timer", pattern: `${calleeName}(variable)`, description: "변수를 통한 동적 실행 가능성 (문자열일 경우 eval 효과)" });
          }
        }

        // [4] 난독화 패턴 단독 사용
        if (OBFUSCATION_PATTERNS.has(calleeName)) {
          addFinding({ line, type: "obfuscation", subtype: calleeName.replace(".", "_"), pattern: `${calleeName}(...)`, description: "인코딩/디코딩 기반 난독화 패턴 사용" });
        }

        // [5] String.fromCharCode() 명시적 탐지
        if (calleeName === "String.fromCharCode") {
          addFinding({ line, type: "obfuscation", subtype: "fromCharCode", pattern: "String.fromCharCode(...)", description: "문자 코드 기반 문자열 생성 (난독화 가능성)" });
        }

        // [6] child_process 직접 함수 호출
        if (node.callee?.type === "Identifier" && node.callee.name && childProcessDirectFuncs.has(node.callee.name)) {
          addFinding({ line, type: "system_command_execution", subtype: "direct_call", pattern: node.callee.name, description: "child_process 함수를 통한 시스템 명령 실행 가능" });
        }

        if (node.callee?.type === "MemberExpression") {
          const objName = getMemberName(node.callee.object);
          const propName = getMemberName(node.callee.property);

          // [7] child_process 객체 메서드 호출
          if ((childProcessObjects.has(objName) || objName === "child_process") && CHILD_PROCESS_FUNCS.has(propName)) {
            addFinding({ line, type: "system_command_execution", subtype: "member_call", pattern: `${objName}.${propName}`, description: "child_process 객체를 통한 시스템 명령 실행 가능" });
          }

          // [8] HTTP/HTTPS 외부 통신
          if ((HTTP_MODULES.has(objName) || httpObjects.has(objName)) && (propName === "get" || propName === "request")) {
            addFinding({ line, type: "external_communication", subtype: "http_request", pattern: `${objName}.${propName}`, description: "HTTP/HTTPS 기반 외부 통신 가능" });
          }

          // [9] 서드파티 HTTP 클라이언트 (axios, got 등)
          if (KNOWN_HTTP_CLIENTS.has(objName) && HTTP_CLIENT_METHODS.has(propName)) {
            addFinding({ line, type: "external_communication", subtype: "http_client", pattern: `${objName}.${propName}`, description: `서드파티 HTTP 클라이언트(${objName})를 통한 외부 통신 가능` });
          }
        }

        // [10] fetch()
        if (node.callee?.type === "Identifier" && node.callee.name === "fetch") {
          addFinding({ line, type: "external_communication", subtype: "fetch", pattern: "fetch(...)", description: "fetch를 통한 외부 통신 가능" });
        }

        // [11] 동적 require
        if (isDynamicRequire(node)) {
          const argType = node.arguments[0]?.type || "unknown";
          addFinding({ line, type: "dynamic_execution", subtype: "dynamic_require", pattern: `require(${argType})`, description: "동적 require 사용 - 실제 로드 모듈을 정적으로 파악 불가" });
        }
      },

      // ── [12] NewExpression ───────────────────────────────────────────────
      NewExpression(nodePath) {
        const node = nodePath.node;
        const calleeName = getMemberName(node.callee);
        const line = node.loc?.start?.line ?? null;

        if (calleeName === "Function") {
          addFinding({ line, type: "dynamic_execution", subtype: "new_Function", pattern: "new Function(...)", description: "new Function을 통한 동적 코드 실행 가능" });
        }
      },

      // ── [13] ImportExpression: ESM dynamic import 탐지 (신규 추가) ──────
      // ImportDeclaration(import fs from "fs")과 다름 — 런타임에 실행되는 import()
      ImportExpression(nodePath) {
        const node = nodePath.node;
        const line = node.loc?.start?.line ?? null;
        const sourceNode = node.source;
        if (!sourceNode) return;

        if (sourceNode.type === "StringLiteral") {
          // 고정 문자열: import("child_process"), import("https")
          const moduleName = sourceNode.value;

          if (moduleName === "child_process") {
            addFinding({ line, type: "system_command_execution", subtype: "esm_dynamic_import", pattern: `import("${moduleName}")`, description: "ESM dynamic import를 통한 child_process 로드 가능" });
          } else if (HTTP_MODULES.has(moduleName)) {
            addFinding({ line, type: "external_communication", subtype: "esm_dynamic_import", pattern: `import("${moduleName}")`, description: `ESM dynamic import를 통한 ${moduleName} 모듈 로드 가능` });
          }
        } else {
          // 동적 문자열: import(variable), import("a" + "b")
          addFinding({ line, type: "dynamic_execution", subtype: "dynamic_import_expression", pattern: `import(${sourceNode.type})`, description: "동적 ESM import 사용 - 실제 로드 모듈을 정적으로 파악 불가" });
        }
      },

      // ── [14~16] MemberExpression ─────────────────────────────────────────
      MemberExpression(nodePath) {
        const node = nodePath.node;
        const fullName = getMemberName(node);
        const objName = getMemberName(node.object);
        const propName = getMemberName(node.property);
        const line = node.loc?.start?.line ?? null;

        // [14] 환경 변수 접근
        if (fullName === "process.env" || fullName.startsWith("process.env.")) {
          addFinding({ line, type: "system_info_access", subtype: "env_access", pattern: fullName, description: "환경 변수 접근" });
        }

        // [15] os 모듈 시스템 정보 수집
        if ((objName === "os" || osObjects.has(objName)) && SYSTEM_INFO_OS_FUNCS.has(propName)) {
          addFinding({ line, type: "system_info_access", subtype: "os_info", pattern: `${objName}.${propName}`, description: "시스템 정보 접근 가능" });
        }

        // [16] process 프로세스 정보 접근
        if (objName === "process" && propName && propName !== "env" && SENSITIVE_PROCESS_PROPS.has(propName)) {
          addFinding({ line, type: "system_info_access", subtype: "process_info", pattern: `process.${propName}`, description: "프로세스/시스템 정보 접근" });
        }
      }
    });

    return {
      packageInfo,
      findings: filterRedundantProcessEnv(deduplicateFindings(findings)),
      parse_errors: parseErrors
    };

  } catch (error) {
    parseErrors.push({
      file: packageInfo ? packageInfo.relativeFile : filePath,
      type: "parse_error",
      pattern: "AST parse failed",
      description: error.message
    });
    return { packageInfo, findings: [], parse_errors: parseErrors };
  }
}

// ─── 프로젝트 전체 분석 ───────────────────────────────────────────────────────

function analyzeProject(projectDir) {
  const files = collectJsFiles(projectDir);
  const packageMap = new Map();

  for (const filePath of files) {
    const result = analyzeFile(filePath);
    const packageInfo = result.packageInfo;
    if (!packageInfo) continue;

    const key = `${packageInfo.package}@${packageInfo.version}`;
    if (!packageMap.has(key)) {
      packageMap.set(key, { package: packageInfo.package, version: packageInfo.version, findings: [], parse_errors: [] });
    }

    const pkgResult = packageMap.get(key);
    pkgResult.findings.push(...result.findings);
    pkgResult.parse_errors.push(...result.parse_errors);
  }

  const finalResults = [];
  for (const pkgResult of packageMap.values()) {
    pkgResult.findings = filterRedundantProcessEnv(deduplicateFindings(pkgResult.findings));
    pkgResult.parse_errors = deduplicateFindings(pkgResult.parse_errors);
    finalResults.push({
      package: pkgResult.package,
      version: pkgResult.version,
      findings: pkgResult.findings,
      ...(pkgResult.parse_errors.length > 0 && { parse_errors: pkgResult.parse_errors })
    });
  }

  return finalResults;
}

// ─── 진입점 ──────────────────────────────────────────────────────────────────

function main() {
  const projectDir = process.argv[2];
  if (!projectDir) {
    console.error(JSON.stringify({ error: "project_dir argument is required" }));
    process.exit(1);
  }
  try {
    const result = analyzeProject(projectDir);
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ error: error.message }));
    process.exit(1);
  }
}

main();
