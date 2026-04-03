const fs = require("fs");
const path = require("path");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const JS_EXTENSIONS = new Set([".js", ".mjs", ".cjs"]);
const CHILD_PROCESS_FUNCS = new Set(["exec", "execSync", "spawn", "spawnSync", "fork"]);
const HTTP_MODULES = new Set(["http", "https"]);
const SYSTEM_INFO_OS_FUNCS = new Set(["userInfo", "hostname", "networkInterfaces"]);
const EXCLUDED_DIR_NAMES = new Set([
  "test",
  "tests",
  "__tests__",
  "coverage"
]);

function shouldExcludePath(fullPath) {
  const normalized = fullPath.split(path.sep).join("/");

  return (
    normalized.includes("/test/") ||
    normalized.includes("/tests/") ||
    normalized.includes("/__tests__/") ||
    normalized.includes("/coverage/")
  );
}

function collectJsFiles(projectDir) {
  const results = [];

  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (EXCLUDED_DIR_NAMES.has(entry.name)) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);

        if (!JS_EXTENSIONS.has(ext)) {
          continue;
        }

        if (!fullPath.includes("node_modules")) {
          continue;
        }

        if (
          fullPath.includes("/test/") ||
          fullPath.includes("/tests/") ||
          fullPath.includes("/__tests__/")
        ) {
          continue;
        }

        results.push(fullPath);
      }
    }
  }

  walk(projectDir);
  return results;
}

function getMemberName(node) {
  if (!node) return "";

  if (node.type === "Identifier") {
    return node.name;
  }

  if (node.type === "StringLiteral") {
    return node.value;
  }

  if (node.type === "ThisExpression") {
    return "this";
  }

  if (node.type === "MemberExpression") {
    const obj = getMemberName(node.object);
    const prop = getMemberName(node.property);
    if (obj && prop) return `${obj}.${prop}`;
    return obj || prop;
  }

  if (node.type === "OptionalMemberExpression") {
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

function extractChildProcessBindings(ast) {
  const childProcessObjects = new Set();
  const childProcessDirectFuncs = new Set();

  traverse(ast, {
    VariableDeclarator(path) {
      const node = path.node;
      if (!isRequireOf(node.init, "child_process")) return;

      const id = node.id;

      if (id.type === "Identifier") {
        childProcessObjects.add(id.name);
      } else if (id.type === "ObjectPattern") {
        for (const prop of id.properties) {
          if (prop.type !== "ObjectProperty") continue;
          if (prop.key.type !== "Identifier") continue;

          const importedName = prop.key.name;
          if (!CHILD_PROCESS_FUNCS.has(importedName)) continue;

          if (prop.value && prop.value.type === "Identifier") {
            childProcessDirectFuncs.add(prop.value.name);
          } else {
            childProcessDirectFuncs.add(importedName);
          }
        }
      }
    }
  });

  return { childProcessObjects, childProcessDirectFuncs };
}

function deduplicateFindings(findings) {
  const seen = new Set();
  const unique = [];

  for (const item of findings) {
    const key = JSON.stringify([
      item.file,
      item.line,
      item.type,
      item.subtype || "",
      item.pattern,
      item.description
    ]);

    if (!seen.has(key)) {
      seen.add(key);
      unique.push(item);
    }
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
      (item) =>
        typeof item.pattern === "string" &&
        item.pattern.startsWith("process.env.")
    );

    for (const item of items) {
      if (hasSpecificEnv && item.pattern === "process.env") {
        continue;
      }
      filtered.push(item);
    }
  }

  return filtered;
}

function containsBufferFrom(node) {
  let found = false;

  traverse(node, {
    noScope: true,
    CallExpression(innerPath) {
      const calleeName = getMemberName(innerPath.node.callee);
      if (calleeName === "Buffer.from") {
        found = true;
        innerPath.stop();
      }
    }
  });

  return found;
}

function analyzeFile(filePath) {
  const findings = [];
  const parseErrors = [];

  try {
    const code = fs.readFileSync(filePath, "utf-8");

    const ast = parser.parse(code, {
      sourceType: "unambiguous",
      plugins: [
        "jsx",
        "typescript",
        "classProperties",
        "classPrivateProperties",
        "classPrivateMethods",
        "optionalChaining",
        "nullishCoalescingOperator",
        "dynamicImport",
        "objectRestSpread",
        "topLevelAwait"
      ],
      errorRecovery: false
    });

    const { childProcessObjects, childProcessDirectFuncs } =
      extractChildProcessBindings(ast);

    traverse(ast, {
      CallExpression(path) {
        const node = path.node;
        const calleeName = getMemberName(node.callee);
        const line = node.loc?.start?.line ?? null;

        if (calleeName === "eval") {
          findings.push({
            file: filePath,
            line,
            type: "dynamic_execution",
            subtype: "eval",
            pattern: "eval(...)",
            description: "동적 코드 실행"
          });

          if (containsBufferFrom(path.parentPath.node || node)) {
            findings.push({
              file: filePath,
              line,
              type: "dynamic_execution",
              subtype: "obfuscated_eval",
              pattern: "eval(Buffer.from(...))",
              description: "Buffer.from 기반 복원 후 eval 실행 의심"
            });
          }
        }

        if (
          (calleeName === "setTimeout" || calleeName === "setInterval") &&
          node.arguments &&
          node.arguments.length > 0
        ) {
          const firstArg = node.arguments[0];
          if (firstArg.type === "StringLiteral") {
            findings.push({
              file: filePath,
              line,
              type: "dynamic_execution",
              subtype: "string_timer",
              pattern: `${calleeName}(string)`,
              description: "문자열 기반 동적 실행 가능"
            });
          }
        }

        if (
          node.callee &&
          node.callee.type === "Identifier" &&
          node.callee.name === "Function"
        ) {
          findings.push({
            file: filePath,
            line,
            type: "dynamic_execution",
            subtype: "Function",
            pattern: "Function(...)",
            description: "Function 생성자를 통한 동적 코드 실행 가능"
          });
        }

        if (
          node.callee &&
          node.callee.type === "Identifier" &&
          childProcessDirectFuncs.has(node.callee.name)
        ) {
          findings.push({
            file: filePath,
            line,
            type: "system_command_execution",
            pattern: node.callee.name,
            description: "child_process 기반 시스템 명령 실행 가능"
          });
        }

        if (node.callee && node.callee.type === "MemberExpression") {
          const objName = getMemberName(node.callee.object);
          const propName = getMemberName(node.callee.property);

          if (
            childProcessObjects.has(objName) &&
            CHILD_PROCESS_FUNCS.has(propName)
          ) {
            findings.push({
              file: filePath,
              line,
              type: "system_command_execution",
              pattern: `${objName}.${propName}`,
              description: "child_process 객체를 통한 시스템 명령 실행 가능"
            });
          }

          if (
            objName === "child_process" &&
            CHILD_PROCESS_FUNCS.has(propName)
          ) {
            findings.push({
              file: filePath,
              line,
              type: "system_command_execution",
              pattern: `${objName}.${propName}`,
              description: "child_process 객체를 통한 시스템 명령 실행 가능"
            });
          }

          if (HTTP_MODULES.has(objName) && (propName === "get" || propName === "request")) {
            findings.push({
              file: filePath,
              line,
              type: "external_communication",
              pattern: `${objName}.${propName}`,
              description: "HTTP/HTTPS 기반 외부 통신 가능"
            });
          }
        }

        if (
          node.callee &&
          node.callee.type === "Identifier" &&
          node.callee.name === "fetch"
        ) {
          findings.push({
            file: filePath,
            line,
            type: "external_communication",
            pattern: "fetch",
            description: "외부 통신 가능"
          });
        }
      },

      NewExpression(path) {
        const node = path.node;
        const calleeName = getMemberName(node.callee);
        const line = node.loc?.start?.line ?? null;

        if (calleeName === "Function") {
          findings.push({
            file: filePath,
            line,
            type: "dynamic_execution",
            subtype: "new_Function",
            pattern: "new Function(...)",
            description: "new Function을 통한 동적 코드 실행 가능"
          });
        }
      },

      MemberExpression(path) {
        const node = path.node;
        const fullName = getMemberName(node);
        const line = node.loc?.start?.line ?? null;

        if (fullName === "process.env" || fullName.startsWith("process.env.")) {
          findings.push({
            file: filePath,
            line,
            type: "system_info_access",
            pattern: fullName,
            description: "환경 변수 접근"
          });
        }

        for (const funcName of SYSTEM_INFO_OS_FUNCS) {
          const target = `os.${funcName}`;
          if (fullName === target) {
            findings.push({
              file: filePath,
              line,
              type: "system_info_access",
              pattern: fullName,
              description: "시스템 정보 접근 가능"
            });
          }
        }
      }
    });

    const deduped = deduplicateFindings(findings);
    const filtered = filterRedundantProcessEnv(deduped);

    return {
      findings: filtered,
      parse_errors: parseErrors
    };
  } catch (error) {
    parseErrors.push({
      file: filePath,
      type: "parse_error",
      pattern: "AST parse failed",
      description: error.message
    });

    return {
      findings: [],
      parse_errors: parseErrors
    };
  }
}

function analyzeProject(projectDir) {
  const files = collectJsFiles(projectDir);
  const allFindings = [];
  const allParseErrors = [];

  for (const filePath of files) {
    const result = analyzeFile(filePath);
    allFindings.push(...result.findings);
    allParseErrors.push(...result.parse_errors);
  }

  return {
    findings: allFindings,
    parse_errors: allParseErrors
  };
}

function main() {
  const projectDir = process.argv[2];

  if (!projectDir) {
    console.error(JSON.stringify({
      error: "project_dir argument is required"
    }));
    process.exit(1);
  }

  try {
    const result = analyzeProject(projectDir);
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(JSON.stringify({
      error: error.message
    }));
    process.exit(1);
  }
}

main();

