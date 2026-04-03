import json
from pathlib import Path

from graph_builder import DependencyGraphBuilder
from detectors.install_script_detector import detect_install_scripts
from detectors.typosquatting_detector import detect_typosquatting
from detectors.dependency_confusion_detector import detect_dependency_confusion
from detectors.ast_detector import detect_ast_risks


def save_output(data: dict, output_path: str) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main() -> None:
    project_dir = "../test-projects/sample-app"
    lockfile_path = f"{project_dir}/package-lock.json"
    npmrc_path = f"{project_dir}/.npmrc"

    graph_output_path = f"{project_dir}/dependency_graph.json"
    detection_output_path = f"{project_dir}/detection_results.json"

    builder = DependencyGraphBuilder(lockfile_path)
    graph = builder.build()

    print("=== Dependency Graph Summary ===")
    print("Root:", graph["root_id"])
    print("Node count:", len(graph["nodes"]))
    print("Edge count:", len(graph["edges"]))

    install_script_results = detect_install_scripts(graph)
    typosquatting_results = detect_typosquatting(graph)
    dependency_confusion_results = detect_dependency_confusion(
        graph,
        npmrc_path=npmrc_path
    )

    ast_result = detect_ast_risks(project_dir)
    ast_findings = ast_result["findings"]
    ast_parse_errors = ast_result["parse_errors"]

    detection_results = {
        "install_script_results": install_script_results,
        "typosquatting_results": typosquatting_results,
        "dependency_confusion_results": dependency_confusion_results,
        "ast_results": {
            "findings": ast_findings,
            "parse_errors": ast_parse_errors
        }
    }

    print("\n=== Detection Summary ===")
    print("Install script findings:", len(install_script_results))
    print("Typosquatting findings:", len(typosquatting_results))
    print("Dependency confusion findings:", len(dependency_confusion_results))
    print("AST findings:", len(ast_findings))
    print("AST parse errors:", len(ast_parse_errors))

    if ast_findings:
        print("\nAST findings:")
        for item in ast_findings[:10]:
            print(
                f"- {item['file']} "
                f"(line {item.get('line', '?')}) "
                f"-> {item['type']} / "
                f"{item.get('subtype', item['pattern'])} : {item['description']}"
            )

    if ast_parse_errors:
        print("\nAST parse errors:")
        for item in ast_parse_errors[:10]:
            print(f"- {item['file']} -> {item['description']}")

    if install_script_results:
        print("\nInstall script findings:")
        for item in install_script_results[:10]:
            print(f"- {item['package']} ({item['version']}) -> {item['reason']}")

    if typosquatting_results:
        print("\nTyposquatting candidates:")
        for item in typosquatting_results[:10]:
            print(
                f"- {item['package']} ({item['version']}) "
                f"-> {item['reason']} [distance={item['distance']}]"
            )

    if dependency_confusion_results:
        print("\nDependency confusion candidates:")
        for item in dependency_confusion_results[:10]:
            print(
                f"- {item['package']} ({item['version']}) "
                f"-> {item['reason']}"
            )

    save_output(graph, graph_output_path)
    save_output(detection_results, detection_output_path)

    print(f"\nGraph saved to: {graph_output_path}")
    print(f"Detection results saved to: {detection_output_path}")


if __name__ == "__main__":
    main()
