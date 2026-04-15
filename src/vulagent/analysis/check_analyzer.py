"""
Static analyzer: for each function in a C/C++ file, determine what validation
checks exist for each input parameter.

Uses tree-sitter-c to parse the AST and walks the function body looking for
conditions, assertions, and validation-like calls that reference parameters.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

LANG_C = Language(tsc.language())

# C++ grammar is optional — fall back to C grammar if not installed.
try:
    import tree_sitter_cpp as tscpp
    LANG_CPP = Language(tscpp.language())
except ImportError:
    LANG_CPP = None

# Default grammar (kept for backwards compatibility with callers that reference LANG)
LANG = LANG_C

_CPP_SUFFIXES = {".cpp", ".cc", ".cxx", ".cxx", ".hpp", ".hh", ".hxx"}


def _pick_language(file_path: str) -> "Language":
    """Dispatch to C++ grammar for C++ files if available, else fall back to C."""
    from pathlib import Path as _Path
    suffix = _Path(file_path).suffix.lower()
    if suffix in _CPP_SUFFIXES and LANG_CPP is not None:
        return LANG_CPP
    return LANG_C

# ── Check categories ────────────────────────────────────────────────────────

CHECK_KINDS = {
    "null_check",       # == NULL, != NULL, !ptr, if(ptr)
    "bounds_check",     # < len, >= 0, < MAX, index range guards
    "sizeof_check",     # involves sizeof()
    "strlen_check",     # involves strlen() or strnlen()
    "overflow_check",   # wraparound guards (a + b < a), or explicit overflow funcs
    "enum_check",       # switch on param or param->field, comparison with enum/constant
    "assertion",        # assert(), GF_ASSERT, TORRENT_ASSERT, etc.
    "validation_call",  # is_valid(param), check_*(param), validate_*(param)
    "negative_check",   # param < 0, param >= 0  (signed error/range)
    "zero_check",       # param == 0, param != 0, !param  (non-pointer)
    "bitwise_check",    # param & MASK, param | FLAG in condition
    "cast_check",       # explicit cast before use (e.g., (unsigned)param)
}

COMPARISON_OPS = {"<", ">", "<=", ">=", "==", "!="}
NULL_LITERALS = {"NULL", "nullptr", "0", "nil"}
ASSERT_NAMES = re.compile(
    r"^(assert|g_assert|GF_ASSERT|TORRENT_ASSERT|BOOST_ASSERT|BT_ASSERT|"
    r"gf_assert|g_return_if_fail|g_return_val_if_fail|SDL_assert|"
    r"DCHECK|CHECK|RCHECK|VERIFY|Q_ASSERT|wxASSERT|NS_ASSERTION)$",
    re.IGNORECASE,
)
VALIDATION_NAMES = re.compile(
    r"(is_valid|check_|validate_|verify_|ensure_|assert_|sanitize_|"
    r"IsValid|Check|Validate|Verify|Ensure)", re.IGNORECASE,
)
SIZE_IDENT = re.compile(
    r"(len|length|size|count|num|nb|capacity|max|min|limit|bound|"
    r"remaining|avail|total|offset|stride|width|height|depth)", re.IGNORECASE,
)


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class ParamCheck:
    kind: str           # one of CHECK_KINDS
    line: int           # source line (1-based)
    snippet: str        # short code snippet of the check
    context: str = ""   # e.g. "if-condition", "assert", "for-bound", "switch"


@dataclass
class ParamInfo:
    name: str
    type_str: str       # e.g. "char *", "int", "struct context *"
    is_pointer: bool
    checks: list[ParamCheck] = field(default_factory=list)


@dataclass
class FunctionChecks:
    name: str
    file: str
    line: int           # start line (1-based)
    end_line: int
    params: list[ParamInfo] = field(default_factory=list)
    unchecked_params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Drop empty checks for brevity
        for p in d["params"]:
            if not p["checks"]:
                del p["checks"]
        return d


# ── Helpers ──────────────────────────────────────────────────────────────────

def _text(node: Node) -> str:
    return node.text.decode(errors="replace")


def _collect_identifiers(node: Node) -> set[str]:
    """Recursively collect all identifier names under a node."""
    ids: set[str] = set()
    if node.type == "identifier":
        ids.add(_text(node))
    for child in node.children:
        ids.update(_collect_identifiers(child))
    return ids


def _collect_field_accesses(node: Node) -> set[str]:
    """Collect base identifiers used in -> or . field access (e.g. ctx in ctx->type)."""
    bases: set[str] = set()
    if node.type in ("field_expression", "pointer_expression"):
        for child in node.children:
            if child.type == "identifier":
                bases.add(_text(child))
                break
    for child in node.children:
        bases.update(_collect_field_accesses(child))
    return bases


def _has_node_type(node: Node, type_name: str) -> bool:
    if node.type == type_name:
        return True
    return any(_has_node_type(c, type_name) for c in node.children)


def _has_call_named(node: Node, pattern: re.Pattern) -> bool:
    """Check if any call_expression under node matches the name pattern."""
    if node.type == "call_expression":
        for child in node.children:
            if child.type == "identifier" and pattern.search(_text(child)):
                return True
    return any(_has_call_named(c, pattern) for c in node.children)


def _has_sizeof(node: Node) -> bool:
    return _has_node_type(node, "sizeof_expression")


def _has_strlen(node: Node) -> bool:
    if node.type == "call_expression":
        for child in node.children:
            if child.type == "identifier" and _text(child) in ("strlen", "strnlen", "wcslen"):
                return True
    return any(_has_strlen(c) for c in node.children)


def _snippet(node: Node, max_len: int = 120) -> str:
    t = _text(node).replace("\n", " ").strip()
    if len(t) > max_len:
        t = t[:max_len] + "..."
    return t


def _extract_type_str(param_node: Node) -> tuple[str, str, bool]:
    """Extract (type_string, param_name, is_pointer) from a parameter_declaration."""
    parts: list[str] = []
    name = ""
    is_pointer = False

    for child in param_node.children:
        if child.type in ("primitive_type", "sized_type_specifier", "type_identifier"):
            parts.append(_text(child))
        elif child.type in ("struct_specifier", "union_specifier", "enum_specifier"):
            parts.append(_text(child))
        elif child.type == "type_qualifier":
            parts.append(_text(child))
        elif child.type == "identifier":
            name = _text(child)
        elif child.type == "pointer_declarator":
            is_pointer = True
            parts.append("*")
            # Find the identifier inside
            for c in child.children:
                if c.type == "identifier":
                    name = _text(c)
                elif c.type == "pointer_declarator":
                    parts.append("*")
                    for cc in c.children:
                        if cc.type == "identifier":
                            name = _text(cc)
        elif child.type == "abstract_pointer_declarator":
            is_pointer = True
            parts.append("*")
        elif child.type == "array_declarator":
            for c in child.children:
                if c.type == "identifier":
                    name = _text(c)

    type_str = " ".join(parts).replace(" *", " *").strip()
    # Heuristic: char*, void*, any_struct* are pointers
    if not is_pointer and "*" in _text(param_node):
        is_pointer = True
    return type_str, name, is_pointer


# ── Condition classification ─────────────────────────────────────────────────

def _classify_condition_for_param(
    cond_node: Node, param_name: str, is_pointer: bool, context: str
) -> list[ParamCheck]:
    """Given a condition AST node, determine what checks it performs on param_name."""
    checks: list[ParamCheck] = []
    ids_in_cond = _collect_identifiers(cond_node)
    if param_name not in ids_in_cond:
        # Also check field accesses (ctx->field)
        fields = _collect_field_accesses(cond_node)
        if param_name not in fields:
            return checks

    line = cond_node.start_point[0] + 1
    snip = _snippet(cond_node)

    # Unary negation: !param  (null check for pointers, zero check otherwise)
    if cond_node.type == "unary_expression":
        op_child = cond_node.children[0] if cond_node.children else None
        if op_child and _text(op_child) == "!":
            arg = cond_node.children[1] if len(cond_node.children) > 1 else None
            if arg and arg.type == "identifier" and _text(arg) == param_name:
                kind = "null_check" if is_pointer else "zero_check"
                checks.append(ParamCheck(kind, line, snip, context))
                return checks

    # Bare identifier as condition: if(param)
    if cond_node.type == "identifier" and _text(cond_node) == param_name:
        kind = "null_check" if is_pointer else "zero_check"
        checks.append(ParamCheck(kind, line, snip, context))
        return checks

    # Binary expressions
    if cond_node.type == "binary_expression" and len(cond_node.children) >= 3:
        left, op_node, right = cond_node.children[0], cond_node.children[1], cond_node.children[2]
        op = _text(op_node)

        # Logical operators: recurse into both sides
        if op in ("&&", "||"):
            checks.extend(_classify_condition_for_param(left, param_name, is_pointer, context))
            checks.extend(_classify_condition_for_param(right, param_name, is_pointer, context))
            return checks

        left_ids = _collect_identifiers(left)
        right_ids = _collect_identifiers(right)
        involves_param = param_name in left_ids or param_name in right_ids

        if involves_param and op in COMPARISON_OPS:
            # Null check: param == NULL, param != NULL
            left_t = _text(left).strip()
            right_t = _text(right).strip()
            if left_t in NULL_LITERALS or right_t in NULL_LITERALS:
                # Only count as null check if param is used directly (not subscripted/dereferenced)
                param_is_direct = (
                    (left.type == "identifier" and _text(left) == param_name) or
                    (right.type == "identifier" and _text(right) == param_name)
                )
                if _has_node_type(cond_node, "null") and param_is_direct:
                    checks.append(ParamCheck("null_check", line, snip, context))
                    return checks
                if is_pointer and (left_t == "0" or right_t == "0") and param_is_direct:
                    checks.append(ParamCheck("null_check", line, snip, context))
                    return checks

            # sizeof check
            if _has_sizeof(cond_node):
                checks.append(ParamCheck("sizeof_check", line, snip, context))
                return checks

            # strlen check
            if _has_strlen(cond_node):
                checks.append(ParamCheck("strlen_check", line, snip, context))
                return checks

            # Negative check: param < 0, param >= 0
            if (right_t == "0" or left_t == "0") and not is_pointer:
                if op in ("<", ">=", "<=", ">"):
                    checks.append(ParamCheck("negative_check", line, snip, context))
                    return checks
                else:
                    checks.append(ParamCheck("zero_check", line, snip, context))
                    return checks

            # Bounds check: comparison with size-like identifiers or numeric literals
            other_ids = (right_ids - {param_name}) | (left_ids - {param_name})
            if any(SIZE_IDENT.search(oid) for oid in other_ids):
                checks.append(ParamCheck("bounds_check", line, snip, context))
                return checks
            # Comparison with numeric literal > 0 is a bounds check
            if _has_node_type(right, "number_literal") or _has_node_type(left, "number_literal"):
                if op in ("<", ">", "<=", ">="):
                    checks.append(ParamCheck("bounds_check", line, snip, context))
                    return checks

            # Generic comparison with constants/enums (uppercase identifiers)
            if op in ("==", "!="):
                for oid in other_ids:
                    if oid.isupper() or oid.startswith("GF_") or oid.startswith("TYPE_"):
                        checks.append(ParamCheck("enum_check", line, snip, context))
                        return checks

            # Overflow check: (a + b < a) pattern
            if _has_node_type(left, "binary_expression") or _has_node_type(right, "binary_expression"):
                # If param appears on both sides of comparison, likely overflow guard
                if param_name in left_ids and param_name in right_ids:
                    checks.append(ParamCheck("overflow_check", line, snip, context))
                    return checks

            # Fallback: it's at least a bounds check if it's a comparison
            if op in ("<", ">", "<=", ">="):
                checks.append(ParamCheck("bounds_check", line, snip, context))
                return checks

        # Bitwise in condition
        if involves_param and op in ("&", "|"):
            checks.append(ParamCheck("bitwise_check", line, snip, context))
            return checks

    # Recurse into nested parenthesized expressions
    if cond_node.type == "parenthesized_expression":
        for child in cond_node.children:
            if child.type not in ("(", ")"):
                checks.extend(_classify_condition_for_param(child, param_name, is_pointer, context))
        return checks

    # Recurse into comma expressions
    if cond_node.type == "comma_expression":
        for child in cond_node.children:
            checks.extend(_classify_condition_for_param(child, param_name, is_pointer, context))
        return checks

    return checks


# ── Body walkers ─────────────────────────────────────────────────────────────

def _find_checks_in_body(body: Node, param_name: str, is_pointer: bool) -> list[ParamCheck]:
    """Walk a function body and collect all checks on a given parameter."""
    checks: list[ParamCheck] = []

    def walk(node: Node) -> None:
        # ── if / else-if ──
        if node.type == "if_statement":
            for child in node.children:
                if child.type == "parenthesized_expression":
                    for inner in child.children:
                        if inner.type not in ("(", ")"):
                            checks.extend(
                                _classify_condition_for_param(inner, param_name, is_pointer, "if-condition")
                            )
                    break

        # ── while ──
        if node.type == "while_statement":
            for child in node.children:
                if child.type == "parenthesized_expression":
                    for inner in child.children:
                        if inner.type not in ("(", ")"):
                            checks.extend(
                                _classify_condition_for_param(inner, param_name, is_pointer, "while-condition")
                            )
                    break

        # ── for ──
        if node.type == "for_statement":
            # Condition is the second expression (after the init declaration/expression)
            # In tree-sitter, the condition comes after the init, between the two semicolons
            parts = [c for c in node.children if c.type not in ("for", "(", ")", ";")]
            if len(parts) >= 2:
                cond = parts[1]  # condition part
                checks.extend(
                    _classify_condition_for_param(cond, param_name, is_pointer, "for-condition")
                )

        # ── ternary ──
        if node.type == "conditional_expression" and len(node.children) >= 1:
            checks.extend(
                _classify_condition_for_param(node.children[0], param_name, is_pointer, "ternary")
            )

        # ── switch on param or param->field ──
        if node.type == "switch_statement":
            for child in node.children:
                if child.type == "parenthesized_expression":
                    ids = _collect_identifiers(child)
                    fields = _collect_field_accesses(child)
                    if param_name in ids or param_name in fields:
                        # Count cases
                        case_count = sum(
                            1 for desc in _iter_descendants(node)
                            if desc.type == "case_statement"
                        )
                        line = node.start_point[0] + 1
                        snip = f"switch({_snippet(child, 60)}) [{case_count} cases]"
                        checks.append(ParamCheck("enum_check", line, snip, "switch"))
                    break

        # ── assert-like calls ──
        if node.type == "call_expression":
            func_name_node = node.children[0] if node.children else None
            if func_name_node and func_name_node.type == "identifier":
                fname = _text(func_name_node)
                if ASSERT_NAMES.match(fname):
                    ids = _collect_identifiers(node)
                    if param_name in ids:
                        line = node.start_point[0] + 1
                        checks.append(ParamCheck("assertion", line, _snippet(node), "assert"))
                        return  # Don't recurse into assert args
                elif VALIDATION_NAMES.search(fname):
                    # Check if param is an argument
                    for child in node.children:
                        if child.type == "argument_list":
                            arg_ids = _collect_identifiers(child)
                            if param_name in arg_ids:
                                line = node.start_point[0] + 1
                                checks.append(ParamCheck("validation_call", line, _snippet(node), "call"))
                                return

        # ── cast in expression (heuristic: cast before use) ──
        if node.type == "cast_expression":
            ids = _collect_identifiers(node)
            if param_name in ids:
                line = node.start_point[0] + 1
                checks.append(ParamCheck("cast_check", line, _snippet(node), "cast"))

        for child in node.children:
            walk(child)

    walk(body)
    return checks


def _iter_descendants(node: Node):
    for child in node.children:
        yield child
        yield from _iter_descendants(child)


# ── Parameter extraction ─────────────────────────────────────────────────────

def _extract_params(func_node: Node) -> list[ParamInfo]:
    """Extract parameter info from a function_definition node."""
    params: list[ParamInfo] = []
    for child in func_node.children:
        if child.type == "function_declarator":
            for c in child.children:
                if c.type == "parameter_list":
                    for p in c.children:
                        if p.type == "parameter_declaration":
                            type_str, name, is_ptr = _extract_type_str(p)
                            if name:  # skip unnamed params like (void)
                                params.append(ParamInfo(name, type_str, is_ptr))
            break
        # Handle pointer declarator wrapping: int *foo(...)
        if child.type == "pointer_declarator":
            for c in _iter_descendants(child):
                if c.type == "function_declarator":
                    for p_list in c.children:
                        if p_list.type == "parameter_list":
                            for p in p_list.children:
                                if p.type == "parameter_declaration":
                                    type_str, name, is_ptr = _extract_type_str(p)
                                    if name:
                                        params.append(ParamInfo(name, type_str, is_ptr))
                    break
            break
    return params


def _get_body(func_node: Node) -> Node | None:
    for child in func_node.children:
        if child.type == "compound_statement":
            return child
    return None


# ── Public API ───────────────────────────────────────────────────────────────

def analyze_function(func_node: Node, file_path: str) -> FunctionChecks | None:
    """Analyze a single function_definition node and return its check summary."""
    # Get function name
    name = None
    for child in func_node.children:
        if child.type == "function_declarator":
            for c in child.children:
                if c.type == "identifier":
                    name = _text(c)
                    break
            break
        if child.type == "pointer_declarator":
            for c in _iter_descendants(child):
                if c.type == "function_declarator":
                    for cc in c.children:
                        if cc.type == "identifier":
                            name = _text(cc)
                            break
                    break
            break

    if not name or not name.isidentifier() or name in ("if", "for", "while", "switch", "return"):
        return None

    params = _extract_params(func_node)
    body = _get_body(func_node)
    if not body or not params:
        return FunctionChecks(
            name=name,
            file=file_path,
            line=func_node.start_point[0] + 1,
            end_line=func_node.end_point[0] + 1,
            params=params,
            unchecked_params=[p.name for p in params],
        )

    for param in params:
        param.checks = _find_checks_in_body(body, param.name, param.is_pointer)

    unchecked = [p.name for p in params if not p.checks]

    return FunctionChecks(
        name=name,
        file=file_path,
        line=func_node.start_point[0] + 1,
        end_line=func_node.end_point[0] + 1,
        params=params,
        unchecked_params=unchecked,
    )


def analyze_source(source: str, file_path: str = "<stdin>") -> list[FunctionChecks]:
    """Analyze all functions in a C/C++ source string.

    Dispatches to the C++ grammar for .cpp/.cc/.cxx/.hpp/.hh/.hxx files when
    tree-sitter-cpp is installed; otherwise falls back to the C grammar (which
    can parse simple C-like C++ but breaks on namespaces, classes, templates).
    """
    parser = Parser(_pick_language(file_path))
    tree = parser.parse(source.encode(errors="replace"))
    results: list[FunctionChecks] = []

    def walk(node: Node) -> None:
        if node.type == "function_definition":
            fc = analyze_function(node, file_path)
            if fc:
                results.append(fc)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return results


def analyze_file(path: str | Path) -> list[FunctionChecks]:
    """Analyze a single C/C++ file."""
    path = Path(path)
    if path.suffix.lower() not in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}:
        return []
    source = path.read_text(errors="replace")
    return analyze_source(source, str(path))


def analyze_directory(
    root: str | Path,
    extensions: set[str] | None = None,
    skip_tests: bool = True,
) -> list[FunctionChecks]:
    """Recursively analyze all C/C++ files in a directory."""
    if extensions is None:
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
    root = Path(root)
    results: list[FunctionChecks] = []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in extensions:
            continue
        if skip_tests and ("test" in path.parts or "tests" in path.parts):
            continue
        try:
            results.extend(analyze_file(path))
        except Exception as e:
            print(f"Warning: failed to analyze {path}: {e}")
    return results


# ── Reporting ────────────────────────────────────────────────────────────────

def format_text_report(results: list[FunctionChecks], show_checked: bool = False) -> str:
    """Format results as a human-readable text report."""
    lines: list[str] = []
    total_funcs = len(results)
    funcs_with_unchecked = sum(1 for r in results if r.unchecked_params)
    total_params = sum(len(r.params) for r in results)
    total_unchecked = sum(len(r.unchecked_params) for r in results)

    lines.append(f"=== Argument Check Analysis ===")
    lines.append(f"Functions analyzed: {total_funcs}")
    lines.append(f"Total parameters:  {total_params}")
    lines.append(f"Unchecked params:  {total_unchecked}")
    lines.append(f"Functions with unchecked params: {funcs_with_unchecked}")
    lines.append("")

    for fc in results:
        if not show_checked and not fc.unchecked_params:
            continue

        lines.append(f"--- {fc.file}:{fc.line}  {fc.name}() ---")
        for param in fc.params:
            status = "UNCHECKED" if not param.checks else f"{len(param.checks)} check(s)"
            ptr_tag = " [ptr]" if param.is_pointer else ""
            lines.append(f"  {param.type_str} {param.name}{ptr_tag}: {status}")
            for chk in param.checks:
                lines.append(f"    [{chk.kind}] L{chk.line} ({chk.context}): {chk.snippet}")
        lines.append("")

    return "\n".join(lines)


def format_json_report(results: list[FunctionChecks]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


def format_summary(results: list[FunctionChecks]) -> str:
    """Compact per-function summary: function name + which params are checked/unchecked."""
    lines: list[str] = []
    for fc in results:
        checked = [p.name for p in fc.params if p.checks]
        unchecked = fc.unchecked_params
        check_kinds_by_param: dict[str, set[str]] = {}
        for p in fc.params:
            for c in p.checks:
                check_kinds_by_param.setdefault(p.name, set()).add(c.kind)

        parts = []
        for p in fc.params:
            kinds = check_kinds_by_param.get(p.name, set())
            if kinds:
                parts.append(f"{p.name}:{','.join(sorted(kinds))}")
            else:
                parts.append(f"{p.name}:NONE")
        lines.append(f"{fc.file}:{fc.line} {fc.name}({'; '.join(parts)})")
    return "\n".join(lines)
