# grader.py
import json
from dataclasses import dataclass

@dataclass
class GradeResult:
    passed: int
    total: int
    details: list  # list of dicts: {input, expected, output/error, ok}


def grade(code: str, tests_json: str, timeout: int = 2, max_mem_mb: int = 128) -> GradeResult:
    """
    Run student code against tests.

    Contract with the rest of your app:

    - Student defines:  def solve(x): ...
      (or more generally solve(...) – see below)
    - We call solve(...) for each test.
    - tests_json is a JSON list of objects with keys:
          {"input": ..., "expected": ...}

    Input handling:
      - If input is a list -> solve(*input)
      - If input is a dict -> solve(**input)
      - Else              -> solve(input)
    """

    # 1) Parse tests from JSON
    try:
        tests = json.loads(tests_json)
    except Exception as e:
        # If tests are broken, bail out with a single error entry
        details = [{
            "input": "",
            "expected": "",
            "error": f"Bad tests JSON: {type(e).__name__}: {e}",
            "ok": False,
        }]
        return GradeResult(passed=0, total=0, details=details)

    # 2) Execute student's code in an isolated namespace
    ns: dict = {}

    try:
        exec(code, ns)
    except Exception as e:
        # Code doesn't even run (syntax error, etc.)
        details = []
        for t in tests:
            details.append({
                "input": repr(t.get("input")),
                "expected": repr(t.get("expected")),
                "error": f"Code error: {type(e).__name__}: {e}",
                "ok": False,
            })
        return GradeResult(passed=0, total=len(tests), details=details)

    # 3) Find the solve function
    solve_fn = ns.get("solve")
    if not callable(solve_fn):
        details = []
        for t in tests:
            details.append({
                "input": repr(t.get("input")),
                "expected": repr(t.get("expected")),
                "error": "No callable function 'solve' defined.",
                "ok": False,
            })
        return GradeResult(passed=0, total=len(tests), details=details)

    # 4) Run all tests
    details = []
    passed = 0

    for t in tests:
        inp = t.get("input")
        expected = t.get("expected")

        try:
            # Allow different shapes of input if you want later
            if isinstance(inp, list):
                result = solve_fn(*inp)
            elif isinstance(inp, dict):
                result = solve_fn(**inp)
            else:
                result = solve_fn(inp)

            ok = (result == expected)
            if ok:
                passed += 1

            details.append({
                "input": repr(inp),
                "expected": repr(expected),
                "output": repr(result),
                "ok": ok,
            })

        except Exception as e:
            details.append({
                "input": repr(inp),
                "expected": repr(expected),
                "error": f"{type(e).__name__}: {e}",
                "ok": False,
            })

    return GradeResult(passed=passed, total=len(tests), details=details)
