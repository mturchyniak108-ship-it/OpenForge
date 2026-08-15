#!/data/data/com.termux/files/usr/bin/bash
set +e

cd "$(dirname "$0")" || exit 1

RESULTS_FILE=".pytest-results.xml"

rm -f "$RESULTS_FILE"

pytest -q --junitxml="$RESULTS_FILE"
STATUS=$?

python - "$RESULTS_FILE" <<'PY'
import sys
import xml.etree.ElementTree as ET

path = sys.argv[1]
root = ET.parse(path).getroot()

testcases = root.findall(".//testcase")

total = len(testcases)
failed = []
errors = []
skipped = []

for case in testcases:
    name = case.attrib.get("name", "<unknown>")
    classname = case.attrib.get("classname", "")
    full_name = f"{classname}::{name}" if classname else name

    if case.find("failure") is not None:
        failed.append(full_name)

    if case.find("error") is not None:
        errors.append(full_name)

    if case.find("skipped") is not None:
        skipped.append(full_name)

passed = total - len(failed) - len(errors) - len(skipped)

print()
print("================ TEST SUMMARY ================")
print(f"TOTAL:   {total}")
print(f"PASSED:  {passed}")
print(f"FAILED:  {len(failed)}")
print(f"ERRORS:  {len(errors)}")
print(f"SKIPPED: {len(skipped)}")

if failed:
    print()
    print("---------------- FAILED TESTS ----------------")
    for test in failed:
        print(f"FAIL: {test}")

if errors:
    print()
    print("---------------- ERROR TESTS -----------------")
    for test in errors:
        print(f"ERROR: {test}")

if skipped:
    print()
    print("---------------- SKIPPED TESTS ---------------")
    for test in skipped:
        print(f"SKIP: {test}")

print("==============================================")
PY

rm -f "$RESULTS_FILE"

exit "$STATUS"
