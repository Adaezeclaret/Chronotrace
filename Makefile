PY ?= python3
IN  = demo/input
OUT = demo/output

.PHONY: all demo-data build test verify audit bench clean

all: test build verify audit

demo-data:
	$(PY) -m chronotrace synth --out $(IN)

build: demo-data
	$(PY) -m chronotrace build --input $(IN) --changes $(IN)/changes.json --out $(OUT)

test:
	$(PY) tests/run_tests.py

verify: demo-data
	$(PY) -m chronotrace verify --input $(IN) --changes $(IN)/changes.json

audit:
	@! grep -rEn --exclude=Makefile --exclude-dir=__pycache__ --exclude-dir=demo \
	  "UBI-A[0-9]+-|UBI-20[0-9]{2}-[0-9]{4}|evidence_binding|updates-example|sealed-evidence|northstar|NS-WKS|10\.41\.|198\.51\.100\.124|svc-backup|nora\.contractor" . \
	  && echo "AUDIT OK: no assessment markers or private identifiers in the repository"

bench:
	$(PY) -m chronotrace synth --out demo/bench --scale $(or $(SCALE),100)
	$(PY) -m chronotrace build --input demo/bench --changes demo/bench/changes.json --out demo/bench-out
	@cat demo/bench-out/run-metrics.json

clean:
	rm -rf demo tests/test-report.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
