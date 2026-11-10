PY ?= python3
export PYTHONPATH := src

.PHONY: fetch scaffold render validate build test diff clean

fetch:          ## download the pinned ATT&CK release and write the slim extract
	$(PY) -m mitremap fetch

scaffold:       ## create/refresh content/data_components/*.yml (curated blocks preserved)
	$(PY) -m mitremap scaffold

render:         ## render Splunk app, Sigma pipeline and docs into dist/ and docs/
	$(PY) -m mitremap render

validate:       ## consistency checks on config, content and rendered output
	$(PY) -m mitremap validate

build: scaffold render validate

test:
	$(PY) -m pytest -q

diff:           ## changelog between two ATT&CK versions, e.g. make diff FROM=20.0 TO=20.1
	$(PY) -m mitremap diff $(FROM) $(TO)

clean:
	rm -rf attack/raw/*.json
