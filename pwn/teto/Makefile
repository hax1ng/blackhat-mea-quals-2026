PYTHON ?= python3
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: setup check local docker-up docker-down docker-solve planners clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

check:
	$(PYTHON) tools/verify_bundle.py
	$(PYTHON) -m py_compile exploit.py tools/verify_bundle.py

local:
	$(PY) exploit.py --retry

docker-up:
	cd challenge && docker compose up --build --detach

docker-down:
	cd challenge && docker compose down

docker-solve:
	$(PY) exploit.py --docker --retry

planners:
	mkdir -p build
	$(CXX) -O3 -std=c++17 -o build/plan_exploit tools/plan_exploit.cpp
	$(CXX) -O3 -std=c++17 -o build/plan_session tools/plan_session.cpp

clean:
	$(RM) -r build __pycache__

