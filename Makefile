.PHONY: test eval eval-json demo demo-debug claude-demo api smoke release-smoke all

test:
	uv run pytest tests/ -v

eval:
	uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline
	uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline_stateful
	uv run python evals/run_corpus.py --corpus tests/fixtures/safe_fp --kind safe_fp

eval-json:
	mkdir -p evals/reports
	uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline --output evals/reports/pipeline.json --no-fail --quiet
	uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline_stateful --output evals/reports/pipeline_stateful.json --no-fail --quiet
	uv run python evals/run_corpus.py --corpus tests/fixtures/safe_fp --kind safe_fp --output evals/reports/safe_fp.json --no-fail --quiet

demo:
	uv run python examples/support_copilot/demo.py

demo-debug:
	uv run python examples/support_copilot/demo.py --debug

claude-demo:
	uv run python examples/claude_agent_sdk_guard/demo.py

api:
	uv run uvicorn api.server.app:app --reload

smoke:
	uv run python examples/support_copilot/demo.py
	uv run python examples/claude_agent_sdk_guard/demo.py
	uv run python -c "from api.server.app import app; print('api import ok')"

release-smoke:
	./scripts/release_smoke.sh

all:
	make test
	make eval
	make smoke
