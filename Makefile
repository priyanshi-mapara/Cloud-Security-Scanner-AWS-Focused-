.PHONY: run test lint format

run:
	uvicorn app.main:app --reload

test:
	pytest -q

lint:
	ruff check .

format:
	black .
