SHELL=/bin/bash

clean:
	@rm -Rf build/
	@rm -Rf dist/
	@rm -Rf __pycache__/
	@rm -Rf tests/__pycache__/
	@rm -Rf src/aad/__pycache__/
	@rm -Rf src/__pycache__/
	@rm -Rf src/aad.egg-info

format:
	@isort .
	@black .

install-deps:
	@PYTHONPATH=./src pip install -r ./src/requirements.txt --quiet
	@PYTHONPATH=./src pip install -r ./tests/requirements.txt --quiet

unit-test: clean install-deps
	@PYTHONPATH=./src python3 -m pytest ./tests --doctest-modules --cov=./src --junitxml=pytest-results.xml --cov-report term --cov-report=xml

dist: clean install-deps
	@PYTHONPATH=./src python3 -m setup bdist_wheel
