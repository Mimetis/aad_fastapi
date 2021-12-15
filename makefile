SHELL=/bin/bash

clean:
	@rm -Rf build/
	@rm -Rf dist/
	@rm -Rf __pycache__/
	@rm -Rf tests/__pycache__/
	@rm -Rf src/aad/__pycache__/
	@rm -Rf src/__pycache__/
	@rm -Rf src/aad.egg-info
	@rm -Rf src/flask_session

format:
	@isort .
	@black .

install-deps:
	@PYTHONPATH=./src pip install -r ./src/requirements.txt --quiet
	@PYTHONPATH=./src pip install -r ./tests/requirements.txt --quiet

unit-test: clean install-deps
	@PYTHONPATH=./src python3 -m pytest ./tests --doctest-modules 

dist: clean
	@PYTHONPATH=./src python3 ./src/setup.py sdist

pypi-upload:
	@python3 -m twine upload ./dist/*
