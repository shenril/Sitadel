test: clean
	@python -m pytest tests

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +

lint:
	@flake8 --ignore=E501 .
