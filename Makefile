test: clean
	@python -m pytest tests

clean:
	find . -name '*.pyc' -exec rm --force {} +
	find . -name '*.pyo' -exec rm --force {} +
	find . -name '*~' -exec rm --force  {} +

lint:
	@flake8 --ignore=E501 .
