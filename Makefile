test: clean
	@python -m pytest tests -m "not dangerous"

full_test: clean
	@python -m pytest tests -s

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +

lint:
	@flake8 --ignore=E501 --show-source --statistics .

criticalint:
	@flake8 . --count --select=E901,E999,F821,F822,F823 --show-source --statistics
