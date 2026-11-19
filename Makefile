.PHONY: test lint install uninstall user-install clean zip
test:
	bash tests/run.sh
lint:
	shellcheck -x -S warning nmap-toolkit.sh lib/*.sh install.sh tests/run.sh
	python3 -m py_compile lib/report.py
install:
	./install.sh
user-install:
	./install.sh --user
uninstall:
	./install.sh --uninstall
clean:
	rm -rf results lib/__pycache__
