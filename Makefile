.PHONY: test lint install uninstall user-install clean zip completions options-docs option-drift
test:
	bash tests/run.sh
lint:
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck -x -S warning nmap-toolkit.sh lib/*.sh install.sh tests/run.sh; else printf 'shellcheck not installed; skipping\n'; fi
	bash tests/test_shellcheck.sh
	python3 -m py_compile lib/report.py
install:
	./install.sh
user-install:
	./install.sh --user
uninstall:
	./install.sh --uninstall
clean:
	rm -rf results lib/__pycache__

completions:
	mkdir -p completions
	bash -c 'source lib/options.sh; options_emit_completion' > completions/xamltech-nmap.bash
	bash -c 'source lib/options.sh; options_emit_zsh' > completions/_xamltech-nmap
	bash -c 'source lib/options.sh; options_emit_fish' > completions/xamltech-nmap.fish

options-docs:
	bash -c 'source lib/options.sh; options_emit_docs' > docs/OPTIONS.md
	bash -c 'source lib/options.sh; options_emit_man' > docs/xamltech-nmap.1

option-drift: completions options-docs
	@bash -c 'source lib/options.sh; options_emit_completion' | diff -u completions/xamltech-nmap.bash -
	@bash -c 'source lib/options.sh; options_emit_zsh' | diff -u completions/_xamltech-nmap -
	@bash -c 'source lib/options.sh; options_emit_fish' | diff -u completions/xamltech-nmap.fish -
	@bash -c 'source lib/options.sh; options_emit_docs' | diff -u docs/OPTIONS.md -
	@bash -c 'source lib/options.sh; options_emit_man' | diff -u docs/xamltech-nmap.1 -
