PREFIX ?= $(HOME)/bin

.PHONY: build install uninstall clean run

build:
	zig build -Doptimize=ReleaseFast

install: build
	@mkdir -p $(PREFIX)
	cp zig-out/bin/zur $(PREFIX)/zur
	@echo "installed zur to $(PREFIX)/zur"

uninstall:
	rm -f $(PREFIX)/zur
	@echo "removed $(PREFIX)/zur"

clean:
	rm -rf zig-out .zig-cache

run:
	zig build run -- $(ARGS)
