# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ccgui-asm-bridge
# Copyright (C) 2026 SnapKitty Collective
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

NASM ?= nasm
LD ?= ld
ASM_SRC = asm/mcpd.asm
BIN = build/mcpd

all: $(BIN)

$(BIN): $(ASM_SRC)
	mkdir -p build
	$(NASM) -f elf64 -o build/mcpd.o $(ASM_SRC)
	$(LD) -o $(BIN) build/mcpd.o

clean:
	rm -rf build

serve: $(BIN)
	./$(BIN)

harness: $(BIN)
	python3 harness/harness.py

.PHONY: all clean serve harness

bridge: $(BIN)
	python3 bridge/ws_bridge.py

web: $(BIN)
	@echo "Starting mcpd (:7341), ws-bridge (:8765), http (:8000)..."
	@./build/mcpd 7341 & echo $$! > .mcpd.pid
	@sleep 0.3
	@python3 bridge/ws_bridge.py --ws-port 8765 & echo $$! > .bridge.pid
	@sleep 0.5
	@cd web && python3 -m http.server 8000
	@kill `cat .mcpd.pid` `cat .bridge.pid` 2>/dev/null; rm -f .mcpd.pid .bridge.pid

screenshots: $(BIN)
	python3 docs/render_screenshots.py

.PHONY: bridge web screenshots
