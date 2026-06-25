# Repository Guidelines

## Project Structure & Module Organization

This is the OpenWrt build tree. Core build logic lives in `Makefile`, `include/`,
and `scripts/`. Target definitions, device trees, kernel configs, and image
recipes are under `target/linux/`. Package recipes and package-local patches
live in `package/`, while external feeds are configured by `feeds.conf.default`
and materialize under `package/feeds/` after feed installation. Toolchain and
host build support are in `toolchain/` and `tools/`. Generated output such as
firmware images, build directories, and downloads should remain uncommitted.

## Build, Test, and Development Commands

- `./scripts/feeds update -a`: refresh package feed metadata.
- `./scripts/feeds install -a`: create feed package symlinks in `package/feeds/`.
- `make menuconfig`: choose target, toolchain, kernel, and package options.
- `make`: build the selected firmware image and packages.
- `make download`: prefetch source archives for the selected configuration.
- `make check`: run build-system validation checks.
- `scripts/deptest.sh [--lean|-j N] [packages...]`: run automated package build
  dependency tests.
- `make clean`, `make dirclean`, `make distclean`: remove progressively more
  generated build state.

## Coding Style & Naming Conventions

Use LF line endings and keep files ending with a final newline. Avoid trailing
whitespace; `.patch` files have stricter whitespace rules in `.gitattributes`.
Follow local style in nearby package Makefiles, shell scripts, DTS files, and
kernel patches. Package and target changes should use existing naming patterns
such as `package/<name>`, `target/linux/<platform>`, and `Device/<vendor>_<model>`.

## Testing Guidelines

There is no single root `tests/` suite. Prefer the narrowest useful validation:
run `make check` for metadata/build-system changes, `scripts/deptest.sh` for
package dependency coverage, and package-specific targets such as
`make package/<pkg>/compile` or `make package/<pkg>/check` when available. For
kernel or target patch changes, select the affected target in `.config` before
building or refreshing patches.

## Commit & Pull Request Guidelines

Recent history uses short scope prefixes such as `kernel:`, `ramips:`,
`netifd:`, `scripts:`, and `package:` followed by an imperative summary. Keep
commits focused and explain user-visible behavior, hardware impact, or build
impact in the body when relevant. For new device support, include hardware
specification, flash instructions, and MAC address layout. Refresh quilt-managed
patches with `make target/linux/refresh` or `make package/<pkg>/refresh`, not
`git format-patch`. PRs should describe the change, affected targets/packages,
and the validation performed.
