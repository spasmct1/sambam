#!/bin/sh
set -eu

# Clean up generated fish completion file if present.
rm -f /usr/share/fish/vendor_completions.d/sambam.fish || true
