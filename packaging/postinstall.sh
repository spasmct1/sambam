#!/bin/sh
set -eu

# Install fish completion only when fish is present.
if [ -x /usr/bin/fish ] && [ -f /usr/share/doc/sambam/completions/sambam.fish ]; then
    install -D -m 0644 /usr/share/doc/sambam/completions/sambam.fish /usr/share/fish/vendor_completions.d/sambam.fish
fi
