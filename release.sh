#!/bin/bash
set -e

# Load release config
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/.release-config"

VERSION="$1"
if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh <version>"
    echo "Example: ./release.sh 1.2.10"
    exit 1
fi

TAG="v$VERSION"
GO="${GO:-/usr/local/go/bin/go}"

echo "==> Building $TAG"

# Build both platforms
echo "  Building linux/amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -ldflags="-s -w" -o sambam-linux-amd64 .
echo "  Building linux/arm64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO" build -ldflags="-s -w" -o sambam-linux-arm64 .

# Compress
echo "  Compressing with UPX..."
upx --best sambam-linux-amd64 sambam-linux-arm64

# Upload to GitLab packages
echo "==> Uploading to GitLab packages"
for ARCH in amd64 arm64; do
    echo "  Uploading sambam-linux-$ARCH..."
    curl -sf --request PUT \
         --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
         --upload-file "sambam-linux-$ARCH" \
         "$GITLAB_API/packages/generic/sambam/$VERSION/sambam-linux-$ARCH" > /dev/null
done

# Create GitLab release
echo "==> Creating GitLab release $TAG"
CHANGES="${2:-See git log for changes}"
curl -sf --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
     --header "Content-Type: application/json" \
     --data "$(cat <<EOF
{
  "tag_name": "$TAG",
  "name": "$TAG",
  "description": "## Changes\n\n$CHANGES\n\n## Downloads\n\n- [sambam-linux-amd64](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-linux-amd64)\n- [sambam-linux-arm64](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-linux-arm64)"
}
EOF
)" \
     "$GITLAB_API/releases" > /dev/null

echo "==> Released $TAG"
echo "    https://git.tcjew.win/yaron/sambam/-/releases/$TAG"
