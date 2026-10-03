#!/usr/bin/env bash
# Upload a northstar-audit-archive/1 package directory to S3 with Object Lock
# in COMPLIANCE mode (WORM). The retention period matches the archive's own
# retain_until (default 180 days, EU AI Act Art. 12).
#
# Prerequisites: aws CLI v2, a bucket with Object Lock ENABLED (must be set
# at bucket creation; it cannot be added later), and credentials with
# s3:PutObject + s3:PutObjectRetention.
#
# Usage: scripts/s3-worm-upload.sh <archive-dir> <s3://bucket/prefix>
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <archive-dir> <s3://bucket/prefix>" >&2
  exit 64
fi

ARCHIVE_DIR="$1"
DEST="$2"

if [ ! -f "$ARCHIVE_DIR/archive-manifest.json" ]; then
  echo "error: $ARCHIVE_DIR is not a northstar audit archive (no archive-manifest.json)" >&2
  exit 1
fi

# Verify the package before it leaves the building.
if ! python3 -c "
import sys; sys.path.insert(0, 'components/northstar-agent-runtime')
from audit_archive import verify_archive
r = verify_archive('$ARCHIVE_DIR')
sys.exit(0 if r.ok else 1)
"; then
  echo "error: archive failed verification, refusing to upload" >&2
  exit 1
fi

RETAIN_UNTIL=$(python3 -c "
import json; print(json.load(open('$ARCHIVE_DIR/archive-manifest.json'))['retain_until'])")

echo "uploading $ARCHIVE_DIR -> $DEST (retain until $RETAIN_UNTIL, COMPLIANCE)"

# Manifest last: a reader that finds archive-manifest.json sees a complete package.
for f in "$ARCHIVE_DIR"/*; do
  [ "$(basename "$f")" = "archive-manifest.json" ] && continue
  aws s3api put-object \
    --bucket "$(echo "$DEST" | sed -e 's#s3://##' -e 's#/.*##')" \
    --key "$(echo "$DEST" | sed -e 's#s3://[^/]*##' -e 's#^/##')/$(basename "$f")" \
    --body "$f" \
    --object-lock-mode COMPLIANCE \
    --object-lock-retain-until-date "$RETAIN_UNTIL" \
    --checksum-algorithm SHA256 \
    --output text --query ETag
done
aws s3api put-object \
  --bucket "$(echo "$DEST" | sed -e 's#s3://##' -e 's#/.*##')" \
  --key "$(echo "$DEST" | sed -e 's#s3://[^/]*##' -e 's#^/##')/archive-manifest.json" \
  --body "$ARCHIVE_DIR/archive-manifest.json" \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "$RETAIN_UNTIL" \
  --checksum-algorithm SHA256 \
  --output text --query ETag

echo "done. Objects are WORM-locked until $RETAIN_UNTIL; even the bucket owner cannot delete them before then."
