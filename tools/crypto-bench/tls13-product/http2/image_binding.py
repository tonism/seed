"""Location of an explicitly prepared, byte-bound HTTP/2 test image."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
TEST_IMAGE = Path(os.environ.get("SEED_HTTP2_TEST_IMAGE", ROOT / "build/ibm_pc_5150/http2-tests"))
