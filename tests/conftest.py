"""Pytest defaults for local runtime integrations."""

import os


# Unit/integration tests should not invoke the real MemPalace embedding/backend
# stack unless a test explicitly enables and fakes that boundary.
os.environ.setdefault("FIM_MEMPALACE_ENABLED", "0")
