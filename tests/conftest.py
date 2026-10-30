import os

import pytest

from bastion.config import RulesConfig
from bastion.crypto import ScryptParams
from bastion.events import Event

# cheap scrypt just for tests (the product default is n=2**17)
FAST_SCRYPT = ScryptParams(n=2 ** 10, r=8, p=1)


@pytest.fixture
def fast_scrypt():
    return FAST_SCRYPT


@pytest.fixture
def config():
    return RulesConfig.default()


@pytest.fixture
def make_files(tmp_path):
    """Create N fictional text files and return their folder."""
    def _make(n=5, subdir="data", size=2000):
        d = tmp_path / subdir
        d.mkdir(exist_ok=True)
        for i in range(n):
            (d / f"f{i:02d}.txt").write_text(f"fictional content {i} " * (size // 20))
        return d
    return _make


def ev(type_, path, ts=0.0, **kw):
    return Event(type_, path, ts, **kw)


def noise(n=4096):
    return os.urandom(n)
