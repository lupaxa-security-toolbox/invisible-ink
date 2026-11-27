"""Property checks for reversible concealment."""

from hypothesis import given, settings
from hypothesis import strategies as st

from lupaxa.invisible_ink.config import fast_settings
from lupaxa.invisible_ink.engine import hide, reveal
from lupaxa.invisible_ink.errors import CapacityError

COVER = "Hello from the harbour."


@given(message=st.text(max_size=24))
@settings(max_examples=30)
def test_zero_width_reverses(message: str) -> None:
    options = fast_settings()
    text, _warnings = hide(COVER, message.encode(), options, method_name="zero-width", framed=True, placement="distributed", seed=0, password=None, binary=False)
    found = reveal(text, options, method_name="zero-width", format_name="framed", placement="distributed", seed=0, length=None, password=None, find_all=False)
    assert found[0].payload == message.encode()


def test_capacity_is_enforced() -> None:
    options = fast_settings()
    options.max_message_bytes = 4
    try:
        hide(COVER, b"too-long", options, method_name="tag", framed=False, placement="end", seed=0, password=None, binary=True)
    except CapacityError:
        return
    raise AssertionError("oversized payload was accepted")
