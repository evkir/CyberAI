"""What the probe advertises to a target it is scanning.

URL-mode elicitation arrived with revision 2025-11-25: a server may answer a
request by asking the client to open a URL, and a client that advertises the
capability has said it is willing. A scanner that says so to the endpoint it
is scanning has agreed to follow that endpoint's links.

Today it does not, and nothing in this repository says so -- the guarantee is
structural. `ClientSession` advertises elicitation only when an elicitation
callback was supplied, `probe` supplies none, and the default callback is
therefore the one left in place. Someone adding a callback for a form prompt
would turn on URL mode in the same line: measured here, the SDK builds
`ElicitationCapability(form=..., url=...)` as one object with no separate
switch. So the control below is not decoration. It is the whole reason this
file exists: it shows that the first assertion can fail, and how.

The capability set is read off a built session rather than off the source of
`probe`, because reading the source would assert the code as written rather
than what the SDK does with it. `_build_capabilities` is private and this
test is coupled to it knowingly; the SDK offers no public way to ask a
session what it advertises before a transport is live.
"""

from __future__ import annotations

from typing import Any

import anyio
import mcp.types as types
from mcp import ClientSession


def _advertised(**session_kwargs: Any) -> dict[str, Any]:
    """The capability ad a session of this shape would send."""

    result: dict[str, Any] = {}

    async def build() -> None:
        _, client_read = anyio.create_memory_object_stream[Any](1)
        client_write, _ = anyio.create_memory_object_stream[Any](1)
        session = ClientSession(client_read, client_write, **session_kwargs)
        capabilities = session._build_capabilities("2025-11-25")
        result.update(capabilities.model_dump(mode="json", by_alias=True, exclude_none=True))

    anyio.run(build)
    return result


async def _elicitation_callback(
    context: Any, params: types.ElicitRequestParams
) -> types.ElicitResult | types.ErrorData:
    return types.ErrorData(code=types.INVALID_REQUEST, message="not supported")


def test_the_probe_advertises_no_elicitation() -> None:
    assert "elicitation" not in _advertised()


def test_one_callback_would_advertise_url_mode_too() -> None:
    """The control: form and URL mode are not separable at the SDK's seam."""
    advertised = _advertised(elicitation_callback=_elicitation_callback)
    assert "url" in advertised["elicitation"]
    assert "form" in advertised["elicitation"]
