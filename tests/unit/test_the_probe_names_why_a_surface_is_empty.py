"""Three causes of an empty list, told apart by what `_dump` returns.

These exercise the function rather than its source: an unsupported capability
answers with a code and is not a failure, anything else is, and a client-side
signature mismatch must not read as a server that answered nothing.
"""

from typing import Any, cast

from mcp import ClientSession

from cyberai.mcp.client_probe import _dump, inventory_with_causes

_async_run = __import__("asyncio").run


class _Item:
    def __init__(self, name: str) -> None:
        self._name = name

    def model_dump(self, **_kwargs: Any) -> dict[str, Any]:
        return {"name": self._name}


class _Page:
    """One page of any capability: the probe asks for the list by attribute name."""

    def __init__(self, items: list[_Item], attr: str = "tools") -> None:
        setattr(self, attr, items)
        self.next_cursor = None


class _CodedError(Exception):
    """Stands in for mcp's MCPError: the probe reads `.code`, not the class."""

    def __init__(self, code: int) -> None:
        super().__init__(f"code {code}")
        self.code = code


def test_a_server_that_answers_method_not_found_reports_no_failure() -> None:
    async def missing(**_kwargs: Any) -> Any:
        raise _CodedError(-32601)

    items, failure = _async_run(_dump(missing, "tools"))
    assert items == []
    assert failure is None, "a capability the server does not implement is not a failure"


def test_a_read_that_failed_names_itself() -> None:
    async def broken(**_kwargs: Any) -> Any:
        raise TimeoutError("read timed out")

    items, failure = _async_run(_dump(broken, "tools"))
    assert items == []
    assert failure is not None, "a timed-out tools/list must not read as a clean server"
    assert "TimeoutError" in failure


def test_an_error_carrying_another_code_is_a_failure() -> None:
    async def internal(**_kwargs: Any) -> Any:
        raise _CodedError(-32603)

    _items, failure = _async_run(_dump(internal, "tools"))
    assert failure is not None, "only method-not-found means the server answered"


def test_a_page_missing_the_asked_for_attribute_is_a_failure() -> None:
    """The client-side cause: the SDK renamed the field and nothing answered wrong."""

    async def renamed(**_kwargs: Any) -> Any:
        return _Page([_Item("read_file")], attr="toolz")

    items, failure = _async_run(_dump(renamed, "tools"))
    assert items == []
    assert failure is not None, "a surface this client failed to read is not an empty server"
    assert "AttributeError" in failure


def test_a_served_surface_carries_no_cause() -> None:
    async def served(**_kwargs: Any) -> Any:
        return _Page([_Item("read_file")])

    items, failure = _async_run(_dump(served, "tools"))
    assert items == [{"name": "read_file"}]
    assert failure is None


def test_the_real_sdk_error_still_carries_a_code() -> None:
    """If the SDK stops exposing `.code`, the branch above silently stops working."""
    from mcp.shared.exceptions import MCPError

    assert MCPError(code=-32601, message="nope").code == -32601


def test_the_inventory_keys_causes_by_capability() -> None:
    class _Session:
        async def list_tools(self, **_kwargs: Any) -> Any:
            raise TimeoutError("slow")

        async def list_prompts(self, **_kwargs: Any) -> Any:
            raise _CodedError(-32601)

        async def list_resources(self, **_kwargs: Any) -> Any:
            return _Page([], attr="resources")

    surface, causes = _async_run(inventory_with_causes(cast(ClientSession, _Session())))
    assert surface == {"tools": [], "prompts": [], "resources": []}
    assert set(causes) == {"tools"}, "only the read that failed belongs in the mapping"
