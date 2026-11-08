"""Clearance: per-user tool permissions for Hermes on messaging platforms and webhooks.

Hermes's gateway allowlist decides *who* may talk to the agent; Clearance decides *what each of
them may make it do*. Every tool call is checked in code against the sender's tier, so a prompt
cannot talk its way past it.
"""

from __future__ import annotations

from typing import Any

__all__ = ["register"]


def register(ctx: Any) -> None:
    # Imported here so that merely importing this file (e.g. test collection) needs no package context.
    from .commands import Commands
    from .runtime import Runtime

    runtime = Runtime(ctx.get_config)
    commands = Commands(runtime, ctx.set_config)
    ctx.register_hook("pre_tool_call", runtime.pre_tool_call)
    ctx.register_hook("pre_llm_call", runtime.pre_llm_call)
    ctx.register_command(
        "clearance",
        handler=commands.handle,
        description="Show or change who may use which tools (tiers, users, audit)",
        args_hint="[tiers|users|audit [n]|set <platform:id> <tier>|unset <platform:id>]",
    )
