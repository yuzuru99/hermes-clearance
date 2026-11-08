"""Pure policy logic: tiers, tool groups, identity keys and decisions.

Nothing in this module imports Hermes, so every rule here is unit-testable on its own.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

TIER_ORDER = ("blocked", "guest", "user", "admin", "owner")

# Shorthands usable in a tier's allow / deny lists. Anything else is a tool-name glob
# (``mcp__github__*``), so a tool Hermes adds later is denied for restricted tiers until
# the owner names it.
GROUPS: dict[str, tuple[str, ...]] = {
    "@web": ("web_search", "web_extract", "x_search"),
    "@vision": ("vision_analyze", "video_analyze"),
    "@media": ("image_generate", "text_to_speech", "video_generate", "xai_video_edit", "xai_video_extend"),
    "@read": ("read_file", "search_files"),
    "@write": ("write_file", "patch"),
    "@shell": ("terminal", "process_manage", "execute_code", "close_terminal", "read_terminal"),
    "@browser": ("browser_*",),
    "@memory": ("memory", "session_search"),
    "@skills": ("skills_list", "skill_view"),
    "@skills_write": ("skill_manage",),
    "@schedule": ("cronjob_manage", "kanban_*"),
    "@delegate": ("delegate_task", "a2a_*"),
    "@mcp": ("mcp__*",),
    "@desktop": ("computer_use", "desktop_*", "focus_pane", "gui_tour", "set_theme", "show_tip",
                 "annotate_preview", "drive_preview", "read_window_below", "react_to_message"),
    "@chat": ("clarify", "todo_list"),
}

DEFAULT_TIERS: dict[str, dict[str, Any]] = {
    "owner": {"allow": ["*"], "deny": [], "rate_per_hour": 0, "chat": True, "manage": True, "audit": True},
    "admin": {"allow": ["*"], "deny": [], "rate_per_hour": 0, "chat": True, "manage": False, "audit": True},
    "user": {"allow": ["@web", "@vision", "@media", "@skills", "@chat"], "deny": [], "rate_per_hour": 60,
             "chat": True, "manage": False, "audit": False},
    "guest": {"allow": ["@chat"], "deny": [], "rate_per_hour": 20, "chat": True, "manage": False, "audit": False},
    "blocked": {"allow": [], "deny": ["*"], "rate_per_hour": 0, "chat": False, "manage": False, "audit": False},
}

# Platforms whose turns come from the machine itself (CLI, TUI, Desktop, ACP editors).
LOCAL_PLATFORMS = frozenset({"", "cli", "tui", "desktop", "local", "acp"})


@dataclass(frozen=True)
class Tier:
    name: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    rate_per_hour: int = 0
    chat: bool = True
    manage: bool = False
    audit: bool = False

    @property
    def unrestricted(self) -> bool:
        return not self.deny and "*" in self.allow


@dataclass(frozen=True)
class Identity:
    """Who sent the message the agent is working on right now."""

    kind: str  # "local" | "cron" | "gateway" | "unknown"
    key: str  # "telegram:123", "webhook:github", "local", "cron", "telegram:?"
    platform: str = ""
    user_id: str = ""
    user_name: str = ""

    def label(self) -> str:
        if self.user_name and self.kind == "gateway":
            return f"{self.key} ({self.user_name})"
        return self.key


@dataclass(frozen=True)
class Decision:
    allowed: bool
    tier: str
    rule: str  # the pattern that decided, or "default-deny"


@dataclass
class Policy:
    tiers: dict[str, Tier]
    users: dict[str, str] = field(default_factory=dict)
    default_tier: str = "guest"
    local_tier: str = "owner"
    cron_tier: str = "owner"
    warnings: list[str] = field(default_factory=list)

    # -------------------------------------------------------------- lookups

    def tier_named(self, name: str) -> Tier:
        """A configured tier; an unknown name falls back to ``guest`` (fail closed, never open)."""
        tier = self.tiers.get(name)
        if tier is not None:
            return tier
        return self.tiers.get("guest") or Tier("guest", ("@chat",), (), 20)

    def tier_name_for(self, ident: Identity) -> str:
        if ident.kind == "local":
            return self.local_tier
        if ident.kind == "cron":
            return self.cron_tier
        if ident.kind == "unknown":
            return self.default_tier
        for key in (ident.key, f"{ident.platform}:*", "*"):
            if key in self.users:
                return self.users[key]
        return self.default_tier

    def tier_for(self, ident: Identity) -> Tier:
        return self.tier_named(self.tier_name_for(ident))

    # ------------------------------------------------------------ decisions

    def decide(self, ident: Identity, tool_name: str) -> Decision:
        tier = self.tier_for(ident)
        return decide_tool(tier, tool_name)


def expand(patterns: Iterable[str]) -> list[str]:
    out: list[str] = []
    for p in patterns:
        p = str(p).strip()
        if not p:
            continue
        out.extend(GROUPS.get(p, (p,)) if p.startswith("@") else (p,))
    return out


def _match(tool_name: str, patterns: Iterable[str]) -> str | None:
    for raw in patterns:
        for pat in expand([raw]):
            if fnmatch.fnmatchcase(tool_name, pat):
                return raw
    return None


def decide_tool(tier: Tier, tool_name: str) -> Decision:
    """Deny wins over allow; a tool no rule names is denied."""
    hit = _match(tool_name, tier.deny)
    if hit is not None:
        return Decision(False, tier.name, f"deny {hit}")
    hit = _match(tool_name, tier.allow)
    if hit is not None:
        return Decision(True, tier.name, f"allow {hit}")
    return Decision(False, tier.name, "default-deny")


# ------------------------------------------------------------------ building


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _as_int(value: Any, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def build_tiers(overrides: Any, warnings: list[str]) -> dict[str, Tier]:
    """Defaults merged with the owner's ``tiers`` setting, field by field. Custom tier names are allowed."""
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in DEFAULT_TIERS.items()}
    if isinstance(overrides, Mapping):
        for name, spec in overrides.items():
            name = str(name).strip().lower()
            if not name:
                continue
            if not isinstance(spec, Mapping):
                warnings.append(f"tiers.{name} is not a mapping; ignored")
                continue
            base = merged.setdefault(name, dict(DEFAULT_TIERS["guest"]) | {"allow": [], "deny": []})
            for k, v in spec.items():
                if k in ("allow", "deny"):
                    base[k] = _as_list(v)
                elif k == "rate_per_hour":
                    base[k] = _as_int(v, base.get(k, 0))
                elif k in ("chat", "manage", "audit"):
                    base[k] = bool(v)
                else:
                    warnings.append(f"tiers.{name}.{k} is not a known field; ignored")
    elif overrides not in (None, ""):
        warnings.append("tiers is not a mapping; using the default tiers")
    # The owner tier always keeps full access and management, so a typo can never lock the owner out.
    merged["owner"].update({"allow": ["*"], "deny": [], "chat": True, "manage": True, "audit": True})
    tiers: dict[str, Tier] = {}
    for name, spec in merged.items():
        tiers[name] = Tier(
            name=name,
            allow=tuple(_as_list(spec.get("allow"))),
            deny=tuple(_as_list(spec.get("deny"))),
            rate_per_hour=_as_int(spec.get("rate_per_hour"), 0),
            chat=bool(spec.get("chat", True)),
            manage=bool(spec.get("manage", False)),
            audit=bool(spec.get("audit", False)),
        )
    return tiers


def normalize_user_key(key: Any) -> str | None:
    """``telegram:123`` style key, lower-cased platform; ``*`` and ``platform:*`` are wildcards."""
    text = str(key).strip()
    if text == "*":
        return "*"
    if ":" not in text:
        return None
    platform, _, uid = text.partition(":")
    platform, uid = platform.strip().lower(), uid.strip()
    if not platform or not uid:
        return None
    return f"{platform}:{uid}"


def build_policy(get: Callable[[str, Any], Any]) -> Policy:
    warnings: list[str] = []
    tiers = build_tiers(get("tiers", None), warnings)
    users: dict[str, str] = {}
    raw_users = get("users", None)
    if isinstance(raw_users, Mapping):
        for k, v in raw_users.items():
            if v is None or str(v).strip() == "":
                continue  # unassigned (``/clearance unset`` writes null: settings writes deep-merge)
            key = normalize_user_key(k)
            tier = str(v).strip().lower()
            if key is None:
                warnings.append(f"users: {k!r} is not 'platform:user_id'; ignored")
                continue
            if tier not in tiers:
                warnings.append(f"users: {key} has unknown tier {tier!r}; treated as guest")
                tier = "guest"
            users[key] = tier
    elif raw_users not in (None, ""):
        warnings.append("users is not a mapping; no users assigned")

    def _tier_setting(name: str, default: str) -> str:
        value = str(get(name, default) or default).strip().lower()
        if value not in tiers:
            warnings.append(f"{name} {value!r} is not a tier; using {default!r}")
            return default
        return value

    return Policy(
        tiers=tiers,
        users=users,
        default_tier=_tier_setting("default_tier", "guest"),
        local_tier=_tier_setting("local_tier", "owner"),
        cron_tier=_tier_setting("cron_tier", "owner"),
        warnings=warnings,
    )


# ------------------------------------------------------------------ identity


def make_identity(platform: str, user_id: str, user_name: str = "", *, cron: bool = False) -> Identity:
    platform = (platform or "").strip().lower()
    user_id = (user_id or "").strip()
    if cron:
        return Identity("cron", "cron", platform, user_id, user_name)
    if platform in LOCAL_PLATFORMS and not user_id:
        return Identity("local", "local", platform, "", user_name)
    if not user_id:
        # A gateway turn without a sender id: never guess, fall to default_tier.
        return Identity("unknown", f"{platform or 'gateway'}:?", platform, "", user_name)
    # Webhook routes already carry their platform ("webhook:github"): don't double it.
    uid = user_id[len(platform) + 1:] if user_id.lower().startswith(platform + ":") else user_id
    return Identity("gateway", f"{platform}:{uid}", platform, uid, user_name)


def describe_tier(tier: Tier) -> str:
    if tier.unrestricted:
        return "all tools"
    if not tier.chat:
        return "no access"
    allow = ", ".join(tier.allow) if tier.allow else "no tools"
    deny = f"; denied: {', '.join(tier.deny)}" if tier.deny else ""
    return allow + deny


def allowed_tool_names(tier: Tier, known_tools: Iterable[str]) -> list[str]:
    return sorted(t for t in known_tools if decide_tool(tier, t).allowed)
