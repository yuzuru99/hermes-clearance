"""The ``/clearance`` slash command."""

from __future__ import annotations

from typing import Any, Callable

from .policy import TIER_ORDER, Identity, describe_tier, make_identity, normalize_user_key
from .runtime import Runtime

USAGE = (
    "Usage:\n"
    "  /clearance                 your identity, tier and tools\n"
    "  /clearance tiers           every tier and what it allows\n"
    "  /clearance users           who is assigned to which tier (admin+)\n"
    "  /clearance audit [n]       last n refused actions (admin+)\n"
    "  /clearance set <platform:user_id> <tier>   assign a tier (owner)\n"
    "  /clearance unset <platform:user_id>        back to the default tier (owner)"
)


def caller_identity(platform: str = "", source: Any = None) -> Identity:
    """Identity of whoever typed the command, from the gateway's SessionSource (never from text)."""
    if source is None:
        return make_identity(platform or "", "")
    plat = getattr(source, "platform", None)
    plat = getattr(plat, "value", plat) or platform or ""
    return make_identity(str(plat), str(getattr(source, "user_id", "") or ""), str(getattr(source, "user_name", "") or ""))


def _tier_sort_key(name: str) -> tuple[int, str]:
    return (TIER_ORDER.index(name) if name in TIER_ORDER else len(TIER_ORDER), name)


class Commands:
    def __init__(self, runtime: Runtime, set_config: Callable[[str, Any], None]) -> None:
        self.rt = runtime
        self._set_config = set_config

    def handle(self, raw_args: str = "", *, platform: str = "", source: Any = None, **_: Any) -> str:
        ident = caller_identity(platform, source)
        parts = (raw_args or "").split()
        sub = parts[0].lower() if parts else "me"
        policy = self.rt.policy()
        tier = policy.tier_for(ident)
        try:
            if sub in ("me", "whoami"):
                return self._me(ident)
            if sub == "tiers":
                return self._tiers()
            if sub in ("help", "-h", "--help"):
                return USAGE
            if sub == "users":
                if not tier.audit:
                    return f"Only admin or owner can list users (you are {tier.name})."
                return self._users()
            if sub == "audit":
                if not tier.audit:
                    return f"Only admin or owner can read the audit log (you are {tier.name})."
                n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
                return self._audit(min(max(n, 1), 100))
            if sub in ("set", "unset"):
                if not tier.manage:
                    self.rt._audit("manage_denied", ident, tier.name, command=sub)
                    return f"Only the owner can change tiers (you are {tier.name})."
                return self._set(ident, sub, parts[1:])
        except Exception as exc:  # a command must answer, never raise into the gateway
            return f"clearance: {type(exc).__name__}: {exc}"
        return USAGE

    # ------------------------------------------------------------------ views

    def _me(self, ident: Identity) -> str:
        policy = self.rt.policy()
        tier = policy.tier_for(ident)
        rate = (
            f"{self.rt.rate.used(ident.key)}/{tier.rate_per_hour} messages this hour"
            if tier.rate_per_hour else "no rate limit"
        )
        return f"You are {ident.label()}.\nTier: {tier.name}\nTools: {describe_tier(tier)}\nRate: {rate}"

    def _tiers(self) -> str:
        policy = self.rt.policy()
        lines = ["Tiers:"]
        for name in sorted(policy.tiers, key=_tier_sort_key):
            t = policy.tiers[name]
            rate = f", {t.rate_per_hour}/h" if t.rate_per_hour else ""
            lines.append(f"  {name}: {describe_tier(t)}{rate}")
        lines.append(
            f"Defaults: unknown senders = {policy.default_tier}, local sessions = {policy.local_tier}, "
            f"cron = {policy.cron_tier}"
        )
        return "\n".join(lines)

    def _users(self) -> str:
        policy = self.rt.policy()
        if not policy.users:
            return f"No users assigned. Everyone on a messaging platform is {policy.default_tier}."
        rows = sorted(policy.users.items(), key=lambda kv: (_tier_sort_key(kv[1]), kv[0]))
        return "Users:\n" + "\n".join(f"  {k} -> {v}" for k, v in rows)

    def _audit(self, n: int) -> str:
        recs = self.rt.audit.tail(n)
        if not recs:
            return "Audit log is empty."
        lines = [f"Last {len(recs)} audit events:"]
        for r in recs:
            what = r.get("tool") or r.get("command") or r.get("target") or ""
            extra = f" -> {r['new_tier']}" if r.get("new_tier") else ""
            lines.append(f"  {r.get('ts', '?')}  {r.get('event')}  {r.get('who')} [{r.get('tier')}]  {what}{extra}")
        return "\n".join(lines)

    # --------------------------------------------------------------- changes

    def _set(self, ident: Identity, sub: str, args: list[str]) -> str:
        policy = self.rt.policy()
        if not args:
            return USAGE
        key = normalize_user_key(args[0])
        if key is None:
            return f"{args[0]!r} is not 'platform:user_id' (for example telegram:123456789)."
        if sub == "unset":
            if key not in policy.users:
                return f"{key} has no tier assigned."
            # Hermes deep-merges plugin settings, so a key cannot be dropped from the dict: null it.
            value: Any = None
            new_tier = policy.default_tier
        else:
            if len(args) < 2:
                return USAGE
            new_tier = args[1].strip().lower()
            if new_tier not in policy.tiers:
                return f"Unknown tier {new_tier!r}. Tiers: {', '.join(sorted(policy.tiers, key=_tier_sort_key))}."
            value = new_tier
        users: dict[str, Any] = dict(policy.users)
        users[key] = value
        self._set_config("users", users)
        self.rt.invalidate()
        # Read the saved settings back: a change that did not land must never be reported as done.
        effective = self.rt.policy().users.get(key, "")
        expected = "" if value is None else new_tier
        if effective != expected:
            self.rt._audit("tier_set_failed", ident, policy.tier_for(ident).name, target=key, new_tier=new_tier)
            return f"Could not save the change for {key} (still {effective or policy.default_tier}). Check config.yaml."
        self.rt._audit("tier_set", ident, policy.tier_for(ident).name, target=key, new_tier=new_tier)
        return f"{key} is now {new_tier}."
