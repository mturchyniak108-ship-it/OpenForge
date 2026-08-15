"""Transport-independent SecureChat identity model."""

from __future__ import annotations

from dataclasses import dataclass
import re
import uuid


_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class Identity:
    """Public application identity for a SecureChat participant.

    This layer deliberately contains no private keys, networking,
    Tor configuration, SOCKS5 configuration, or UI concerns.
    """

    identity_id: str
    display_name: str

    def __post_init__(self) -> None:
        identity_id = self.identity_id.strip().lower()
        display_name = self.display_name.strip()

        if not _ID_RE.fullmatch(identity_id):
            raise ValueError("identity_id must be a valid UUID")

        if not display_name:
            raise ValueError("display_name cannot be empty")

        if len(display_name) > 128:
            raise ValueError("display_name is too long")

        object.__setattr__(self, "identity_id", identity_id)
        object.__setattr__(self, "display_name", display_name)

    @classmethod
    def create(cls, display_name: str) -> "Identity":
        """Create a new identity with a random UUID."""

        return cls(
            identity_id=str(uuid.uuid4()),
            display_name=display_name,
        )

    def to_dict(self) -> dict[str, str]:
        """Return the public identity representation."""

        return {
            "identity_id": self.identity_id,
            "display_name": self.display_name,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Identity":
        """Restore an identity from its public representation."""

        required = {"identity_id", "display_name"}
        missing = required - value.keys()

        if missing:
            raise ValueError(
                f"missing identity fields: {sorted(missing)}"
            )

        if not isinstance(value["identity_id"], str):
            raise ValueError("identity_id must be a string")

        if not isinstance(value["display_name"], str):
            raise ValueError("display_name must be a string")

        return cls(
            identity_id=value["identity_id"],
            display_name=value["display_name"],
        )
