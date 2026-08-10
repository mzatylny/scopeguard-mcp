"""Domain-specific errors returned by ScopeGuard services."""


class ScopeGuardError(RuntimeError):
    """Base class for expected ScopeGuard failures."""


class ConfigurationError(ScopeGuardError):
    """Raised when operator-controlled configuration is invalid."""


class InvalidTargetError(ScopeGuardError):
    """Raised when a target cannot be safely normalized."""


class EngagementNotFoundError(ScopeGuardError):
    """Raised when an engagement ID does not exist."""


class AuthorizationError(ScopeGuardError):
    """Raised when an engagement does not authorize an operation."""


class NetworkProbeError(ScopeGuardError):
    """Raised when a bounded network probe cannot be completed safely."""
