"""Source adapter interface."""

from __future__ import annotations

import abc

from packguard.models import PackageCoordinate, ResolvedPackage


class PackageSource(abc.ABC):
    @abc.abstractmethod
    def resolve(self, coordinate: PackageCoordinate) -> ResolvedPackage:
        """Resolve a package to a downloadable artifact."""
