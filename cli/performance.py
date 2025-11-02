#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
"""Performance optimization and caching system for Devkit.

Provides:
- Package installation parallelization
- Installation result caching
- Performance metrics collection
- Intelligent cache invalidation
"""

import hashlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class CacheManager:
    """Manage installation and configuration caches."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        """Initialize cache manager.

        Args:
            cache_dir: Directory to store cache files (defaults to ~/.devkit/cache)
        """
        self.cache_dir = cache_dir or Path.home() / ".devkit" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def get_cache_file(self, key: str) -> Path:
        """Get path to cache file for key."""
        safe_key = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.cache"

    def set(self, key: str, value: dict[str, Any], ttl_hours: int = 24) -> None:
        """Store value in cache with optional TTL.

        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            ttl_hours: Time-to-live in hours (default 24)
        """
        cache_file = self.get_cache_file(key)
        expires_at = datetime.now(tz=UTC) + timedelta(hours=ttl_hours)

        cache_data = {
            "key": key,
            "value": value,
            "created": datetime.now(tz=UTC).isoformat(),
            "expires": expires_at.isoformat(),
            "ttl_hours": ttl_hours,
        }

        try:
            with cache_file.open("w", encoding="utf-8") as f:
                json.dump(cache_data, f)
            self.logger.debug("Cached %s for %d hours", key, ttl_hours)
        except OSError as e:
            self.logger.warning("Failed to cache %s: %s", key, e)

    def get(self, key: str) -> Any | None:
        """Retrieve value from cache if valid.

        Args:
            key: Cache key

        Returns:
            Cached value if valid, None if expired or not found
        """
        cache_file = self.get_cache_file(key)

        if not cache_file.exists():
            return None

        try:
            with cache_file.open(encoding="utf-8") as f:
                cache_data: dict[str, Any] = json.load(f)

            expires = datetime.fromisoformat(cache_data["expires"])
            if datetime.now(tz=UTC) > expires:
                cache_file.unlink()  # Delete expired cache
                self.logger.debug("Cache expired for %s", key)
                return None

            self.logger.debug("Cache hit for %s", key)
            value: Any = cache_data["value"]
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as e:
            self.logger.warning("Failed to read cache for %s: %s", key, e)
            return None

        return value

    def invalidate(self, key: str) -> None:
        """Invalidate cache entry."""
        cache_file = self.get_cache_file(key)
        if cache_file.exists():
            try:
                cache_file.unlink()
                self.logger.debug("Invalidated cache for %s", key)
            except (OSError, PermissionError) as e:
                self.logger.warning("Failed to invalidate cache for %s: %s", key, e)

    def clear(self) -> None:
        """Clear all cache entries."""
        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink()
            self.logger.info("Cleared all cache entries")
        except (OSError, PermissionError) as e:
            self.logger.warning("Failed to clear cache: %s", e)

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        cache_files = list(self.cache_dir.glob("*.cache"))
        total_size = sum(f.stat().st_size for f in cache_files)

        return {
            "entries": len(cache_files),
            "size_bytes": total_size,
            "size_mb": round(total_size / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir),
        }


class PerformanceMonitor:
    """Monitor and track performance metrics."""

    def __init__(self) -> None:
        """Initialize performance monitor."""
        self.metrics: dict[str, list[float]] = {}
        self.logger = logging.getLogger(__name__)

    def start_timer(self, label: str = "") -> float:
        """Start a timer for performance measurement.

        Args:
            label: Label for the timer (optional, used for tracking)

        Returns:
            Start time (for manual tracking if needed)
        """
        if label and label not in self.metrics:
            self.metrics[label] = []
        return time.time()

    def record_metric(self, label: str, duration: float, unit: str = "seconds") -> None:
        """Record a performance metric.

        Args:
            label: Metric label
            duration: Duration value
            unit: Unit of measurement (default "seconds")
        """
        if label not in self.metrics:
            self.metrics[label] = []

        self.metrics[label].append(duration)
        self.logger.debug("Metric %s: %.2f %s", label, duration, unit)

    def end_timer(self, label: str, start_time: float) -> float:
        """End a timer and record the metric.

        Args:
            label: Metric label
            start_time: Start time from start_timer()

        Returns:
            Elapsed duration in seconds
        """
        elapsed = time.time() - start_time
        self.record_metric(label, elapsed)
        return elapsed

    def get_summary(self) -> dict[str, dict[str, Any]]:
        """Get performance metrics summary."""
        summary: dict[str, dict[str, Any]] = {}

        for label, durations in self.metrics.items():
            if not durations:
                continue

            summary[label] = {
                "count": len(durations),
                "min": round(min(durations), 2),
                "max": round(max(durations), 2),
                "avg": round(sum(durations) / len(durations), 2),
                "total": round(sum(durations), 2),
            }

        return summary

    def print_report(self) -> None:
        """Print performance metrics report."""
        summary = self.get_summary()

        if not summary:
            return

        for _label, stats in sorted(summary.items()):
            count = stats.get("count", 0)
            if count:
                pass


class InstallationOptimizer:
    """Optimize installation processes."""

    def __init__(self) -> None:
        """Initialize installation optimizer."""
        self.cache = CacheManager()
        self.performance = PerformanceMonitor()
        self.logger = logging.getLogger(__name__)

    def should_reinstall(self, package: str, version: str) -> bool:
        """Check if package should be reinstalled based on cache.

        Args:
            package: Package name
            version: Package version

        Returns:
            True if should reinstall, False if cached version is still valid
        """
        cache_key = f"install:{package}:{version}"
        cached = self.cache.get(cache_key)

        if cached and cached.get("success"):
            self.logger.info("Using cached installation for %s@%s", package, version)
            return False

        return True

    def mark_installed(self, package: str, version: str, *, success: bool = True) -> None:
        """Mark package as installed in cache.

        Args:
            package: Package name
            version: Package version
            success: Whether installation was successful
        """
        cache_key = f"install:{package}:{version}"
        self.cache.set(
            cache_key,
            {
                "package": package,
                "version": version,
                "success": success,
                "timestamp": datetime.now(tz=UTC).isoformat(),
            },
        )

    def get_optimization_suggestions(self) -> list[str]:
        """Get suggestions for further optimization."""
        suggestions = []

        stats = self.cache.get_cache_stats()
        if stats["entries"] > 100:
            suggestions.append(
                f"Clear cache ({stats["entries"]} entries, {stats["size_mb"]}MB): "
                "devkit cache clear",
            )

        perf = self.performance.get_summary()
        for label, metrics in perf.items():
            if metrics["avg"] > 30:  # Operations taking over 30s
                suggestions.append(f"Slow operation detected ({label}): avg {metrics["avg"]}s")

        return suggestions


class ParallelInstaller:
    """Support parallel installation of packages."""

    def __init__(self, max_parallel: int = 4) -> None:
        """Initialize parallel installer.

        Args:
            max_parallel: Maximum number of parallel installations
        """
        self.max_parallel = max_parallel
        self.optimizer = InstallationOptimizer()
        self.logger = logging.getLogger(__name__)

    def get_install_order(self, packages: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """Get optimal installation order for packages.

        Handles dependency ordering and parallelization.

        Args:
            packages: List of package dicts with keys: name, version, depends_on (optional)

        Returns:
            List of installation waves (each wave can be parallel)
        """
        # Build dependency graph
        dependency_map: dict[Any, dict[str, Any]] = {}
        for pkg in packages:
            name = pkg.get("name")
            depends_on = pkg.get("depends_on", [])
            dependency_map[name] = {
                "package": pkg,
                "dependencies": set(depends_on),
                "installed": False,
            }

        # Perform topological sort
        waves: list[list[dict[str, Any]]] = []
        remaining = set(dependency_map.keys())

        while remaining:
            # Find packages with no remaining dependencies
            current_wave: list[dict[str, Any]] = []
            for name in remaining:
                entry: dict[str, Any] = dependency_map[name]
                if not entry["dependencies"]:
                    current_wave.append(entry["package"])

            if not current_wave:
                self.logger.warning("Circular dependencies detected in package list")
                break

            waves.append(current_wave)

            # Mark as installed and update dependencies
            for pkg in current_wave:
                name = pkg.get("name")
                dependency_map[name]["installed"] = True
                remaining.remove(name)

                # Remove from other packages' dependencies
                for entry in dependency_map.values():
                    entry_dict: dict[str, Any] = entry
                    dependencies = entry_dict["dependencies"]
                    if isinstance(dependencies, set):
                        dependencies.discard(name)

        return waves

    def estimate_duration(self, packages: list[dict[str, Any]]) -> float:
        """Estimate total installation duration.

        Args:
            packages: List of packages

        Returns:
            Estimated duration in seconds
        """
        # This is a simple estimate - can be enhanced with historical data
        base_time = 10  # Base time per package

        return base_time * len(packages) / min(self.max_parallel, len(packages))


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "CacheManager",
    "InstallationOptimizer",
    "ParallelInstaller",
    "PerformanceMonitor",
]
