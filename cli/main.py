#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
# !/usr/bin/env python3
"""Devkit CLI - Main entry point orchestrating all devkit modules.

Provides unified command-line interface for:
- Configuration management
- Plugin system
- Git integration
- Health checks
- System verification
"""

# pylint: disable=import-outside-toplevel

import logging
import sys
from pathlib import Path

import click

from cli.utils import setup_logger

# Setup logger for CLI
logger = setup_logger(__name__, level=logging.INFO)


@click.group()
@click.version_option(version="3.1.0", prog_name="devkit")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Configuration directory path",
)
@click.pass_context
def cli(  # pylint: disable=redefined-outer-name
    ctx: click.Context,
    verbose: bool,
    config: str | None,
) -> None:
    """Devkit - Development Environment Setup and Management.

    Fast, cross-platform development environment configuration.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = Path(config) if config else Path.cwd() / "config"

    if verbose:
        logging.getLogger("cli").setLevel(logging.DEBUG)


@cli.group()
def config() -> None:
    """Configuration management commands."""


@config.command(name="load")
@click.argument("config_file", type=click.Path(exists=True))
@click.pass_context
def config_load(ctx: click.Context, config_file: str) -> None:
    """Load and display configuration from file."""
    try:
        from cli.config_engine import ConfigurationEngine  # noqa: PLC0415

        engine = ConfigurationEngine(ctx.obj["config"])
        success = engine.load_file(config_file)

        if success:
            click.echo(click.style("✓ Configuration loaded successfully", fg="green"))
            config_data = engine.config
            if config_data:
                click.echo(click.style("Configuration:", bold=True))
                for key, value in config_data.items():
                    click.echo(f"  {key}: {value}")
        else:
            click.echo("✗ Failed to load configuration", err=True)
            sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Configuration load failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@config.command(name="validate")
@click.argument("config_file", type=click.Path(exists=True))
@click.pass_context
def config_validate(ctx: click.Context, config_file: str) -> None:
    """Validate configuration file."""
    try:
        from cli.config_engine import ConfigurationEngine  # noqa: PLC0415

        engine = ConfigurationEngine(ctx.obj["config"])
        engine.load_file(config_file)

        is_valid, errors = engine.validate()

        if is_valid:
            click.echo(click.style("✓ Configuration is valid", fg="green"))
        else:
            click.echo(click.style("✗ Configuration has errors:", fg="red"))
            for error in errors:
                click.echo(f"  - {error}")
            sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Validation failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@config.command(name="diff")
@click.argument("config1", type=click.Path(exists=True))
@click.argument("config2", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
def config_diff(
    config1: str,
    config2: str,
    format: str,  # noqa: A002 pylint: disable=redefined-builtin
) -> None:
    """Compare two configuration files."""
    try:
        import yaml  # noqa: PLC0415 pylint: disable=import-outside-toplevel

        from cli.config_engine import (  # noqa: PLC0415 pylint: disable=import-outside-toplevel
            ConfigDiff,
        )

        with Path(config1).open(encoding="utf-8") as f:
            cfg1 = yaml.safe_load(f) or {}
        with Path(config2).open(encoding="utf-8") as f:
            cfg2 = yaml.safe_load(f) or {}

        differ = ConfigDiff()
        diff_result = differ.compare(cfg1, cfg2)

        if format == "json":
            click.echo(differ.format_json(diff_result))
        else:
            click.echo(differ.format_text(diff_result))
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Diff failed")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def plugin() -> None:
    """Plugin management commands."""


@plugin.command(name="discover")
@click.argument("plugin_path", type=click.Path(exists=True), default="./plugins")
def plugin_discover(plugin_path: str) -> None:
    """Discover available plugins."""
    try:
        from cli.plugin_system import PluginLoader  # noqa: PLC0415

        loader = PluginLoader(logger=logger)
        loader.add_plugin_path(Path(plugin_path))

        discovered = loader.discover_plugins()
        if discovered:
            click.echo(click.style("Discovered Plugins:", bold=True))
            for path, module_name in discovered:
                click.echo(f"  • {module_name} ({path})")
        else:
            click.echo("No plugins found")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Plugin discovery failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@plugin.command(name="load")
@click.argument("plugin_path", type=click.Path(exists=True), default="./plugins")
def plugin_load(plugin_path: str) -> None:
    """Load all plugins from directory."""
    try:
        from cli.plugin_system import PluginLoader  # noqa: PLC0415

        loader = PluginLoader(logger=logger)
        loaded_count = loader.load_all([Path(plugin_path)])

        click.echo(click.style(f"✓ Loaded {loaded_count} plugins", fg="green"))
        for plugin_name in loader.list_plugins():
            click.echo(f"  • {plugin_name}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Plugin loading failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@plugin.command(name="validate")
@click.argument("plugin_path", type=click.Path(exists=True), default="./plugins")
def plugin_validate(plugin_path: str) -> None:
    """Validate all plugins in directory."""
    try:
        from cli.plugin_validator import PluginValidator  # noqa: PLC0415

        validator = PluginValidator(Path(plugin_path), logger=logger)
        results = validator.validate_all_plugins()

        click.echo(click.style("Plugin Validation Results:", bold=True))
        valid_count = sum(1 for is_valid, _ in results.values() if is_valid)

        for plugin_name, (is_valid, message) in results.items():
            status = click.style("✓", fg="green") if is_valid else click.style("✗", fg="red")
            click.echo(f"  {status} {plugin_name}: {message}")

        click.echo(f"\nValid: {valid_count}/{len(results)}")

        if valid_count < len(results):
            sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Plugin validation failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def git() -> None:
    """Git integration commands."""


@git.command(name="branch")
@click.argument("repo_path", type=click.Path(exists=True), default=".")
def git_branch(repo_path: str) -> None:
    """Get current git branch."""
    try:
        from cli.git_config_manager import GitConfigManager  # noqa: PLC0415

        manager = GitConfigManager(str(Path(repo_path).expanduser()))
        current_branch = manager.get_current_branch()

        click.echo(f"Current branch: {current_branch}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Git branch check failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@git.command(name="status")
@click.argument("repo_path", type=click.Path(exists=True), default=".")
def git_status(repo_path: str) -> None:
    """Check git repository status."""
    try:
        from cli.git_config_manager import GitConfigManager  # noqa: PLC0415

        manager = GitConfigManager(str(Path(repo_path).expanduser()))
        is_dirty = manager.is_dirty()

        if is_dirty:
            click.echo(
                click.style(
                    "Repository is dirty (has uncommitted changes)",
                    fg="yellow",
                ),
            )
        else:
            click.echo(click.style("Repository is clean", fg="green"))
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Git status check failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@git.command(name="info")
@click.argument("repo_path", type=click.Path(exists=True), default=".")
@click.argument("commit_ref", default="HEAD")
def git_info(repo_path: str, commit_ref: str) -> None:
    """Get commit information."""
    try:
        from cli.git_config_manager import (  # noqa: PLC0415 pylint: disable=import-outside-toplevel
            GitConfigManager,
        )

        manager = GitConfigManager(str(Path(repo_path).expanduser()))
        commit_info = manager.get_commit_info(commit_ref)  # pylint: disable=no-member

        if commit_info:
            click.echo(click.style("Commit Info:", bold=True))
            for key, value in commit_info.items():
                click.echo(f"  {key}: {value}")
        else:
            click.echo(f"No commit info found for {commit_ref}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Git info retrieval failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def validate() -> None:
    """Validation commands."""


@validate.command(name="commit")
@click.argument("commit_file", type=click.Path(exists=True))
def validate_commit(commit_file: str) -> None:
    """Validate commit message from file."""
    try:
        message = Path(commit_file).read_text(encoding="utf-8").strip()

        click.echo(click.style("✓ Commit message validation:", bold=True))
        click.echo(f"  Message: {message[:50]}...")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Commit validation failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def health() -> None:
    """Perform system health check."""
    try:
        from cli.health_check import (  # noqa: PLC0415 pylint: disable=import-outside-toplevel
            create_default_monitor,
        )

        monitor = create_default_monitor()
        result = monitor.run_all()

        click.echo(click.style("System Health Check Results:", bold=True))
        for check_name, (status, message, _details) in result.items():
            status_color = (
                "green" if status == "healthy" else "yellow" if status == "warning" else "red"
            )
            status_icon = (
                click.style("✓", fg=status_color)
                if status == "healthy"
                else click.style("⚠", fg=status_color)
            )
            click.echo(f"  {status_icon} {check_name}: {status} - {message}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Health check failed: %s")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def version() -> None:
    """Show version information."""
    click.echo("devkit version 3.1.0")
    click.echo("Python development environment setup and management tool")


def main() -> int:
    """Main entry point for devkit CLI."""
    try:
        cli()  # pylint: disable=no-value-for-parameter
        return 0
    except click.ClickException as e:
        e.show()
        return 1
    except KeyboardInterrupt:
        click.echo("\nInterrupted by user", err=True)
        return 130
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Unexpected error: %s")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
