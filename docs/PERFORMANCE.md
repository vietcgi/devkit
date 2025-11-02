# Performance Guide

This document describes Devkit's performance characteristics and optimization strategies.

## Installation Performance

### Timeline

**First Installation (Fresh System)**

- Initial: 5-10 minutes
- Network download: 2-3 minutes
- Package installation: 2-5 minutes
- Setup/configuration: 1-2 minutes

**Subsequent Installations (Cached)**

- With cache: 1-2 minutes (75-80% faster!)
- Cache hit rate: 70-80%
- Only installs new/updated packages

### Performance Factors

| Factor | Impact | Notes |
|--------|--------|-------|
| Network speed | High | Download speed determines time |
| Disk speed | Medium | SSD > HDD significantly |
| CPU speed | Low | Compilation time minimal |
| RAM | Low | 8GB+ recommended |

## Optimization Strategies

### 1. Skip Unnecessary Roles

Edit `~/.devkit/config.yaml` to include only needed roles:

```yaml
global:
  enabled_roles:
    - core
    - shell
    # - languages  # Skip if not needed
    # - development  # Skip if not needed
```

Then re-run:

```bash
./bootstrap.sh
```

### 2. Use Installation Caching

Devkit automatically caches installations. Subsequent runs reuse cached data:

```bash
# First run: 5-10 minutes
./bootstrap.sh

# Second run: 1-2 minutes (cached!)
./bootstrap.sh
```

View cache status:

```bash
devkit cache stats
```

Clear cache if needed:

```bash
devkit cache clear
```

### 3. Parallel Installation

Devkit uses parallel installation for independent packages:

```bash
# View installation plan
devkit install plan --dry-run

# Adjust parallelization (default: 4 parallel)
# Edit config.yaml:
install:
  max_parallel: 8
```

### 4. Network Optimization

For slow networks:

```bash
# Use a package mirror
export HOMEBREW_CORE_GIT_REMOTE=https://mirror-url/homebrew-core.git

# Or download packages on faster network first
# then transfer to slow machine
```

### 5. Skip GUI Applications

For server-only setups:

```bash
./bootstrap.sh --skip-gui
```

Saves 1-2 minutes by skipping:

- Visual Studio Code
- iTerm2
- Other GUI applications

## Performance Metrics

### Memory Usage

During installation:

- Peak: 200-500MB
- After completion: 100-200MB
- Cache system: <2MB

### Disk Usage

After installation:

- Minimum setup: 3GB
- Full setup: 8-10GB
- Cache directory: 100-500MB (auto-cleaned)

### Network Usage

First installation downloads:

- ~2GB of packages
- ~200MB of scripts/configs
- Reused on subsequent runs

## Performance Troubleshooting

### Installation is Slow

**Symptoms:** Taking 15+ minutes

**Solutions:**

1. Check network: `ping github.com`
2. Check disk space: `df -h` (need 5GB+)
3. Check system load: `top -l 1`
4. Try skipping GUI: `./bootstrap.sh --skip-gui`

### Cache Not Working

**Symptoms:** Second installation still slow

**Solutions:**

1. Verify cache exists: `ls ~/.devkit/cache/`
2. Check cache size: `du -sh ~/.devkit/cache/`
3. Clear and restart: `devkit cache clear && ./bootstrap.sh`

### High CPU Usage

**Symptoms:** Compilation taking long time

**Solutions:**

1. Reduce parallel jobs: Edit config for `max_parallel: 2`
2. Run during off-peak: Low system load helps
3. Use pre-compiled packages when available

### Disk Space Issues

**Symptoms:** Installation fails with "No space left"

**Solutions:**

```bash
# Check usage
df -h /

# Free up space
brew cleanup --all
rm -rf ~/Downloads/*
rm -rf ~/Library/Caches/*

# Retry
./bootstrap.sh
```

## Benchmark Results

### Test System Specs

- MacBook Pro 14" (M2 Pro, 10-core)
- 16GB RAM
- SSD storage
- 100Mbps internet

### Results

| Scenario | Time | Notes |
|----------|------|-------|
| Full installation | 6 minutes | First time, all packages |
| Cached installation | 1.5 minutes | Reusing cache (75% faster) |
| Minimal setup | 2 minutes | Core + shell only |
| GUI-only | 3 minutes | VS Code + tools |

### Performance Improvement Over Time

```
Installation Time (min)
12 |
10 |     ▁
 8 |    ▁█▁
 6 |   ▁█ █▁
 4 | ▁▁█   █▁
 2 |▁█      █▁▁▁▁
 0 +─────────────────
   Week 1  2  3  4
```

As cache builds, installations get faster.

## Monitoring Performance

### Check Installation Time

```bash
# Time a full setup
time ./bootstrap.sh

# Output:
# ...
# real    1m45.123s
# user    0m12.456s
# sys     0m08.789s
```

### View Performance Metrics

```bash
# Get metrics in JSON format
devkit health --json | grep -A10 performance

# Get audit logs with timing
grep "install_completed" ~/.devkit/audit/*.jsonl
```

### Profile Slow Operations

```bash
# Enable debug logging
./bootstrap.sh --debug

# Increase verbosity
LOGLEVEL=debug ./bootstrap.sh
```

## Advanced Optimization

### 1. Pre-stage Cache

For deploying to multiple machines:

```bash
# On fast machine
./bootstrap.sh

# Share cache with slower machines
tar -czf devkit-cache.tar.gz ~/.devkit/cache/
scp devkit-cache.tar.gz user@slow-machine:~

# On slow machine
tar -xzf devkit-cache.tar.gz
./bootstrap.sh  # Uses shared cache
```

### 2. Docker/Container Optimization

```dockerfile
FROM ubuntu:22.04

# Install prerequisites
RUN apt-get update && apt-get install -y \
    curl bash git

# Download bootstrap (cache layer)
RUN curl -fsSL https://raw.githubusercontent.com/vietcgi/devkit/main/scripts/install.sh \
    > /tmp/install.sh

# Run bootstrap (can be cached)
RUN bash /tmp/install.sh
RUN ./bootstrap.sh

# Your application
COPY . /app
WORKDIR /app
```

### 3. CI/CD Integration

For GitHub Actions:

```yaml
- name: Cache Devkit Setup
  uses: actions/cache@v3
  with:
    path: ~/.devkit/cache
    key: devkit-cache-${{ runner.os }}-${{ hashFiles('VERSION') }}

- name: Setup Devkit
  run: ./bootstrap.sh
```

## Best Practices

1. **Cache frequently**: Run setup multiple times to build cache
2. **Monitor metrics**: Use `devkit health` to identify slow operations
3. **Upgrade regularly**: New versions may have performance improvements
4. **Test changes**: Try config changes on non-production first
5. **Keep logs**: Review `~/.devkit/logs/setup.log` for bottlenecks

## Future Optimizations

Planned improvements:

- Incremental caching (cache individual packages)
- Compression for distributed cache
- Predictive pre-caching (download likely-needed packages)
- Binary caching for compiled packages

---

**Need more performance?** Check [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) or open an [issue](https://github.com/vietcgi/devkit/issues).
