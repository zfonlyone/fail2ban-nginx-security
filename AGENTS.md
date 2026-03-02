# AGENTS

## 目标
- `security` 项目部署必须可在源码目录直接执行，并稳定同步到 `/etc/security-guard`。
- 以最小改动保障可维护性和可回滚性。

## 部署规范
- 部署入口为 `scripts/deploy.sh`。
- 部署脚本必须自动将源码同步到 `/etc/security-guard`（至少包含 `docker-compose.yml`、`tg-bot/`、`scripts/`）。
- 复制目录时必须使用递归同步方式，不允许对目录使用单文件 `cp -f`。
- 同步时应过滤运行时缓存：`__pycache__/`、`*.pyc`、`*.pyo`。

## Shell 规范
- 必须启用严格模式：`set -euo pipefail`。
- 新增函数需职责单一，命名清晰（如 `sync_tree`）。
- 外部命令失败时必须有可读日志，避免静默失败。

## Docker 与运行规范
- `docker-compose.yml` 服务需配置 `restart` 策略。
- 对关键服务添加 `healthcheck`，健康检查失败可被巡检脚本重启。
- 与 systemd 配套：开机自启服务 + 定时健康巡检（timer）。

## 变更与验证
- 每次修改部署逻辑后至少执行：
  - `bash -n scripts/deploy.sh`
  - `docker compose --env-file .env config`
- 修改后更新 `README.md` 或补充运维说明（如有行为变化）。
