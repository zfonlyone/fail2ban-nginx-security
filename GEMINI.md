# Security Guard 项目架构与部署规范

## 1. 核心架构
本项目遵循与 `ai-proxy` 一致的 `源码构建、环境隔离、纯净运行` 模式。

- 源码目录：`/root/code/fail2ban-nginx-security`
  - 负责修改 `tg-bot/`、`scripts/`、`docker-compose.yml`。
  - `Security Bot` 镜像必须在源码目录构建，禁止在 `/etc/security-guard` 内保留应用源码后再构建。
- 运行目录：`/etc/security-guard`
  - 只保留运行所需的 `docker-compose.yml`、`.env`、`ban/`、`state/`、`scripts/`。
  - 禁止在该目录新增或修改 `tg-bot` Python 源码。

## 2. 配置规范
- 唯一运行时环境变量文件：`/etc/security-guard/.env`
- 封禁与状态目录：
  - `/etc/security-guard/ban`
  - `/etc/security-guard/state`
- 运维脚本目录：`/etc/security-guard/scripts`

真实 Token 和 Chat ID 只能放在 `/etc/security-guard/.env`，不得回写仓库。

## 3. 部署流程
代码变更后，必须在源码目录执行：

```bash
cd /root/code/fail2ban-nginx-security
sudo ./scripts/deploy.sh
```

部署脚本负责：
1. 初始化 `/etc/security-guard` 运行目录
2. 在源码目录构建 `security-guard-bot:latest`
3. 同步运行期 `docker-compose.yml` 与运维脚本到 `/etc/security-guard`
4. 清理运行目录残留的 `tg-bot` 源码
5. 在 `/etc/security-guard` 启动或更新容器

## 4. AI 助手操作约束
- 改逻辑：只在 `/root/code/fail2ban-nginx-security`
- 改运行配置：只在 `/etc/security-guard/.env`
- 发布变更：执行 `sudo ./scripts/deploy.sh`
- 严禁在 `/etc/security-guard` 直接修改 Python 源码
