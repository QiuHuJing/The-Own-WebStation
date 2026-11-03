#!/bin/bash
# ============================================================
# 月之海 · 星娅小站  启动 / 重启脚本
# ------------------------------------------------------------
# 用法：
#   bash start.sh            # 前台启动（交给宝塔「守护进程」保活）
#   bash start.sh start      # 同上
#   bash start.sh restart    # 代码更新后：停掉旧进程再启动
#   bash start.sh stop       # 仅停止
#
# 防 OOM：用 --max-old-space-size 限制 V8 堆内存。超限时 Node 主动
#         退出（而非被系统 OOM Killer 强杀），由守护进程重新拉起，
#         避免无限制吃内存拖垮同机的 NoneBot / NapCat。
# ============================================================

APP_DIR="/www/wwwroot/project/Web"
PORT=3000
MEM_LIMIT_MB=256   # 堆内存上限（MB）
LOG_FILE="$APP_DIR/server.log"

cd "$APP_DIR" || { echo "错误：目录不存在 $APP_DIR"; exit 1; }
export NODE_ENV="${NODE_ENV:-production}"

stop() {
  echo "[start.sh] 停止 webown ..."
  # 优先按端口精准杀占用者，避免误伤其它 node 进程
  command -v fuser >/dev/null 2>&1 && fuser -k "${PORT}/tcp" 2>/dev/null
  pkill -f "server.js" 2>/dev/null
  sleep 1
}

start() {
  echo "[start.sh] 启动 webown（堆上限 ${MEM_LIMIT_MB}MB）..."
  # exec 使本脚本进程替换为 node，守护进程可直接管理 node 的生死
  # 日志追加写入 server.log，便于 tail 查看
  exec node --max-old-space-size="$MEM_LIMIT_MB" server.js >> "$LOG_FILE" 2>&1
}

case "$1" in
  restart) stop; start ;;
  stop)    stop ;;
  start|"") start ;;
  *) echo "用法: bash start.sh [start|stop|restart]"; exit 1 ;;
esac
