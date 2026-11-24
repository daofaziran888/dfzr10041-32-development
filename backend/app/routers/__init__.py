"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。"""
from __future__ import annotations

from app.routers import login, resource

# 登录来源约定的固定路径必须先注册，再挂通用 /api/{module} 动态路由。
ROUTERS = [login, resource]
