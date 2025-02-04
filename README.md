# flask-jwt-demo
个人练习演示flask不同接口不同权限
Flask JWT 认证示例
功能特性


JWT Token认证

基于角色的权限控制（admin/user）

SQLite文件数据库存储

安全防护措施

单文件实现（app.py）

技术栈选择
Flask: 轻量级Web框架，适合快速开发API

JWT: 无状态Token认证，天然支持分布式系统

SQLite: 文件数据库，无需额外服务，适合单机部署

passlib: 安全的密码哈希算法（bcrypt）

Pydantic: 数据验证，防止无效请求

安全设计
密码使用bcrypt哈希存储


强制HTTPS（生产环境）



轻量级依赖（总依赖包<10个）


安装依赖

# 安装依赖
pip install flask pyjwt passlib pydantic

# 启动服务
python3 main.py

