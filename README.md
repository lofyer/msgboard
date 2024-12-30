# 留言板应用

这是一个使用 Flask 和 Vue.js 构建的现代化留言板应用。

## 功能特点

- 用户注册和登录
- 支持密码或 Access Key 登录
- RESTful API 接口
- 实时留言显示
- 现代化的用户界面

## 技术栈

- 后端：Flask + SQLite
- 前端：Vue 3 + TailwindCSS
- 认证：JWT

## 安装和运行

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 运行服务器：
```bash
python app.py
```

服务器将在 http://localhost:8000 上运行。

3. 获取管理员凭据：
   - 首次运行时，程序会自动生成管理员账户
   - 管理员凭据（用户名、密码和 access key）将保存在当前目录的 `admin.key` 文件中
   - 请妥善保管该文件，并在记录凭据后删除它

## API 接口

### 用户认证

- POST /api/register - 用户注册
- POST /api/login - 用户登录（支持用户名密码或 Access Key）

### 留言管理

- GET /api/messages - 获取所有留言
- POST /api/messages - 发布新留言（需要认证）

## API 文档

### 认证

#### 登录
```bash
# 使用用户名和密码登录
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# 使用 access key 登录
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"access_key": "your_access_key"}'

# 响应示例
{
  "access_token": "eyJ0eXAi...",
  "username": "admin"
}
```

#### 注册
```bash
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "password123"}'

# 响应示例
{
  "message": "注册成功",
  "access_key": "generated_access_key"
}
```

### 消息管理

#### 获取所有消息
```bash
curl http://localhost:8000/api/messages

# 响应示例
[
  {
    "id": 1,
    "content": "<p>消息内容</p>",
    "author": "admin",
    "created_at": "2024-12-30T13:00:00"
  }
]
```

#### 发送新消息
```bash
curl -X POST http://localhost:8000/api/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_access_token" \
  -d '{"content": "<p>这是一条新消息</p>"}'

# 响应示例
{
  "id": 2,
  "content": "<p>这是一条新消息</p>",
  "author": "admin",
  "created_at": "2024-12-30T13:20:00"
}
```

#### 删除消息（仅管理员）
```bash
curl -X DELETE http://localhost:8000/api/messages/1 \
  -H "Authorization: Bearer your_access_token"

# 响应示例
{
  "message": "消息已删除"
}
```

## 错误响应

所有错误响应都遵循以下格式：
```json
{
  "error": "错误描述"
}
```

常见错误代码：
- 400: 请求参数错误
- 401: 未认证或认证失败
- 403: 权限不足
- 404: 资源不存在
- 500: 服务器内部错误

## 安全说明

- 所有密码都经过 bcrypt 加密存储
- 使用 JWT 进行 API 认证
- Access Key 随机生成，确保安全性

## 环境变量

创建 `.env` 文件并设置以下变量：

```
FLASK_APP=app.py
FLASK_ENV=development
JWT_SECRET_KEY=your-secret-key-please-change-in-production
DATABASE_URL=sqlite:///messages.db
```

请确保在生产环境中更改 JWT_SECRET_KEY。
