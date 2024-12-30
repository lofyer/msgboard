import os
import secrets
import string
import bleach
import traceback
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_current_user
import bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, 
           static_folder='frontend/static',  # 设置静态文件目录
           static_url_path='/static')        # 设置静态文件URL路径
CORS(app, supports_credentials=True, resources={
    r"/api/*": {
        "origins": "*",
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
})

@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response

# 配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # 在生产环境中使用更安全的密钥
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# 初始化扩展
db = SQLAlchemy(app)
jwt = JWTManager(app)

# 允许的 HTML 标签和属性
ALLOWED_TAGS = [
    'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'p',
    'strong', 'ul', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'table', 'thead', 'tbody', 'tr', 'th', 'td', 'img', 'pre', 'code'
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'div': ['class', 'id', 'style'],
    'span': ['class', 'id', 'style'],
    'table': ['class', 'id', 'style'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
    '*': ['class', 'id']
}

ALLOWED_STYLES = ['text-align', 'margin', 'padding', 'width', 'height', 'border', 'color', 'background-color']

# 消息分类
MESSAGE_CATEGORIES = {
    'default': '默认分类',
    'bug': '产品故障',
    'feature': '产品需求',
    'other': '其他问题'
}

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    access_key = db.Column(db.String(100), unique=True)
    messages = db.relationship('Message', backref='author', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(20), nullable=False, default='default')  # 新增分类字段

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

def generate_secure_string(length=16):
    """生成安全的随机字符串"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def init_db():
    """初始化数据库"""
    with app.app_context():
        try:
            print("开始初始化数据库...")
            # 删除所有表并重新创建
            db.drop_all()
            db.create_all()
            print("数据库表创建完成")

            # 创建管理员账户
            print("创建管理员账户...")
            # 生成随机密码和 access key
            admin_password = generate_secure_string(16)
            admin_access_key = generate_secure_string(32)
            
            # 创建管理员用户
            admin = User(
                username='admin',
                password=bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),  # 转换为字符串
                access_key=admin_access_key
            )
            db.session.add(admin)
            
            # 保存凭据到文件
            with open('admin.key', 'w') as f:
                f.write(f"Admin Credentials (generated at {datetime.now().isoformat()})\n")
                f.write("-" * 50 + "\n")
                f.write(f"Username: admin\n")
                f.write(f"Password: {admin_password}\n")
                f.write(f"Access Key: {admin_access_key}\n")
            
            print("管理员账户创建完成，凭据已保存到 admin.key 文件")

            # 添加测试消息
            message = Message(
                content='<h1>欢迎使用留言板！</h1><p>这是一条测试消息。</p>',
                author=admin
            )
            db.session.add(message)
            
            db.session.commit()
            print("初始化数据完成")

        except Exception as e:
            print(f"初始化数据库时出错: {e}")
            print("Traceback:", traceback.format_exc())

def sanitize_html(content):
    """
    清理和过滤 HTML 内容，只允许安全的标签和属性
    """
    # 创建自定义清理器
    cleaner = bleach.Cleaner(
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True,
        protocols=['http', 'https', 'data']  # 允许 data URL
    )
    
    # 清理 HTML
    clean_html = cleaner.clean(content)
    return clean_html

# 前端路由
@app.route('/')
def index():
    with open('frontend/index.html', 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

# API路由
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # 使用 access key 登录
        if 'access_key' in data:
            user = User.query.filter_by(access_key=data['access_key']).first()
            if not user:
                return jsonify({'error': 'Access Key 无效'}), 401
        
        # 使用用户名密码登录
        elif 'username' in data and 'password' in data:
            user = User.query.filter_by(username=data['username']).first()
            if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
                return jsonify({'error': '用户名或密码错误'}), 401
        else:
            return jsonify({'error': '请提供用户名和密码或 Access Key'}), 400
        
        # 创建 JWT token，确保 identity 是字符串
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            'access_token': access_token,
            'username': user.username
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': f'登录失败: {str(e)}'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': '请提供用户名和密码'}), 400
            
        # 检查用户名是否已存在
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': '用户名已存在'}), 400
            
        # 生成 access key
        access_key = generate_secure_string(32)
            
        # 创建新用户
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # 转换为字符串
        user = User(
            username=data['username'],
            password=hashed_password,
            access_key=access_key
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': '注册成功',
            'access_key': access_key
        })
        
    except Exception as e:
        print(f"Register error: {e}")
        return jsonify({'error': f'注册失败: {str(e)}'}), 500

@app.route('/api/categories', methods=['GET'])
def get_categories():
    """获取所有可用的消息分类"""
    return jsonify(MESSAGE_CATEGORIES)

@app.route('/api/messages', methods=['GET'])
def get_messages():
    try:
        # 获取筛选参数
        category = request.args.get('category')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # 构建查询
        query = Message.query

        # 按分类筛选
        if category and category != 'all':
            query = query.filter(Message.category == category)

        # 按日期范围筛选
        if start_date:
            start_datetime = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(Message.created_at >= start_datetime)
        if end_date:
            end_datetime = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(Message.created_at <= end_datetime)

        # 按时间倒序排序
        messages = query.order_by(Message.created_at.desc()).all()

        return jsonify([{
            'id': msg.id,
            'content': msg.content,
            'author': msg.author.username,
            'created_at': msg.created_at.isoformat(),
            'category': msg.category,
            'category_name': MESSAGE_CATEGORIES.get(msg.category, '默认')
        } for msg in messages])
    except Exception as e:
        print(f"Error fetching messages: {e}")
        return jsonify({'error': f'获取消息失败: {str(e)}'}), 500

@app.route('/api/messages', methods=['POST'])
@jwt_required()
def create_message():
    try:
        # 获取当前用户
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': '未找到用户信息'}), 401

        # 获取请求数据
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'error': '请提供消息内容'}), 400

        # 获取分类，如果没有提供则使用默认分类
        category = data.get('category', 'default')
        if category not in MESSAGE_CATEGORIES:
            return jsonify({'error': '无效的分类'}), 400

        print("Received message content:", data['content'])
        print("Message category:", category)
            
        # 清理 HTML 内容
        clean_content = sanitize_html(data['content'])
        print("Sanitized content:", clean_content)
            
        # 创建新消息
        message = Message(
            content=clean_content,
            author=current_user,
            category=category
        )
        db.session.add(message)
        db.session.commit()
            
        return jsonify({
            'id': message.id,
            'content': message.content,
            'author': message.author.username,
            'created_at': message.created_at.isoformat(),
            'category': message.category,
            'category_name': MESSAGE_CATEGORIES.get(message.category, '默认')
        })
            
    except Exception as e:
        print(f"Error creating message: {e}")
        print("Traceback:", traceback.format_exc())
        return jsonify({'error': f'创建消息失败: {str(e)}'}), 500

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    try:
        # 获取当前用户
        current_user = get_current_user()
        if not current_user or current_user.username != 'admin':
            return jsonify({'error': '只有管理员可以删除消息'}), 403
            
        # 查找消息
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'error': '消息不存在'}), 404
            
        # 删除消息
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'message': '消息已删除'}), 200
        
    except Exception as e:
        print(f"Error deleting message: {e}")
        return jsonify({'error': f'删除消息失败: {str(e)}'}), 500

def get_current_user():
    """获取当前用户"""
    jwt_data = get_jwt_identity()
    if jwt_data is None:
        return None
    # 确保用户 ID 是整数
    user_id = int(jwt_data)
    return User.query.get(user_id)

if __name__ == '__main__':
    init_db()  # 初始化数据库
    app.run(debug=True, host='0.0.0.0', port=8000)
