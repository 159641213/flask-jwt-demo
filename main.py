"""
app.py - Flask JWT 认证示例（支持注册、权限控制）
"""
import sqlite3
import jwt
import datetime
from functools import wraps
from passlib.hash import bcrypt
from flask import Flask, jsonify, request, g

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 生产环境应使用环境变量
app.config['DATABASE'] = 'users.db'
app.config['JWT_EXPIRE_MINUTES'] = 15

# 预置用户
PRESEED_USERS = [
    {'username': 'admin', 'password': 'admin123', 'role': 'admin'},
    {'username': 'user1', 'password': 'user123', 'role': 'user'}
]

# 数据库连接管理
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        ''')
        db.commit()

def create_preseeds():
    with app.app_context():
        db = get_db()
        for user in PRESEED_USERS:
            existing_user = db.execute(
                'SELECT 1 FROM users WHERE username = ?',
                (user['username'],)
            ).fetchone()

            if not existing_user:
                password_hash = bcrypt.hash(user['password'])
                db.execute(
                    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (user['username'], password_hash, user['role'])
                )
        db.commit()

# JWT工具函数
def generate_token(username, role):
    payload = {
        'sub': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(
            minutes=app.config['JWT_EXPIRE_MINUTES']
        )
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# 装饰器
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message': 'Token缺失'}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({'message': '无效Token'}), 401

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?',
            (payload['sub'],)
        ).fetchone()

        if not user:
            return jsonify({'message': '用户不存在'}), 401

        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.current_user['role'] != 'admin':
            return jsonify({'message': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated

# 路由
@app.route('/register', methods=['POST'])
@token_required
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # 默认角色为普通用户

    if not username or not password:
        return jsonify({'message': '需要用户名和密码'}), 400

    # 只有管理员可以创建管理员用户
    if role == 'admin' and request.current_user['role'] != 'admin':
        return jsonify({'message': '无权创建管理员用户'}), 403

    db = get_db()
    existing_user = db.execute(
        'SELECT 1 FROM users WHERE username = ?',
        (username,)
    ).fetchone()

    if existing_user:
        return jsonify({'message': '用户名已存在'}), 400

    password_hash = bcrypt.hash(password)
    db.execute(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        (username, password_hash, role)
    )
    db.commit()

    return jsonify({'message': '用户注册成功'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()

    if not user or not bcrypt.verify(password, user['password_hash']):
        return jsonify({'message': '无效凭证'}), 401

    token = generate_token(user['username'], user['role'])
    return jsonify({'token': token})

@app.route('/protected')
@token_required
def protected_route():
    return jsonify({
        'message': f'你好 {request.current_user["username"]}',
        'role': request.current_user["role"]
    })

@app.route('/admin/dashboard')
@token_required
@admin_required
def admin_dashboard():
    return jsonify({'message': '欢迎来到管理员面板'})


if __name__ == '__main__':
    init_db()
    create_preseeds()
    # app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
    app.run( host='0.0.0.0', port=5000)