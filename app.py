import sqlite3
import uuid
import re
import bleach
import bcrypt
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, Markup
from flask_socketio import SocketIO, send
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# 세션 쿠키 보안 설정
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1시간
app.config['SESSION_COOKIE_NAME'] = 'secure_session'
# 세션 만료 시간 설정
app.config['SESSION_EXPIRY'] = 3600  # 1시간
app.config['REAUTH_EXPIRY'] = 300    # 5분
# 로그인 실패 설정
app.config['MAX_LOGIN_ATTEMPTS'] = 5
app.config['LOGIN_TIMEOUT'] = 300    # 5분

# 로깅 설정
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)

# 입력 검증을 위한 상수
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 20
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 100
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]+$')
PASSWORD_PATTERN = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]+$')

# 상품 입력 검증을 위한 상수
PRODUCT_TITLE_MIN_LENGTH = 2
PRODUCT_TITLE_MAX_LENGTH = 100
PRODUCT_DESCRIPTION_MIN_LENGTH = 10
PRODUCT_DESCRIPTION_MAX_LENGTH = 1000
PRODUCT_PRICE_MIN = 0
PRODUCT_PRICE_MAX = 1000000000  # 10억

def validate_username(username):
    if not username:
        return False, "사용자명은 필수입니다."
    if len(username) < USERNAME_MIN_LENGTH or len(username) > USERNAME_MAX_LENGTH:
        return False, f"사용자명은 {USERNAME_MIN_LENGTH}~{USERNAME_MAX_LENGTH}자 사이여야 합니다."
    if not USERNAME_PATTERN.match(username):
        return False, "사용자명은 영문자, 숫자, 언더스코어만 사용할 수 있습니다."
    return True, ""

def validate_password(password):
    if not password:
        return False, "비밀번호는 필수입니다."
    if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
        return False, f"비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자 사이여야 합니다."
    if not PASSWORD_PATTERN.match(password):
        return False, "비밀번호는 영문자, 숫자, 특수문자를 모두 포함해야 합니다."
    return True, ""

def sanitize_input(text):
    if not text:
        return ""
    # HTML 태그 허용 목록 설정
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
    allowed_attributes = {}  # 모든 속성 제거
    # HTML 태그 제거 및 특수문자 이스케이프
    cleaned_text = bleach.clean(
        text,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )
    # 링크를 찾아서 클릭 가능한 텍스트로 변환
    cleaned_text = bleach.linkify(cleaned_text)
    return cleaned_text

def format_product_description(description):
    """상품 설명을 안전하게 포맷팅"""
    # 줄바꿈을 <br> 태그로 변환하고 이스케이프 처리
    escaped_description = description.replace('\n', '<br>')
    return Markup(escaped_description)

def hash_password(password):
    # 비밀번호를 바이트로 변환
    password_bytes = password.encode('utf-8')
    # salt 생성 (bcrypt가 자동으로 생성)
    salt = bcrypt.gensalt()
    # 비밀번호 해싱
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def check_password(password, hashed):
    # 비밀번호를 바이트로 변환
    password_bytes = password.encode('utf-8')
    # 해시된 비밀번호를 바이트로 변환
    hashed_bytes = hashed.encode('utf-8')
    # 비밀번호 검증
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def validate_product_title(title):
    if not title:
        return False, "상품 제목은 필수입니다."
    if len(title) < PRODUCT_TITLE_MIN_LENGTH or len(title) > PRODUCT_TITLE_MAX_LENGTH:
        return False, f"상품 제목은 {PRODUCT_TITLE_MIN_LENGTH}~{PRODUCT_TITLE_MAX_LENGTH}자 사이여야 합니다."
    return True, ""

def validate_product_description(description):
    if not description:
        return False, "상품 설명은 필수입니다."
    if len(description) < PRODUCT_DESCRIPTION_MIN_LENGTH or len(description) > PRODUCT_DESCRIPTION_MAX_LENGTH:
        return False, f"상품 설명은 {PRODUCT_DESCRIPTION_MIN_LENGTH}~{PRODUCT_DESCRIPTION_MAX_LENGTH}자 사이여야 합니다."
    return True, ""

def validate_product_price(price):
    if not price:
        return False, "상품 가격은 필수입니다."
    try:
        price_num = float(price)
        if price_num < PRODUCT_PRICE_MIN or price_num > PRODUCT_PRICE_MAX:
            return False, f"상품 가격은 {PRODUCT_PRICE_MIN}~{PRODUCT_PRICE_MAX}원 사이여야 합니다."
        if not re.match(r'^\d+(\.\d{1,2})?$', price):
            return False, "상품 가격은 소수점 둘째 자리까지만 입력 가능합니다."
    except ValueError:
        return False, "상품 가격은 숫자만 입력 가능합니다."
    return True, ""

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 로그인 시도 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempt (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                attempt_time TIMESTAMP NOT NULL,
                ip_address TEXT NOT NULL,
                success BOOLEAN NOT NULL
            )
        """)
        db.commit()

def check_login_attempts(username, ip_address):
    db = get_db()
    cursor = db.cursor()
    # 최근 5분 동안의 실패한 로그인 시도 횟수 확인
    cursor.execute("""
        SELECT COUNT(*) FROM login_attempt 
        WHERE username = ? AND ip_address = ? AND success = 0 
        AND attempt_time > datetime('now', '-5 minutes')
    """, (username, ip_address))
    failed_attempts = cursor.fetchone()[0]
    return failed_attempts >= app.config['MAX_LOGIN_ATTEMPTS']

def record_login_attempt(username, ip_address, success):
    db = get_db()
    cursor = db.cursor()
    attempt_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO login_attempt (id, username, attempt_time, ip_address, success)
        VALUES (?, ?, datetime('now'), ?, ?)
    """, (attempt_id, username, ip_address, success))
    db.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # 세션 만료 체크
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(seconds=app.config['SESSION_EXPIRY']):
                session.clear()
                flash('세션이 만료되었습니다. 다시 로그인해주세요.')
                return redirect(url_for('login'))
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def reauth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # 재인증 필요 체크
        if 'reauth_time' not in session or \
           datetime.now() - datetime.fromisoformat(session['reauth_time']) > timedelta(seconds=app.config['REAUTH_EXPIRY']):
            return redirect(url_for('reauth'))
        return f(*args, **kwargs)
    return decorated_function

# 오류 처리 핸들러
@app.errorhandler(Exception)
def handle_error(error):
    # HTTP 예외 처리
    if isinstance(error, HTTPException):
        response = {
            "error": error.name,
            "message": error.description
        }
        return jsonify(response), error.code
    
    # 내부 서버 오류 처리
    logger.error(f"Internal Server Error: {str(error)}", exc_info=True)
    return jsonify({
        "error": "Internal Server Error",
        "message": "서버에서 오류가 발생했습니다. 잠시 후 다시 시도해주세요."
    }), 500

# 데이터베이스 오류 처리
def handle_db_error(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.Error as e:
            logger.error(f"Database Error: {str(e)}", exc_info=True)
            flash('데이터베이스 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('index'))
    return wrapper

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
@handle_db_error
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form['username'])
            password = request.form['password']
            
            # 사용자명 검증
            is_valid, error_message = validate_username(username)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('register'))
                
            # 비밀번호 검증
            is_valid, error_message = validate_password(password)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('register'))
                
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                flash('이미 존재하는 사용자명입니다.')
                return redirect(url_for('register'))
            user_id = str(uuid.uuid4())
            # 비밀번호 해싱
            hashed_password = hash_password(password)
            cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                           (user_id, username, hashed_password))
            db.commit()
            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Registration Error: {str(e)}", exc_info=True)
            flash('회원가입 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('register'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        ip_address = request.remote_addr
        
        # 사용자명 검증
        is_valid, error_message = validate_username(username)
        if not is_valid:
            flash(error_message)
            return redirect(url_for('login'))
            
        # 로그인 시도 횟수 확인
        if check_login_attempts(username, ip_address):
            flash('너무 많은 로그인 시도가 있었습니다. 5분 후에 다시 시도해주세요.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and check_password(password, user['password']):
            session['user_id'] = user['id']
            session['last_activity'] = datetime.now().isoformat()
            record_login_attempt(username, ip_address, True)
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(username, ip_address, False)
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
@handle_db_error
def dashboard():
    try:
        search_query = request.args.get('q', '').strip()
        db = get_db()
        cursor = db.cursor()
        
        # 현재 사용자 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
        
        # 상품 검색
        if search_query:
            cursor.execute("""
                SELECT * FROM product 
                WHERE title LIKE ? OR description LIKE ?
                ORDER BY id DESC
            """, (f'%{search_query}%', f'%{search_query}%'))
        else:
            cursor.execute("SELECT * FROM product ORDER BY id DESC")
            
        all_products = cursor.fetchall()
        return render_template('dashboard.html', 
                             products=all_products, 
                             user=current_user,
                             search_query=search_query)
    except Exception as e:
        logger.error(f"Dashboard Error: {str(e)}", exc_info=True)
        flash('상품 목록을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
        return redirect(url_for('index'))

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@reauth_required
@handle_db_error
def profile():
    try:
        db = get_db()
        cursor = db.cursor()
        if request.method == 'POST':
            bio = sanitize_input(request.form.get('bio', ''))
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
            db.commit()
            flash('프로필이 업데이트되었습니다.')
            return redirect(url_for('profile'))
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
        return render_template('profile.html', user=current_user)
    except Exception as e:
        logger.error(f"Profile Update Error: {str(e)}", exc_info=True)
        flash('프로필 업데이트 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
        return redirect(url_for('profile'))

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
@handle_db_error
def new_product():
    if request.method == 'POST':
        try:
            title = sanitize_input(request.form['title'])
            description = sanitize_input(request.form['description'])
            price = request.form['price']
            
            # 제목 검증
            is_valid, error_message = validate_product_title(title)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('new_product'))
                
            # 설명 검증
            is_valid, error_message = validate_product_description(description)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('new_product'))
                
            # 가격 검증
            is_valid, error_message = validate_product_price(price)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('new_product'))
                
            db = get_db()
            cursor = db.cursor()
            product_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
                (product_id, title, description, price, session['user_id'])
            )
            db.commit()
            flash('상품이 등록되었습니다.')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logger.error(f"Product Registration Error: {str(e)}", exc_info=True)
            flash('상품 등록 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('new_product'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
@handle_db_error
def view_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        if not product:
            flash('상품을 찾을 수 없습니다.')
            return redirect(url_for('dashboard'))
        # 판매자 정보 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
        seller = cursor.fetchone()
        
        # 상품 설명 포맷팅
        product = dict(product)  # SQLite Row 객체를 dict로 변환
        product['description'] = format_product_description(product['description'])
        
        return render_template('view_product.html', product=product, seller=seller)
    except Exception as e:
        logger.error(f"Product View Error: {str(e)}", exc_info=True)
        flash('상품 정보를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
        return redirect(url_for('dashboard'))

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 재인증
@app.route('/reauth', methods=['GET', 'POST'])
@login_required
def reauth():
    if request.method == 'POST':
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if user and check_password(password, user['password']):
            session['reauth_time'] = datetime.now().isoformat()
            flash('재인증이 완료되었습니다.')
            return redirect(url_for('dashboard'))
        else:
            flash('비밀번호가 올바르지 않습니다.')
            return redirect(url_for('reauth'))
    return render_template('reauth.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    # 채팅 메시지 sanitize
    if 'message' in data:
        data['message'] = sanitize_input(data['message'])
    if 'username' in data:
        data['username'] = sanitize_input(data['username'])
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

def is_product_owner(product_id):
    """상품 소유자 확인"""
    if 'user_id' not in session:
        return False
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    return product and product['seller_id'] == session['user_id']

@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
@handle_db_error
def edit_product(product_id):
    try:
        if not is_product_owner(product_id):
            flash('상품을 수정할 권한이 없습니다.')
            return redirect(url_for('dashboard'))
            
        db = get_db()
        cursor = db.cursor()
        
        if request.method == 'POST':
            title = sanitize_input(request.form['title'])
            description = sanitize_input(request.form['description'])
            price = request.form['price']
            
            # 제목 검증
            is_valid, error_message = validate_product_title(title)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('edit_product', product_id=product_id))
                
            # 설명 검증
            is_valid, error_message = validate_product_description(description)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('edit_product', product_id=product_id))
                
            # 가격 검증
            is_valid, error_message = validate_product_price(price)
            if not is_valid:
                flash(error_message)
                return redirect(url_for('edit_product', product_id=product_id))
                
            cursor.execute("""
                UPDATE product 
                SET title = ?, description = ?, price = ?
                WHERE id = ? AND seller_id = ?
            """, (title, description, price, product_id, session['user_id']))
            db.commit()
            flash('상품이 수정되었습니다.')
            return redirect(url_for('view_product', product_id=product_id))
            
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        if not product:
            flash('상품을 찾을 수 없습니다.')
            return redirect(url_for('dashboard'))
            
        return render_template('edit_product.html', product=product)
    except Exception as e:
        logger.error(f"Product Edit Error: {str(e)}", exc_info=True)
        flash('상품 수정 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
        return redirect(url_for('dashboard'))

@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
@handle_db_error
def delete_product(product_id):
    try:
        if not is_product_owner(product_id):
            flash('상품을 삭제할 권한이 없습니다.')
            return redirect(url_for('dashboard'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM product WHERE id = ? AND seller_id = ?", 
                      (product_id, session['user_id']))
        db.commit()
        flash('상품이 삭제되었습니다.')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Product Delete Error: {str(e)}", exc_info=True)
        flash('상품 삭제 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    print("\n=== 서버가 시작되었습니다 ===")
    print("로컬 주소: http://127.0.0.1:5000")
    print("외부 접속 주소: http://localhost:5000")
    print("===========================\n")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
