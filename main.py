from flask import  Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime, timedelta
import pymysql
import pymysql.cursors
import hashlib
from config import Config, DATABASE_CONFIG
from flask_mail import Message, Mail
import requests
from bs4 import BeautifulSoup
import pandas as pd
import secrets
import os
from werkzeug.utils import secure_filename
from PIL import Image
import random
import string
import re


app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = "phantom"
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
app.config.from_object(Config)

mail = Mail(app)

# 네이버 주식 크롤링
def get_daily_stock_info(stock_id):
    date_list = []
    price_list = []

    url = f"https://finance.naver.com/item/sise_day.nhn?code={stock_id}"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')

    # 페이지의 테이블 데이터를 파싱
    trs = soup.select('table.type2 tr')
    for tr in trs:
        tds = tr.select('td')
        if len(tds) < 7:
            continue
        date_list.append(tds[0].text.strip())
        price_list.append(tds[1].text.strip())

    # 데이터 프레임 생성
    return pd.DataFrame({'Date': date_list, 'Price': price_list})

def generate_new_password(length=10):
    characters = string.ascii_letters + string.digits + string.punctuation #대소문자 숫자 특수문자
    return ''.join(random.choice(characters) for i in range(length)) #랜덤 10자리

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_otp():
    otp = secrets.randbelow(1000000) #0~1000000미만 범위에 랜덤한 정수 생성
    return f"{otp:06d}" #6자리 수 생성이 아니면 앞은 0으로 체우기

def validate_password(password):
    # 대문자, 소문자, 특수문자를 각각 최소 한 개씩 포함하는 정규 표현식
    upper_case = re.compile(r'[A-Z]')
    lower_case = re.compile(r'[a-z]')
    special_char = re.compile(r'[~!@#$%^&*()?]')  # 제한된 특수문자 집합

    # 검사를 수행합니다.
    if not upper_case.search(password):
        return False, '비밀번호에 최소 한 개의 대문자가 포함되어야 합니다.'
    if not lower_case.search(password):
        return False, '비밀번호에 최소 한 개의 소문자가 포함되어야 합니다.'
    if not special_char.search(password):
        return False, '비밀번호에 허용된 특수문자(~!@#$%^&*()?) 중 최소 한 개가 포함되어야 합니다.'

    # 모든 조건을 만족시키면 True를 반환합니다.
    return True, '비밀번호가 요구 조건을 충족합니다.'
# 이미지 업로드 폴더 설정
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'image')

# 허용된 파일 확장자
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_IMAGE_SIZE = 6 * 1024

def image_size_ok(image):
    img = Image.open(image.stream)
    img_size = len(img.fp.read())
    return img_size <= MAX_IMAGE_SIZE

@app.route('/')
def home():
    return render_template('main.html')

@app.route('/stock')
def stock():
    stock_ids = {
        '삼성전자': '005930',
        'SK하이닉스': '000660',
        'LG에너지솔루션' : '373220',
        '삼성바이오로직스':'207940',
        '삼성전자우' : '005935',
        '현대차' : '005380',
        'POSCO홀딩스' : '005490',
        '기아' : '000270',
        'NAVER': '035420',
        'LG화학' : '051910'
    }

    stock_data = {}

    page_num = 1

    for name, code in stock_ids.items():
        df_daily =  get_daily_stock_info(code)
        first_row_data = df_daily.iloc[0].to_dict() if not df_daily.empty else {} #첫번째 행을 딕셔너리로 변환
        stock_data[name] = first_row_data

    return render_template('stock.html', stock_data=stock_data, stock_ids=stock_ids)

@app.route('/check_userid', methods=['POST'])
def check_userid():

    userid = request.form['userID']
    connection = pymysql.connect(**DATABASE_CONFIG)
    with connection.cursor() as cur:
        sql = "SELECT * FROM users WHERE id = %s"
        cur.execute(sql, (userid,))
        result = cur.fetchone()
        cur.close()

    if result: #이미 존재하는 아이디라면 세션에서 userid_valid로 false로 불허한다.
        session['userid_valid'] = False
        return jsonify({'exists' : True})
    else:
        session['userid_valid'] = True
        session['checked_userid'] = userid
        return jsonify({'exists': False})

@app.route('/check_nickname', methods=['POST'])
def check_nickname():

    nickname= request.form['nickname']
    connection = pymysql.connect(**DATABASE_CONFIG)
    with connection.cursor() as cur :
        sql = "SELECT * FROM users WHERE nickname = %s"
        cur.execute(sql,(nickname,))
        result = cur.fetchone()
        cur.close()

    if result:
        session['nickname_valid'] = False
        return jsonify({'exists' : True})
    else:
        session['nickname_valid'] = True
        session['checked_nickname'] = nickname
        return jsonify({'exists': False})

@app.route('/law')
def law():
    return render_template('law.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':

        userid = request.form.get('userID')
        password = request.form.get('password')
        check_passwd = request.form.get('checkPassword')
        name = request.form.get('username')
        nickname = request.form.get('nickname')
        email = request.form.get('email')

        # 중복 검사 확인
        if userid != session.get('checked_userid') or nickname != session.get('checked_nickname'):
            flash('아이디와 닉네임 중복 검사를 해주세요.')
            return redirect(url_for('signup'))

        # 비밀번호 길이 확인
        if len(password) < 8 or len(password) > 14:
            flash('비밀번호는 8자 이상 14자 이하로 설정해주세요.')
            return redirect(url_for('signup'))

        # 비밀번호 일치 확인
        if not (password and check_passwd and password == check_passwd):
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('signup'))

        # 비밀번호 복잡성 확인
        if not validate_password(password):
            flash('비밀번호는 대문자, 소문자, 특수문자를 각각 최소 하나씩 포함해야 합니다.')
            return redirect(url_for('signup'))

        # 모든 검증이 통과되면 비밀번호 해싱
        hashpasswd = hashlib.sha256(password.encode()).hexdigest()

        # 이메일 OTP 인증 확인
        if not session.get('otp_verified'):
            flash('이메일 인증을 완료해주세요.')
            return redirect(url_for('signup'))

        connection = pymysql.connect(**DATABASE_CONFIG)
        # 데이터베이스 연결 및 사용자 정보 저장
        try:
            with connection.cursor() as cur:
                sql = "INSERT INTO users (id, passwd, username, nickname, email) VALUES (%s, %s, %s, %s, %s)"
                cur.execute(sql, (userid, hashpasswd, name, nickname, email))
                connection.commit()
        except pymysql.MySQLError as e:
            flash('가입 중 문제가 발생했습니다. 다시 시도해주세요.')
            print('가입 문제 발생:', e)
            connection.rollback()
            return redirect(url_for('signup'))
        finally:
            connection.close()

        session.clear()

        # 성공 메시지와 함께 로그인 페이지로 리다이렉트
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('home'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/find_ID', methods=['GET', 'POST'])
def find_ID():
    if request.method == 'POST':

        username = request.form['username']
        email = request.form['email_id']

        # 데이터베이스 연결 및 사용자 ID 조회
        connection = pymysql.connect(**DATABASE_CONFIG)
        try:
            with connection.cursor() as cursor:
                # 데이터베이스에서 이름과 이메일이 일치하는 사용자 ID 조회
                sql = "SELECT id FROM users WHERE username = %s AND email = %s"
                cursor.execute(sql, (username, email))
                result = cursor.fetchone()

                # 일치하는 사용자 ID가 있는 경우
                if result:
                    return jsonify({'id': result['id']})
                else:
                    return jsonify({'error': '일치하는 계정이 없습니다.'}), 404

        except Exception as e:
            app.logger.error(f"Database error: {e}")
            connection.rollback()

            return jsonify({'error': '데이터베이스 오류가 발생했습니다.'}), 500
        finally:
            connection.close()

    return render_template('findID.html')

@app.route('/find_password', methods=['POST'])
def find_password():

    id_pw = request.form['id_pw']
    email_pw = request.form['email_pw']
    connection = pymysql.connect(**DATABASE_CONFIG)
    try:
        with connection.cursor() as cursor:

            sql = "SELECT email FROM users WHERE id = %s"
            cursor.execute(sql, (id_pw,))
            result = cursor.fetchone()

            if result and result['email'] == email_pw:
                # 새로운 비밀번호 생성
                new_password = generate_new_password()
                #해시화 시켜야함
                hashedPassword = hashlib.sha256(new_password.encode()).hexdigest()

                # 사용자의 비밀번호를 새로운 비밀번호로 업데이트
                sql = "UPDATE users SET passwd = %s WHERE id = %s"
                cursor.execute(sql, (hashedPassword, id_pw))
                connection.commit()

                # 이메일 발송 로직
                msg = Message('비밀번호 재설정 안내', sender=app.config['MAIL_USERNAME'], recipients=[email_pw])
                msg.body = f'귀하의 새로운 비밀번호는 다음과 같습니다: {new_password}\n'
                mail.send(msg)

                flash('비밀번호 재설정 이메일을 발송했습니다.')
                return redirect(url_for('findPW'))
            else:
                flash('입력하신 정보와 일치하는 계정이 없습니다.')
                return redirect(url_for('findPW'))
    except Exception as e:
        flash('데이터베이스 오류가 발생했습니다.')
        app.logger.error(f"Database error: {e}")
        connection.rollback()

        return redirect(url_for('findPW'))
    finally:
        connection.close()

@app.route('/findPW')
def findPW():
    return render_template('findPW.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        userID = request.form['userID']
        password = request.form['password']
        connection = pymysql.connect(**DATABASE_CONFIG)
        try:
            with connection.cursor() as cur:
                # 계정 상태까지 조회하는 SQL 쿼리 수정
                sql = "SELECT passwd, account_status, nickname FROM users WHERE id = %s"
                cur.execute(sql, (userID,))
                result = cur.fetchone()

                if result:
                    hashedPassword = hashlib.sha256(password.encode()).hexdigest()
                    if result['passwd'] == hashedPassword:
                        if result['account_status'] == 1:  # 계정이 밴 상태일 경우
                            flash('이 계정은 접근이 제한되었습니다.')
                            return redirect(url_for('home'))  # 홈으로 리다이렉트
                        else:
                            # 로그인 성공 처리
                            session.permanent = True
                            app.permanent_session_lifetime = timedelta(hours=1)
                            session['user_id'] = userID
                            session['nickname'] = result['nickname']
                            return redirect(url_for('home'))  # 홈으로 리다이렉트
                    else:
                        flash('비밀번호가 잘못되었습니다.')
                else:
                    flash('존재하지 않는 사용자입니다.')

        except Exception as e:
            flash('로그인 처리 중 오류가 발생했습니다.')
            app.logger.error(f'Login error: {e}')
            connection.rollback()
        finally:
            connection.close()

    return render_template('login.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form['email']  # 이메일 주소를 입력 폼에서 가져옵니다.
    otp = generate_otp()
    session['otp'] = otp  # 세션에 OTP 저장
    print(session)

    msg = Message('인증번호', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'귀하의 인증번호는 {otp}입니다.'
    mail.send(msg)

    return jsonify({'message': '인증번호가 발송되었습니다.'})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():

    user_otp = request.form['InputOtp'].strip()

    if 'otp' in session:
        session_otp = str(session['otp'])  # 세션의 OTP 값을 문자열로 변환

        if session_otp == user_otp:

            session.pop('otp', None)
            session['otp_verified'] = True

            return jsonify({'message': '인증번호가 확인되었습니다.'})
        else:

            return jsonify({'message': '인증번호가 일치하지 않습니다.'}), 400
    else:
        return jsonify({'message': '세션에 인증번호가 없습니다. 다시 시도해주세요.'}), 400

@app.route('/notices')
def notices():
    connection = pymysql.connect(**DATABASE_CONFIG)
    cur = connection.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM noti ORDER BY seq DESC")

    notices = cur.fetchall()
    cur.close()

    return render_template('notices.html', notices=notices)

@app.route('/notice/<int:seq>')
def notice(seq):
    connection = pymysql.connect(**DATABASE_CONFIG)
    cur = connection.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM noti WHERE seq = %s", (seq,))
    notice = cur.fetchone()
    cur.close()
    return render_template('notice.html', notice=notice)

@app.route('/community')
def community():
    connection = pymysql.connect(**DATABASE_CONFIG)
    try:
        with connection.cursor() as cur:
            # is_deleted가 0인 게시물만 가져오도록 쿼리 수정
            cur.execute("""
                SELECT id, title, author, content, created_at, image_path 
                FROM community 
                WHERE is_deleted = 0
                ORDER BY created_at DESC
            """)
            posts = cur.fetchall()

    except Exception as e:
        flash(f'데이터를 불러오는 중 오류가 발생했습니다: {e}')
        app.logger.error(f'Database Error: {e}')
        return redirect(url_for('home'))

    return render_template('community.html', posts=posts)

@app.route('/new_post', methods=['GET', 'POST'])
def new_post():

    if 'user_id' not in session:
        flash('로그인이 필요한 페이지입니다.')
        return redirect(url_for('login'))

    if request.method == 'POST':

        title = request.form['title']
        content = request.form['content']
        author = session['nickname']
        image = request.files['image']

        relative_image_path = None


        if image and allowed_file(image.filename):

            if not image_size_ok(image):
                flash('이미지 크기가 너무 큽니다. 크기를 줄여서 다시 업로드해주세요.')
                return redirect(request.url)

            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            img = Image.open(image.stream)  # 이미지를 열 때 image.stream을 사용
            img.thumbnail((800, 800))

            if not os.path.exists(os.path.dirname(image_path)):
                os.makedirs(os.path.dirname(image_path))

            img.save(image_path)
            relative_image_path = os.path.join('image', filename).replace("\\", "/")

        connection = pymysql.connect(**DATABASE_CONFIG)
        try:
            with connection.cursor() as cur:
                sql = "INSERT INTO community (title, content, author, image_path) VALUES (%s, %s, %s, %s)"
                cur.execute(sql, (title, content, author, relative_image_path))

            connection.commit()
            flash('게시글이 성공적으로 작성되었습니다.')
        except Exception as e:
            flash(f'게시글 작성 중 오류가 발생했습니다: {e}')
            connection.rollback()

        return redirect(url_for('community'))

    return render_template('new_post.html')


@app.route('/Adminauth', methods=['GET', 'POST'])
def Adminauth():
    if 'user_id' in session and session['user_id'] == 'admin':
        if request.method == 'GET':
            connection = pymysql.connect(**DATABASE_CONFIG)
            try:
                with connection.cursor() as cur:
                    cur.execute("SELECT email FROM users WHERE id = 'admin'")
                    admin_data = cur.fetchone()

                    if admin_data:
                        session['admin_email'] = admin_data['email']
                    else:
                        flash('관리자 정보를 찾을 수 없습니다.')
                        return redirect(url_for('home'))

            except Exception as e:
                flash('데이터베이스 오류가 발생했습니다.')
                app.logger.error(f"Database error: {e}")
                connection.rollback()
                return redirect(url_for('home'))
            finally:
                connection.close()

        # 세션에서 OTP 인증 여부 확인
        if 'otp_verified' in session and session['otp_verified']:
            # OTP 인증이 완료되었으면 관리자 페이지로 리다이렉트
            session.pop('otp_verified', None)
            return redirect(url_for('admin'))
        else:
            admin_email = session.get('admin_email', '')
            return render_template('Adminauth.html', admin_email=admin_email)
    else:
        # user_id가 admin이 아니면 홈으로 리다이렉트
        flash('관리자만 접근 가능합니다.')
        return redirect(url_for('home'))


# 관리자 페이지 라우트
@app.route('/admin')
def admin():
    # 관리자 권한 확인
    if not (session.get('user_id') and session['user_id'] == 'admin'):
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('home'))

    # 초기 페이지 로드 시 표시될 기본 데이터
    return render_template('admin.html')


@app.route('/new_noti_post', methods=['GET', 'POST'])
def new_noti_post():

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        connection = pymysql.connect(**DATABASE_CONFIG)
        try:
            with connection.cursor() as cur:
                sql = "INSERT INTO noti (title, content) VALUES (%s, %s)"
                cur.execute(sql, (title, content))
                connection.commit()
                flash('새 공지사항이 작성되었습니다.')
                return redirect(url_for('admin'))  # 관리자 페이지 또는 공지사항 목록 페이지로 리다이렉트
        except Exception as e:
            flash('공지사항 작성 중 오류가 발생했습니다.')
            app.logger.error(f"Error creating a new notification: {e}")
            connection.rollback()
        finally:
            connection.close()

    # GET 요청 시에는 작성 페이지를 렌더링
    return render_template('admin_post.html')

@app.route('/ban')
def ban_page():
    # 여기서는 추가적인 권한 검사가 없으나 실제 앱에서는 필요할 수 있습니다.
    return render_template('ban.html')

@app.route('/ban_user', methods=['POST'])
def ban_user():
    nickname = request.form.get('nickname')
    connection = pymysql.connect(**DATABASE_CONFIG)
    try:
        with connection.cursor() as cursor:
            sql = "UPDATE users SET account_status = '1' WHERE nickname = %s"
            cursor.execute(sql, (nickname,))
            connection.commit()
        return jsonify({'banned': True})
    except Exception as e:
        app.logger.error(f"Error banning user: {e}")
        connection.rollback()  # 에러 발생 시 롤백
        return jsonify({'message': '사용자 밴 처리 중 오류가 발생했습니다.'}), 500
    finally:
        connection.close()  # 데이터베이스 연결을 닫습니다.

@app.route('/search_user_for_ban', methods=['POST'])
def search_user_for_ban():
    search_nickname = request.form['nickname']
    user_details = None
    connection = pymysql.connect(**DATABASE_CONFIG)
    try:
        with connection.cursor() as cur:
            sql = "SELECT id, username, nickname, email, account_status FROM users WHERE nickname = %s"
            cur.execute(sql, (search_nickname,))
            user_details = cur.fetchone()

            if user_details:
                return jsonify({
                    'username': user_details['username'],
                    'email': user_details['email'],
                    'nickname': user_details['nickname'],
                    'account_status': '밴됨' if user_details['account_status'] else '이용중'
                })
            else:
                return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404

    except Exception as e:
        app.logger.error(f"Search User for Ban Error: {e}")
        connection.close()
        return jsonify({'error': '사용자 검색 중 오류가 발생했습니다.'}), 500


@app.route('/search_user', methods=['POST'])
def search_user():

    search_username = request.form['search_username']
    user_details = None
    search_results = None
    connection = pymysql.connect(**DATABASE_CONFIG)
    try:
        with connection.cursor() as cur:
            # 사용자 닉네임으로 검색하여 사용자 정보 가져오기
            sql = "SELECT * FROM users WHERE nickname = %s"
            cur.execute(sql, (search_username,))
            user_details = cur.fetchone()

            # 사용자 상세정보를 HTML로 렌더링
            user_details_html = ''
            if user_details:
                user_details_html = render_template('user_details.html', user_details=user_details)
                # 커뮤니티 테이블에서 게시물 검색 시 사용자 ID 사용
                cur.execute("SELECT * FROM community WHERE author = %s AND is_deleted = 0", (user_details['id'],))
                search_results = cur.fetchall()

            # 검색 결과를 HTML로 렌더링
            search_results_html = render_template('search_results.html', search_results=search_results)
            return jsonify({
                'user_details_html': user_details_html,
                'search_results_html': search_results_html
            })

    except Exception as e:
        app.logger.error(f'Search Error: {e}')
        return jsonify({'error': '검색 중 오류가 발생했습니다.'}), 500




@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    connection = pymysql.connect(**DATABASE_CONFIG)
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            # 게시글 삭제 플래그 쿼리
            result = cursor.execute("UPDATE community SET is_deleted = 1 WHERE id = %s", (post_id,))
            connection.commit()
            if result > 0:
                return jsonify({'success': True, 'message': '게시물이 삭제 플래그 되었습니다.'})
            else:
                return jsonify({'success': False, 'message': '삭제할 게시물을 찾을 수 없습니다.'})

    except Exception as e:
        app.logger.error(f'Delete Error: {e}')
        connection.rollback()
        return jsonify({'error': '게시물 삭제 중 오류가 발생했습니다.'}), 500






if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)


#
# @app.route('/')
# def home():
#     return render_template('home/main.html')


