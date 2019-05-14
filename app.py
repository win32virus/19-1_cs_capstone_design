from flask import Flask, render_template, session, url_for, redirect, flash, request
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import requests
import json
import os

app = Flask(__name__)
app.config['UPLOAD_DIR'] = 'uploads'
app.config['JSON_DIR'] = 'json'
app.config['SECRET_KEY'] = os.urandom(24)
app.config['CUCKOO_API_HOST'] = '192.168.126.151:8090'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sql3"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __table_name__ = 'user'
    idx = db.Column(db.Integer, nullable=False, primary_key=True)
    user_id = db.Column(db.String, nullable=False, unique=True)
    user_pw = db.Column(db.String, nullable=False)
    comments = db.relationship('Comment', backref='user', lazy=True)

    def __init__(self, user_id, pw):
        self.user_id = user_id
        self.set_password(pw)

    def __repr__(self):
        return '<User %r>' % self.user_id

    def set_password(self, pw):
        self.user_pw = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.user_pw, pw)


class Comment(db.Model):
    __table_name__ = 'comment'
    idx = db.Column(db.Integer, nullable=False, primary_key=True)
    task_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.idx'), nullable=True)
    content = db.Column(db.Text)

    def __repr__(self):
        return '<Comment %r>' % self.idx


@app.template_filter()
def to_hex(text):
    result = ""
    for t in text:
        result += "%02x " % ord(t)
    return result


@app.route('/')
def index():
    if 'user_idx' in session:
        return render_template('main/index.html')
    else:
        return redirect(url_for('login'))


@app.route('/sample/')
def sample_list():
    if 'user_idx' not in session:
        return redirect(url_for('index'))

    page = request.args.get('page')
    m = request.args.get('m')
    if page is None:
        page = 1
    else:
        page = int(page)
        if page <= 0:
            page = 1

    url = "http://{0}/tasks/list".format(app.config['CUCKOO_API_HOST'])
    if m and int(m) == 1:
        url = "{0}?owner={1}".format(url, session['user_id'])
    res = requests.get(url)
    obj = json.loads(res.text)
    tasks_count = len(obj['tasks'])
    res.close()
    url = "http://{0}/tasks/list/10/{1}".format(app.config['CUCKOO_API_HOST'], 10*(page-1))
    if m and int(m) == 1:
        url = "{0}?owner={1}".format(url, session['user_id'])
    res = requests.get(url)
    obj = json.loads(res.text)
    res.close()
    # id_list = []
    return render_template('sample/sample_list.html',
                           tasks=obj['tasks'],
                           pagination=True,
                           page=page,
                           tasks_count=tasks_count)


@app.route('/report/<int:idx>')
def report(idx):
    if 'user_idx' not in session:
        return redirect(url_for('index'))

    # cache
    json_path = os.path.join(app.config['JSON_DIR'], '{0}.json'.format(idx))
    if json_path and os.path.exists(json_path) is True:
        with open(json_path, "r") as f:
            obj = json.loads(f.read())
    else:
        report_url = "http://{0}/tasks/report/{1}".format(app.config['CUCKOO_API_HOST'], idx)
        res = requests.get(report_url)
        obj = json.loads(res.text)
        res.close()
        with open(json_path, "w") as f:
            f.write(json.dumps(obj))
    # print(obj)
    """
    for key, data in obj['static']['hwp']['streams'].items():
        print(data['meta'])
    """
    comments = Comment.query.filter_by(task_id=idx)
    return render_template('analysis/index.html', report=obj, comments=comments)


@app.route('/sample/new', methods=['GET', 'POST'])
def sample_new():
    if 'user_idx' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            package = request.form.get('package', None)
            save_path = os.path.join(app.config['UPLOAD_DIR'], filename)
            file.save(save_path)

            url = "http://{0}/tasks/create/file".format(app.config['CUCKOO_API_HOST'])

            with open(save_path, 'rb') as f:
                multipart_file = {"file": (os.path.basename(save_path), f)}
                data = {'package': package, 'owner': session['user_id']}
                res = requests.post(url, files=multipart_file, data=data)
            res.close()
            return redirect(url_for('sample_list'))

    return render_template('sample/sample_upload.html', title='single file upload')


@app.route('/comment/<int:idx>', methods=['POST'])
def comment(idx):
    content = request.form.get('content', None)
    if content:
        comment = Comment(task_id=idx, user_id=session['user_idx'], content=content)
        db.session.add(comment)
        try:
            db.session.commit()
            flash('Comment Success')
            return redirect(url_for('report', idx=idx))
        except Exception as e:
            db.session.rollback()
            flash('Error Occurred')
            return redirect(url_for('report', idx=idx))
    else:
        flash('content is not specified')
        return redirect(url_for('report', idx=idx))


@app.route('/user/join', methods=['GET', 'POST'])
def join():
    if request.method == 'POST':
        user_id = request.form['user_id']
        user_pw = request.form['user_pw']

        user = User(user_id=user_id, pw=user_pw)
        db.session.add(user)

        try:
            db.session.commit()
            flash('Join Success')
            return redirect(request.url)
        except Exception as e:
            db.session.rollback()
            flash('id already exists!')
            return redirect(request.url)

    return render_template('user/user_form.html', title='Join')


@app.route('/user/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        user_pw = request.form['user_pw']

        user = User.query.filter_by(user_id=user_id).first()
        if user is None:
            flash('ID or PW is invalid')
            return redirect(request.url)
        else:
            if user.check_password(user_pw) is True:
                session['user_idx'] = user.idx
                session['user_id'] = user.user_id
                flash('Login Success')
                return redirect(url_for('index'))
    return render_template('user/user_form.html', title='Login')


@app.route('/user/logout')
def logout():
    session.pop('user_idx', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
