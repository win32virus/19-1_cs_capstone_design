from flask import Flask, render_template, session, url_for, redirect, flash, request, make_response
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


@app.template_filter()
def find_exec(text):
    lines = text.split('\n')
    for line in lines:
        if line.find('EXEC') > -1:
            return line
    return 'No Exec line'

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
    json_path = os.path.join(app.config['JSON_DIR'], '{0}'.format(idx))
    if json_path and os.path.exists(json_path) is False:
        os.mkdir(json_path, 0777)
    report_path = os.path.join(json_path, '{0}.json'.format(idx))

    if report_path and os.path.exists(report_path) is True:
        with open(report_path, "r") as f:
            report_obj = json.loads(f.read())
    else:
        report_url = "http://{0}/tasks/report/{1}".format(app.config['CUCKOO_API_HOST'], idx)
        res = requests.get(report_url)
        report_obj = json.loads(res.text)
        behavior_obj = report_obj.get('behavior', [])
        behavior_path = os.path.join(json_path, '{0}_behavior.json'.format(idx))
        static_obj = report_obj.get('static', [])
        static_path = os.path.join(json_path, '{0}_static.json'.format(idx))
        res.close()
        with open(report_path, "w") as f:
            f.write(json.dumps(report_obj))
        with open(behavior_path, "w") as f:
            f.write(json.dumps(behavior_obj))
        with open(static_path, "w") as f:
            f.write(json.dumps(static_obj))

    screenshots = report_obj.get('screenshots', [])
    screenshot_obj = []
    for screenshot in screenshots:
        name = os.path.split(screenshot['path'])[-1][:-4]
        screenshot_url = "http://{0}/tasks/screenshots/{1}/{2}".format(app.config['CUCKOO_API_HOST'], idx, name)
        obj = {'name': screenshot_url}
        screenshot_obj.append(obj)
    comments = Comment.query.filter_by(task_id=idx)
    screenshot_obj.sort()
    return render_template('analysis/index.html', report=report_obj, comments=comments, screenshots=screenshot_obj)


@app.route('/analysis/chunk/<int:idx>/<int:pid>/<int:page>')
def chunk(idx, pid, page):

    if 'user_idx' not in session:
        obj = {'result': -1, 'msg': 'Session Error'}
        response = make_response(json.dumps(obj), 401)
        response.headers["Content-Type"] = "application/json"
        return response

    pid = int(pid)
    page = int(page)
    json_path = os.path.join(app.config['JSON_DIR'], '{0}'.format(idx))
    if json_path and os.path.exists(json_path) is False:
        obj = {'result': -1, 'msg': 'Report doesn\'t exist'}
        response = make_response(json.dumps(obj), 500)
        response.headers["Content-Type"] = "application/json"
        return response

    behavior_path = os.path.join(json_path, '{0}_behavior.json'.format(idx))

    if behavior_path and os.path.exists(behavior_path) is True:
        with open(behavior_path, "r") as f:
            behavior_obj = json.loads(f.read())

        behavior_obj = behavior_obj.get('processes', None)
        if behavior_obj is None:
            obj = {'result': -1, 'msg': 'No processes of Behavior'}
            response = make_response(json.dumps(obj))
            response.headers["Content-Type"] = "application/json"
            return response

        process = None
        for pdict in behavior_obj:
            if pdict['pid'] == pid:
                process = pdict

        if not process:
            obj = {'result': -1, 'msg': 'pid doesn\'t match'}
            response = make_response(json.dumps(obj))
            response.headers["Content-Type"] = "application/json"
            return response

        if page >= 0 and page < len(process["calls"]):
            chunk = dict(calls=process["calls"][(page-1)*10:page*10])
            for idx, call in enumerate(chunk["calls"]):
                call["id"] = (page-1) * 10 + idx
        else:
            chunk = dict(calls=[])
        obj = chunk
    else:
        obj = {'result': -1, 'msg': 'Behavior element of Report doesn\'t exist'}
        response = make_response(json.dumps(obj))
        response.headers["Content-Type"] = "application/json"
        return response
    return render_template('analysis/Behavior/_chunk.html', chunk=obj)


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


@app.route('/download/<int:idx>/<string:key>/<int:sid>', methods=['GET'])
def stream_download(idx, key, sid):
    if 'user_idx' not in session:
        obj = {'result': -1, 'msg': 'Session Error'}
        response = make_response(json.dumps(obj), 401)
        response.headers["Content-Type"] = "application/json"
        return response

    idx = int(idx)
    json_path = os.path.join(app.config['JSON_DIR'], '{0}'.format(idx))
    if json_path and os.path.exists(json_path) is False:
        obj = {'result': -1, 'msg': 'Report doesn\'t exist'}
        response = make_response(json.dumps(obj), 500)
        response.headers["Content-Type"] = "application/json"
        return response

    static_path = os.path.join(json_path, '{0}_static.json'.format(idx))

    static_obj = {}
    if static_path and os.path.exists(static_path) is True:
        with open(static_path, "r") as f:
            static_obj = json.loads(f.read())
    else:
        obj = {'result': -1, 'msg': 'Static json doesn\'t exist'}
        response = make_response(json.dumps(obj), 500)
        response.headers["Content-Type"] = "application/json"
        return response

    element = static_obj.get(key, None)
    if element is None:
        obj = {'result': -1, 'msg': 'key is not existed'}
        response = make_response(json.dumps(obj), 500)
        response.headers["Content-Type"] = "application/json"
        return response
    else:
        stream_obj = None
        if element.get('streams', None) is None:
            obj = {'result': -1, 'msg': 'streams aren\'t existed'}
            response = make_response(json.dumps(obj), 500)
            response.headers["Content-Type"] = "application/json"
            return response

        for key, data in element['streams'].items():
            if data['meta']['sid'] == sid:
                stream_obj = data
                break

        if stream_obj is None:
            obj = {'result': -1, 'msg': 'Stream is not existed'}
            response = make_response(json.dumps(obj), 500)
            response.headers["Content-type"] = "application/json"
            return response

        stream_content = stream_obj.get('stream_content', None)

        if stream_content is None:
            obj = {'result': -1, 'msg': 'Stream content is not existed'}
            response = make_response(json.dumps(obj), 500)
            response.headers["Content-type"] = "application/json"
            return response
        stream_name = stream_obj['meta']['name']
        response = make_response(stream_content)
        response.headers["Content-Type"] = "application/octet-stream"
        response.headers["Content-Disposition"] = "attachment; filename="+os.path.split(stream_name)[-1]
        return response


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
