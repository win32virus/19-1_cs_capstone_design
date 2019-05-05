from flask import Flask, render_template, session, url_for, redirect, flash, request
from werkzeug.utils import secure_filename
import requests
import json
import os

app = Flask(__name__)
app.config['UPLOAD_DIR'] = 'uploads'
app.config['CUCKOO_API_HOST'] = '192.168.126.151:8090'


@app.template_filter()
def to_hex(text):
    result = ""
    for t in text:
        result += "%02x " % ord(t)
    return result


@app.route('/')
def index():
    return render_template('main/index.html')


@app.route('/sample/')
def sample_list():
    page = request.args.get('page')
    if page is None:
        page = 1
    else:
        page = int(page)
        if page <= 0:
            page = 1

    url = "http://{0}/tasks/list".format(app.config['CUCKOO_API_HOST'])
    res = requests.get(url)
    obj = json.loads(res.text)
    tasks_count = len(obj['tasks'])
    res.close()
    url = "http://{0}/tasks/list/10/{1}".format(app.config['CUCKOO_API_HOST'], 10*(page-1))
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
    report_url = "http://{0}/tasks/report/{1}".format(app.config['CUCKOO_API_HOST'], idx)
    res = requests.get(report_url)
    obj = json.loads(res.text)
    # print(obj)
    """
    for key, data in obj['static']['hwp']['streams'].items():
        print(data['meta'])
    """

    res.close()
    return render_template('analysis/index.html', report=obj)


@app.route('/sample/new', methods=['GET', 'POST'])
def sample_new():
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
            fname, package = os.path.splitext(filename)
            package = package.lower()[1:]
            save_path = os.path.join(app.config['UPLOAD_DIR'], filename)
            file.save(save_path)

            url = "http://{0}/tasks/create/file".format(app.config['CUCKOO_API_HOST'])

            with open(save_path, 'rb') as f:
                multipart_file = {"file": (os.path.basename(save_path), f)}
                data = {'package': package}
                res = requests.post(url, files=multipart_file, data=data)
            res.close()
            return redirect(url_for('sample_list'))

    return render_template('sample/sample_upload.html', title='single file upload')


if __name__ == '__main__':
    app.run()
