from flask import Flask, render_template
import requests
import json

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('main/index.html')


@app.route('/sample/')
def sample_list():
    url = "http://localhost:8090/tasks/list"
    res = requests.get(url)
    obj = json.loads(res.text)
    res.close()
    # id_list = []
    """
    ctx = []
    for task in obj['tasks']:
        # id_list.append(task['id'])
        report_url = "http://localhost:8090/tasks/report/{0}".format(task['id'])
        res = requests.get(report_url)
        report_obj = json.loads(res.text)
        ctx.append({
            'id': task['id'],
            'md5': task['sample']['md5'],
            'completed_on': task['completed_on'],
            'package': task['package'],
            'filename': report_obj['target']['file']['name'],
            'score': report_obj['info']['score'],
            'status': task['status']
                    })
        res.close()
    """
    return render_template('samplelist/index.html', tasks=obj['tasks'])


@app.route('/report/<int:idx>')
def report(idx):
    report_url = "http://localhost:8090/tasks/report/{0}".format(idx)
    res = requests.get(report_url)
    obj = json.loads(res.text)
    res.close()
    #print(obj)
    return render_template('analysis/index.html', report=obj)


if __name__ == '__main__':
    app.run()
