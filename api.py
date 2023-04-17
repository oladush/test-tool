# this is simple json api
# methods: rulecreate, networkseparate, networkdivide

# external modules
from modules import NetworkSeparator
from modules import NetworkDivide
from modules import RuleCreator


import os
from flask import Flask, jsonify, request, render_template

template_dir = os.path.abspath('.')

app = Flask(__name__, template_folder=template_dir)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/networkseparate', methods=['POST'])
def network_separate():
    data = request.get_json()
    orig = data['orig']; excl = data['excl']

    orig_striped = []
    excl_striped = []

    for elem in orig:
        if elem:
            orig_striped.append(elem.strip())

    for elem in excl:
        if elem:
            excl_striped.append(elem.strip())

    try:
        result = NetworkSeparator.separate(orig_striped, excl_striped)
        return jsonify({'result': [str(res) for res in result]})
    except Exception as ex:
        return jsonify({'result': str(ex)})

@app.route('/networkdivide', methods=['POST'])
def network_divide():
    data = request.get_json()
    network = data['network'].strip()
    prefix = data['prefix'].strip()

    try:
        result = NetworkDivide.divide(network, int(prefix))
        return jsonify({'result': [str(res) for res in result]})
    except Exception as ex:
        return jsonify({'result': str(ex)})

@app.route('/rulecreate', methods=['POST'])
def rule_create():
    matrix = request.get_json()

    try:
        result = RuleCreator.json_rules(matrix)
        return jsonify({'result': result})
    except Exception as ex:
        return jsonify({'result': str(ex)})

if __name__ == '__main__':
    app.run(debug=True)