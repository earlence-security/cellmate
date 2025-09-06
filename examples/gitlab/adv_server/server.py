from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS so client on another port can access

@app.route('/submit', methods=['POST'])
def submit():
    data = request.get_json()
    message = data.get('message', '')
    print(f"Received message: {message}")
    return jsonify(status="OK", echo=message)

if __name__ == '__main__':
    app.run(port=3000)