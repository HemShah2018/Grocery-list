from flask import Flask, jsonify

app = Flask(__name__)

# Sample data
users = [
    {'id': 1, 'name': 'Arshad'},
    {'id': 2, 'name': 'Vishnu'},
    {'id': 3, 'name': 'Reddy'},
]

@app.route('/users', methods=['GET'])
def get_users():
    return jsonify(users)

if __name__ == "__main__":
    app.run(debug=True)
