from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import os
import time
import pymysql

app = Flask(__name__)
CORS(app)

# Use MySQL if env vars exist, else SQLite for dev
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DB = os.getenv("MYSQL_DB")

if MYSQL_HOST:
    while True:
        try:
            conn = pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER,
                                   password=MYSQL_PASSWORD, database=MYSQL_DB)
            conn.close()
            break
        except pymysql.err.OperationalError:
            print("Waiting for MySQL to be ready...")
            time.sleep(2)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# SINGLE Item model definition
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)


@app.route("/items", methods=["GET"])
def get_items():
    items = Item.query.all()
    return jsonify([{"id": i.id, "name": i.name, "quantity": i.quantity} for i in items])

@app.route("/items", methods=["POST"])
def add_item():
    data = request.json
    item = Item(name=data["name"], quantity=data["quantity"])
    db.session.add(item)
    db.session.commit()
    return jsonify({"status": "success"}), 201

@app.route("/items/<int:item_id>", methods=["PUT"])
def update_item(item_id):
    data = request.json
    item = Item.query.get_or_404(item_id)
    item.name = data["name"]
    item.quantity = data["quantity"]
    db.session.commit()
    return jsonify({"status": "updated"})

@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({"status": "deleted"})

app = Flask(__name__)

@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(host="0.0.0.0", port=5000)
