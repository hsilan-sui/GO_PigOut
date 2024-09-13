from flask import Flask, render_template


app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/<int:food_id>")
def food(food_id):
    return f"哈哈, {food_id}"

if __name__ == "__main__":
    app.run()