from flask import Flask, render_template, url_for, redirect, request,send_file,send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import requests, json
from pymongo import MongoClient
from notion.client import NotionClient
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')



# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(username=form.username.data).first()
#         if user:
#             if bcrypt.check_password_hash(user.password, form.password.data):
#                 login_user(user)
#                 return redirect(url_for('dashboard'))
#     return render_template('login.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)
@app.route('/')
def home():
    return render_template('home.html')




array_of_results = []
first_time=True


cluster = MongoClient(
    "mongodb://notionAPI:Zxcvbnm1238!@cluster0-shard-00-00.phkvz.mongodb.net:27017,cluster0-shard-00-01.phkvz.mongodb.net:27017,cluster0-shard-00-02.phkvz.mongodb.net:27017/?ssl=true&replicaSet=atlas-rkmjvp-shard-0&authSource=admin&retryWrites=true&w=majority"
     )
db = cluster["ForApi"]
col = db["Block"]

token = "token"  #secret_jlfaf0TOQsF1aOSLK4EpctPLLDNMAyVxQOAlf9JnSLB
database_id = "database_id"  #8ebce70ab01d4b36a26b0b83d07a4cdd



def create_headers(token):
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Notion-Version": "2021-05-13",
        "Accept": "application/json",
    }
    return headers

def create_url(type):
    url = "https://api.notion.com/v1/"
    if type == "db":
        url += "search/"
    elif type == "pg":
        url += "pages/"
    elif type == "li":
        url += "search/"
    elif type == "bl":
        url += "blocks/"
    return url


def insert_to_mongo(data):
    #col.insert_one({"json": data})
    pass


def readDB(database_id, token):
    try:
        playload = {"page_size": 100}
        response = requests.post(
            f"https://api.notion.com/v1/databases/{database_id}/query",
            json=playload,
            headers=create_headers(token),
        )
        print(json.dumps(response.json(),indent=4))
        return response.json()
    except:
        print("Error while fetching a user...")

# readDB(database_id,token)



def get_block_by_id(block_id,token):
    url = f"https://api.notion.com/v1/blocks/{block_id}"

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Notion-Version": "2021-05-13",
        "Accept": "application/json",
    }
    response = requests.request("GET", url, headers=headers)
    #print(json.dumps(response.json(), indent=4))
    return json.dumps(response.json(), indent=4)



def get_page_blocks(arr,token):
    arr2 = []
    for i in arr:
        arr2.append(get_block_by_id(i, token))
        json_o = json.loads(get_block_by_id(i, token))
        obj = json_o.items()
        for k, v in obj:
            if k == "type":
                if v == "column_list":
                    arr2.append(column_list(i))
    return arr2



def column_list(block_id):


    url = f"https://api.notion.com/v1/blocks/{block_id}/children?page_size=100"

    headers = {
        "Authorization": "Bearer " + "secret_jlfaf0TOQsF1aOSLK4EpctPLLDNMAyVxQOAlf9JnSLB",
        "Content-Type": "application/json",
        "Notion-Version": "2021-05-13",
        "Accept": "application/json",
    }

    response = requests.request("GET", url, headers=headers)

    #print(json.dumps(response.json(), indent=4))
    return json.dumps(response.json())


#get_list_of_pages(headers)



def get_content_from_db(json_str):
    arr_rows = []
    index = 0
    for i in json_str["results"]:
        index += 1
        arr_rows.append(f" --------------- {index} row ---------------")
        for key , value in i["properties"].items():
            for k,v in value.items():
                if k == "rich_text" or k == "title":
                    arr_rows.append(v)
    return arr_rows


def get_urls(json_str):

    arr = []
    for j in json_str["results"]:
            arr.append(j["url"])
    print(arr)
    return arr



@app.route("/retrieve_a_block", methods=["POST", "GET"])
def retrieve_block():
    result = "there should be json"
    if request.method == ("POST"):
        token = request.form.get("integration")
        database_id = request.form.get("database")
        if token and database_id:
            f = open("files/result.txt", "w")
            result = readDB(database_id,token)
            array_of_results = get_content_from_db(result)
            for i in array_of_results:
                f.write(i.__str__()+"\n")
            f.close()
            app.config["RESULT"] = "files"
            return send_from_directory(app.config["RESULT"], path="result.txt", as_attachment=True)



    return render_template("retrieve_a_block.html")


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/downloads")
@login_required
def downloads():
    return render_template("downloads.html")

if __name__ == "__main__":
    app.run(debug=True)
