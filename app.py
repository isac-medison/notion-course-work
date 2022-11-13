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
import sqlite3
from sqlite3 import Error

import bcrypt
app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
database='database.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn

def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        c.close()
    except Error as e:
        print(e)

conn = create_connection(database)
sql_create_userDetails_table = """ CREATE TABLE IF NOT EXISTS user_details (
                                        id integer PRIMARY KEY,
                                        user_id text,
                                        username text,
                                        name text NOT NULL,
                                        surname text,
                                        date_of_birth text
                                    ); """

sql_create_downloads_table = """ CREATE TABLE IF NOT EXISTS downloads(
                                        id integer PRIMARY KEY,
                                        user_id text NOT NULL,
                                        username text NOT NULL,
                                        database_id text NOT NULL,
                                        integration_id text NOT NULL
                                    ); """

if conn is not None:
    # create userDetails table
    create_table(conn, sql_create_userDetails_table)
    # create downloads table
    create_table(conn, sql_create_downloads_table)
else:
        print("Error! cannot create the database connection.")

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class UserDetails(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(20), nullable=True)
    surname = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.String(20), nullable=True)




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



def readDB(database_id, token):
    try:
        playload = {"page_size": 100}
        response = requests.post(
            f"https://api.notion.com/v1/databases/{database_id}/query",
            json=playload,
            headers=create_headers(token),
        )
        return response.json()
    except:
        print("Error while fetching a user...")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            bytes = user.password.encode('utf-8')

            # generating the salt
            salt = bcrypt.gensalt()

            # Hashing the password
            hash = bcrypt.hashpw(bytes, salt)

            if bcrypt.checkpw(user.password.encode('utf-8'), hash):
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
        try:
            bytes = form.password.data.encode('utf-8')
            salt = bcrypt.gensalt()
            hash = bcrypt.hashpw(bytes, salt)
            sql_create_new_user = f"""INSERT INTO user(username, password) VALUES("{form.username.data}", "{hash}");"""
            conn2 = create_connection(database)
            cur = conn2.cursor()
            cur.execute(sql_create_new_user)
            conn2.commit()
        except Error as e:
            print(e)

        # new_userDetail = UserDetail(name="", surname="", date_of_birth="", user_id=1,username='11')
        # db.session.add(new_userDetail)
        # db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)
@app.route('/')
def home():
    return render_template('home.html')

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
            sql_create_new_download = f"""INSERT INTO downloads(user_id, username, database_id,integration_id) VALUES("{current_user.id}","{current_user.username}","{database_id}","{token}");"""
            conn2 = create_connection(database)
            cur = conn2.cursor()
            cur.execute(sql_create_new_download)
            conn2.commit()
            return send_from_directory(app.config["RESULT"], path="result.txt", as_attachment=True)



    return render_template("retrieve_a_block.html")


@app.route("/profile", methods=["POST", "GET"])
@login_required
def profile():
    if request.method == ("POST"):
        name = request.form.get("name")
        surname = request.form.get("surname")
        date_of_birth = request.form.get("date_of_birth")

        sql_search_userdetails=\
            f"""
            SELECT * 
            FROM user_details 
            WHERE  username = "{current_user.username}"
            """
        sql_patch_userDetails = f"""UPDATE user_details
              SET name = "{name}" ,
                  surname = "{surname}" ,
                  date_of_birth = "{date_of_birth}"
              WHERE username = "{current_user.username}"
"""
        sql_create_new_userDetails = \
            f"""INSERT INTO user_details(user_id,username,name,surname,date_of_birth) VALUES("{current_user.id}", "{current_user.username}","{name}","{surname}","{date_of_birth}");"""
        conn2 = create_connection(database)
        cur = conn2.cursor()
        cur.execute(sql_search_userdetails)
        if cur.fetchall():
            cur.execute(sql_patch_userDetails)
            conn2.commit()
        else:
            cur.execute(sql_create_new_userDetails)
            conn2.commit()
    userDetails = UserDetails.query.filter_by(
            user_id=current_user.id).first()
    return render_template("profile.html",current_user=current_user,user_details=userDetails)

@app.route("/downloads")
@login_required
def downloads():
    sql_search_downloads = \
        f"""
        SELECT * 
        FROM downloads 
        WHERE  username = "{current_user.username}"
        """
    conn2 = create_connection(database)
    cur = conn2.cursor()
    downloads = cur.execute(sql_search_downloads).fetchall()
    print(downloads)
    return render_template("downloads.html",downloads=downloads)

array_of_results = []




# readDB(database_id,token)





def get_content_from_db(json_str):
    arr_rows = []
    index = 0
    for i in json_str["results"]:
        index += 1
        arr_rows.append(f" --------------- {index} row ---------------")
        for key , value in i["properties"].items():
            arr_rows.append(f"column: {key}")
            arr_rows.append(value)
    return arr_rows




if __name__ == "__main__":
    app.run(debug=True)
