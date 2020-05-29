from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, IntegerField, DateField, TextField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3 as sql
from sqlite3 import Error
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn import tree
import csv
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/sudhanshutarale/Transaction.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Rules():
    out_acc_num = db.Column(db.Integer)
    out_date_key = db.Column(db.Date)
    out_beneficiary_num = db.Column(db.Integer)
    out_currency_amount = db.Column(db.Integer)
    in_count_code = db.Column(db.String(2))
    in_currency_amount = db.Column(db.Integer)
    beneficiary_count_code = db.Column(db.String(2))
    in_acc_num = db.Column(db.Integer)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=80)])


class RuleForm(FlaskForm):
    file = FileField('<h4>Upload transaction details<h4>',
                     validators=[FileRequired()])
    sd1 = DateField('Start Date',
                    validators=[InputRequired()], description="Enter the Start date from when you would like to monitor the transactions")
    ed1 = DateField('End Date', validators=[InputRequired(
    )], description="Enter the End date for monitororing the transactions")
    tsum1 = IntegerField('Minimum Sum (in ₹)', validators=[InputRequired(
    )], description="Enter the minimum total amount in transactions from one account")
    tsin1 = IntegerField(
        'Minimum  value of single transaction (in ₹)', validators=[InputRequired()], description="Enter the minimum total amount in a single transactions from one account")
    minsum2 = IntegerField('Minimum value of sum of risky transaction (in ₹)',
                           validators=[InputRequired()], description="Enter the minimum amount above which transactions are considered to be internatinonal ")
    minout3 = IntegerField(
        'Minimum number of outgoing transactions', validators=[InputRequired()], description="Enter the minimum number of accounts that one account can send money to")
    minben3 = IntegerField(
        'Minimum number of distinct beneficiary accounts', validators=[InputRequired()], description="Enter the minimum number of distinct accounts that one account can send money to")
    tsout3 = IntegerField('Minimum value of sum of outgoing transactions (in ₹)',
                          validators=[InputRequired()], description="Enter the minimum total amount in outgoing transactions")
    minin3 = IntegerField('Minimum number of incoming transactions',
                          validators=[InputRequired()], description="Enter the minimum number of accounts that one account can receive money from")
    mincre3 = IntegerField('Minimum number of distinct credit accounts',
                           validators=[InputRequired()], description="Enter the minimum number of distinct accounts that one account can receive money from")
    tsin3 = IntegerField('Minimum value of sum of incoming transactions (in ₹)',
                         validators=[InputRequired()], description="Enter the minimum total amount in incoming transactions")
    lout4 = IntegerField(
        'Minimum amount for outgoing transactions (in ₹)', validators=[InputRequired()], description="Minimum total amount for outgoing transactions")
    uout4 = IntegerField(
        'Maximum amount for outgoing transactions (in ₹)', validators=[InputRequired()], description="Maximum total amount for outgoing transactions")
    lin4 = IntegerField(
        'Minimum amount for incoming transactions (in ₹)', validators=[InputRequired()], description="Minimum total amount for incoming transactions")
    uin4 = IntegerField(
        'Maximum amount for incoming transactions (in ₹)', validators=[InputRequired()], description="Maximum total amount for incoming transactions")
    min_threshold = IntegerField(
        'Enter the threshold value for Risk Score (Maximum value is 4):', validators=[InputRequired()], description="Only accounts with risk score more than the entered number will be shown in the output")


def create_connection(db_file):

    conn = None
    try:
        conn = sql.connect(db_file, isolation_level=None,
                           detect_types=sql.PARSE_COLNAMES)
    except Error as e:
        print(e)

    return conn


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/sst')
@login_required
def sst():
    return render_template('sst.html', name=current_user.username)


@app.route('/srs')
@login_required
def srs():
    return render_template('srs.html', name=current_user.username)


@app.route('/aml')
@login_required
def aml():
    return render_template('aml.html', name=current_user.username)


@app.route('/rules', methods=['GET', 'POST'])
@login_required
def rules():
    form = RuleForm()
    return render_template('rules.html', name=current_user.username, form=form)


@app.route('/output', methods=['GET', 'POST'])
@login_required
def output():
    form = RuleForm()
    if request.method == 'POST':
        file = request.files["file"]
        file.filename = "TwoWayTransactions.csv"
        file.save(file.filename)
        conn = create_connection(r"/Users/sudhanshutarale/Transaction.db")
        cur = conn.cursor()
        read_transactions = pd.read_csv(
            r'/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/TwoWayTransactions.csv')
        cur.execute("DROP TABLE IF EXISTS TwoWayTransactions")
        cur.execute("CREATE TABLE 'TwoWayTransactions' ( `out_acc_num` NUMERIC, `out_date_key` TEXT, `out_beneficiary_num` NUMERIC, `out_currency_amount` NUMERIC, `in_count_code` TEXT, `in_currency_amount` NUMERIC, `beneficiary_count_code` TEXT, `in_acc_num` NUMERIC )")
        read_transactions.to_sql('TwoWayTransactions',
                                 conn, if_exists='replace', index=False)
        sd1 = request.form.get("sd1")
        ed1 = request.form.get("ed1")
        tsum1 = request.form.get("tsum1")
        tsin1 = request.form.get("tsin1")
        sd2 = request.form.get("sd2")
        ed2 = request.form.get("ed2")
        minsum2 = request.form.get("minsum2")
        sd3 = request.form.get("sd3")
        ed3 = request.form.get("ed3")
        minout3 = request.form.get("minout3")
        minben3 = request.form.get("minben3")
        tsout3 = request.form.get("tsout3")
        minin3 = request.form.get("minin3")
        mincre3 = request.form.get("mincre3")
        tsin3 = request.form.get("tsin3")
        sd4 = request.form.get("sd4")
        ed4 = request.form.get("ed4")
        lout4 = request.form.get("lout4")
        uout4 = request.form.get("uout4")
        lin4 = request.form.get("lin4")
        uin4 = request.form.get("uin4")
        min_threshold = (int)(request.form.get("min_threshold"))
        # results=request.form
        with sql.connect("/Users/sudhanshutarale/Transaction.db") as conn:
            threshold_amount_rule(conn, sd1, ed1, tsum1, tsin1)
            excessive_funds_rule(conn, minsum2, sd1, ed1)
            burst_in_originator_rule(
                conn, minout3, minben3, tsout3, minin3, mincre3, tsin3, sd1, ed1)
            structuring_activity_rule(conn, lout4, uout4, lin4, uin4, sd1, ed1)
            score()
            suspicious_accounts(conn)
            suspicious_transactions(conn)
            final_score(conn, min_threshold)
        filename = datetime.now()
        date_time = str(filename.strftime("%d-%m-%Y_%H:%M:%S"))
        path = "///Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output:" + date_time+".csv"
        df = pd.read_csv(path)
        df.index = df.index+1
        return render_template('output.html', results=df)


@app.route('/batch')
@login_required
def batch():
    return render_template('batch.html', name=current_user.username)


def threshold_amount_rule(conn, sd1, ed1, tsum1, tsin1):

    cur = conn.cursor()
    create_view_date_interval(conn, sd1, ed1)
    cur.execute("DROP TABLE IF EXISTS sum_rule1")
    cur.execute(
        "CREATE TABLE sum_rule1 ( `out_acc_num` INTEGER, `sum_transactionamount` INTEGER)")
    cur.execute("INSERT INTO sum_rule1 SELECT date_interval.`out_acc_num`, sum(date_interval.`out_currency_amount`) as      sum_transactionamount from date_interval group by date_interval.`out_acc_num`")
    cur.execute("DROP TABLE IF EXISTS rule_1a")
    cur.execute(
        "CREATE TABLE rule_1a ( `out_acc_num` INTEGER, `sum_transactionamount` INTEGER)")
    cur.execute("INSERT INTO rule_1a (`out_acc_num`, `sum_transactionamount`) SELECT sum_rule1.`out_acc_num`, sum_rule1.`sum_transactionamount` FROM sum_rule1 WHERE sum_rule1.`sum_transactionamount` > ?", (tsum1,))
    cur.execute("DROP TABLE IF EXISTS Testrule1a")
    cur.execute("CREATE TABLE Testrule1a ( `out_acc_num` INTEGER, `sum_transactionamount` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule1a SELECT rule_1a.out_acc_num, rule_1a.sum_transactionamount, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international from rule_1a left join DetailsofAccs on rule_1a.out_acc_num = DetailsofAccs.out_acc_num")
    db_df = pd.read_sql_query("SELECT * FROM Testrule1a", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule1atest.csv', index=False)
    cur.execute("DROP TABLE IF EXISTS rule_1b")
    cur.execute(
        "CREATE TABLE rule_1b ( `out_acc_num` INTEGER, `out_currency_amount` INTEGER)")
    cur.execute("INSERT INTO rule_1b (`out_acc_num`, `out_currency_amount`) SELECT date_interval.`out_acc_num`, date_interval.`out_currency_amount` FROM date_interval WHERE `out_currency_amount`> ?", (tsin1,))
    cur.execute("DROP TABLE IF EXISTS Testrule1b")
    cur.execute("CREATE TABLE Testrule1b ( `out_acc_num` INTEGER, `out_currency_amount` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule1b SELECT rule_1b.out_acc_num, rule_1b.out_currency_amount, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international from rule_1b left join DetailsofAccs on rule_1b.out_acc_num = DetailsofAccs.out_acc_num")
    db_df = pd.read_sql_query("SELECT * FROM Testrule1b", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule1btest.csv', index=False)

    # MLrule1a
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule1atrain.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['net_worth', 'credit_score', 'sum_transactionamount', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule1atest.csv")
    x = ['sum_transactionamount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule1a.csv')

    # MLrule1b
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule1btrain.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['out_currency_amount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule1btest.csv")
    x = ['out_currency_amount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule1b.csv')


def excessive_funds_rule(conn, minsum2, sd1, ed1):

    cur = conn.cursor()
    create_view_date_interval(conn, sd1, ed1)
    cur.execute("DROP VIEW IF EXISTS risky_out")
    cur.execute(
        "CREATE VIEW risky_out as SELECT * FROM date_interval WHERE date_interval.beneficiary_count_code != 'IN'")
    cur.execute("DROP VIEW IF EXISTS risky_in")
    cur.execute(
        "CREATE VIEW risky_in as SELECT * FROM date_interval WHERE date_interval.in_count_code != 'IN'")
    cur.execute("DROP VIEW IF EXISTS risky_sum_out")
    cur.execute("CREATE VIEW risky_sum_out as select risky_out.out_acc_num, sum( risky_out.out_currency_amount) as transactionamount FROM risky_out GROUP BY risky_out.out_acc_num")
    cur.execute("DROP VIEW IF EXISTS risky_sum_in")
    cur.execute("CREATE VIEW risky_sum_in as select risky_in.out_acc_num, sum( risky_in.in_currency_amount) as transactionamount FROM risky_in GROUP BY risky_in.out_acc_num")
    cur.execute("DROP VIEW IF EXISTS risky_all")
    cur.execute(
        "CREATE VIEW risky_all as select * from risky_sum_out union select * from risky_sum_in")
    cur.execute("DROP TABLE IF EXISTS sumofrisky")
    cur.execute(
        "CREATE TABLE sumofrisky ( `out_acc_num` INTEGER, `totalriskyamount` INTEGER)")
    cur.execute("INSERT INTO sumofrisky SELECT risky_all.`out_acc_num`, sum( risky_all.`transactionamount`) as totalriskyamount FROM risky_all GROUP BY risky_all.`out_acc_num`")
    cur.execute("DROP TABLE IF EXISTS rule2")
    cur.execute(
        "CREATE TABLE rule2 ( `out_acc_num` INTEGER, `totalriskyamount` INTEGER)")
    cur.execute(
        "INSERT INTO rule2 SELECT * FROM sumofrisky WHERE sumofrisky.totalriskyamount > ?", (minsum2,))
    cur.execute("DROP TABLE IF EXISTS Testrule2")
    cur.execute("CREATE TABLE Testrule2 ( `out_acc_num` INTEGER, `totalriskyamount` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule2 SELECT rule2.out_acc_num, rule2.totalriskyamount, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international from rule2 left join DetailsofAccs on rule2.out_acc_num=DetailsofAccs.out_acc_num")
    db_df = pd.read_sql_query("SELECT * FROM Testrule2", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule2test.csv', index=False)

    # MLrule2
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule2train.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['totalriskyamount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule2test.csv")
    x = ['totalriskyamount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule2.csv')


def burst_in_originator_rule(conn, minout3, minben3, tsout3, minin3, mincre3, tsin3, sd1, ed1):

    cur = conn.cursor()

    cur.execute("DROP VIEW IF EXISTS outburst1")
    cur.execute("CREATE VIEW outburst1 as SELECT date_interval.out_acc_num, COUNT( date_interval.out_beneficiary_num) as no_of_out, SUM( date_interval.out_currency_amount) as sumout FROM date_interval GROUP BY date_interval.out_acc_num")

    cur.execute("DROP VIEW IF EXISTS outburst2")
    cur.execute("CREATE VIEW outburst2 as SELECT date_interval.out_acc_num, COUNT( DISTINCT date_interval.out_beneficiary_num) as distinct_no_of_out FROM date_interval GROUP BY date_interval.out_acc_num")

    cur.execute("DROP TABLE IF EXISTS outburst")
    cur.execute(
        "CREATE TABLE outburst ( out_acc_num INTEGER, no_of_out INTEGER,sumout INTEGER, distinct_no_of_out INTEGER) ")
    cur.execute("INSERT INTO outburst SELECT outburst1.out_acc_num, outburst1.no_of_out, outburst1.sumout, outburst2.distinct_no_of_out FROM outburst1 LEFT JOIN outburst2 ON outburst1.out_acc_num = outburst2.out_acc_num")

    cur.execute("DROP TABLE IF EXISTS rule3a")
    cur.execute(
        "CREATE TABLE rule3a ( out_acc_num INTEGER, no_of_out INTEGER,sumout INTEGER, distinct_no_of_out INTEGER )")
    cur.execute("INSERT INTO rule3a SELECT * FROM outburst WHERE outburst.no_of_out > ? AND outburst.sumout > ? AND outburst.distinct_no_of_out > ?",
                (minout3, tsout3, minben3,))

    cur.execute("DROP TABLE IF EXISTS Testrule3a")
    cur.execute("CREATE TABLE Testrule3a ( `out_acc_num` INTEGER, `no_of_out` INTEGER, `distinct_no_of_out` INTEGER, `sumout` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule3a SELECT rule3a.out_acc_num, rule3a.no_of_out, rule3a.distinct_no_of_out, rule3a.sumout, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international FROM rule3a LEFT JOIN DetailsofAccs ON rule3a.out_acc_num = DetailsofAccs.out_acc_num")

    db_df = pd.read_sql_query("SELECT * FROM Testrule3a", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule3atest.csv', index=False)

    cur.execute("DROP VIEW IF EXISTS inburst1")
    cur.execute("CREATE VIEW inburst1 as SELECT date_interval.out_acc_num, COUNT( date_interval.in_acc_num) as no_of_in, SUM( date_interval.in_currency_amount) as sumin FROM date_interval GROUP BY date_interval.out_acc_num")

    cur.execute("DROP VIEW IF EXISTS inburst2")
    cur.execute("CREATE VIEW inburst2 as SELECT date_interval.out_acc_num, COUNT( DISTINCT date_interval.in_acc_num) as distinct_no_of_in FROM date_interval GROUP BY date_interval.out_acc_num")

    cur.execute("DROP TABLE IF EXISTS inburst")
    cur.execute(
        "CREATE TABLE inburst ( out_acc_num INTEGER, no_of_in INTEGER,sumin INTEGER, distinct_no_of_in INTEGER) ")
    cur.execute("INSERT INTO inburst SELECT inburst1.out_acc_num, inburst1.no_of_in, inburst1.sumin, inburst2.distinct_no_of_in FROM inburst1 LEFT JOIN inburst2 ON inburst1.out_acc_num = inburst2.out_acc_num")

    cur.execute("DROP TABLE IF EXISTS rule3b")
    cur.execute(
        "CREATE TABLE rule3b ( out_acc_num INTEGER, no_of_in INTEGER,sumin INTEGER, distinct_no_of_in INTEGER )")
    cur.execute("INSERT INTO rule3b SELECT * FROM inburst WHERE inburst.no_of_in > ? AND inburst.sumin > ? AND inburst.distinct_no_of_in > ?",
                (minin3, tsin3, mincre3,))

    cur.execute("DROP TABLE IF EXISTS Testrule3b")
    cur.execute("CREATE TABLE Testrule3b ( `out_acc_num` INTEGER, `no_of_in` INTEGER, `distinct_no_of_in` INTEGER, `sumin` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule3b SELECT rule3b.out_acc_num, rule3b.no_of_in, rule3b.distinct_no_of_in, rule3b.sumin, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international FROM rule3b LEFT JOIN DetailsofAccs ON rule3b.out_acc_num = DetailsofAccs.out_acc_num")

    db_df = pd.read_sql_query("SELECT * FROM Testrule3b", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule3btest.csv', index=False)

    # MLrule3a
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule3atrain.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['no_of_out', 'distinct_no_of_out', 'sumout', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule3atest.csv")
    x = ['no_of_out', 'distinct_no_of_out', 'sumout', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule3a.csv')

    # MLrule3b
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule3btrain.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['no_of_in', 'distinct_no_of_in', 'sumin', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule3btest.csv")
    x = ['no_of_in', 'distinct_no_of_in', 'sumin', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule3b.csv')


def structuring_activity_rule(conn, lout4, uout4, lin4, uin4, sd1, ed1):

    cur = conn.cursor()
    # print("STRUCTURING ACTIVITY RULE!")
    create_view_date_interval(conn, sd1, ed1)
    cur.execute("DROP TABLE IF EXISTS rule4a")
    cur.execute(
        "CREATE TABLE rule4a ( out_acc_num INTEGER, out_currency_amount INTEGER) ")
    cur.execute("INSERT INTO rule4a SELECT date_interval.out_acc_num, date_interval.out_currency_amount FROM date_interval WHERE date_interval.out_currency_amount > ? AND date_interval.out_currency_amount < ?", (lout4, uout4,))
    cur.execute("DROP TABLE IF EXISTS Testrule4a")
    cur.execute("CREATE TABLE Testrule4a ( `out_acc_num` INTEGER, `out_currency_amount` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule4a SELECT rule4a.out_acc_num, rule4a.out_currency_amount, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international from rule4a left join DetailsofAccs on rule4a.out_acc_num = DetailsofAccs.out_acc_num")
    db_df = pd.read_sql_query("SELECT * FROM Testrule4a", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule4atest.csv', index=False)
    cur.execute("DROP TABLE IF EXISTS rule4b")
    cur.execute(
        "CREATE TABLE rule4b ( out_acc_num INTEGER, in_currency_amount INTEGER) ")
    cur.execute("INSERT INTO rule4b SELECT date_interval.out_acc_num, date_interval.in_currency_amount FROM date_interval WHERE date_interval.in_currency_amount > ? AND date_interval.in_currency_amount < ?", (lin4, uin4,))
    cur.execute("DROP TABLE IF EXISTS Testrule4b")
    cur.execute("CREATE TABLE Testrule4b ( `out_acc_num` INTEGER, `in_currency_amount` INTEGER, `net_worth` REAL, `credit_score` REAL, `ratio_cash_deposits` REAL, `ratio_cash_withdrawals` REAL, `ratio_incoming_international` REAL, `ratio_outgoing_international` REAL )")
    cur.execute("INSERT INTO Testrule4b SELECT rule4b.out_acc_num, rule4b.in_currency_amount, DetailsofAccs.net_worth, DetailsofAccs.credit_score, DetailsofAccs.ratio_cash_deposits, DetailsofAccs.ratio_cash_withdrawals, DetailsofAccs.ratio_incoming_international, DetailsofAccs.ratio_outgoing_international from rule4b left join DetailsofAccs on rule4b.out_acc_num = DetailsofAccs.out_acc_num")
    db_df = pd.read_sql_query("SELECT * FROM Testrule4b", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule4btest.csv', index=False)

    # MLrule4a
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule4btrain.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['in_currency_amount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule4btest.csv")
    x = ['in_currency_amount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule4a.csv')

    # MLrule4b
    df = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/train/Rule4btrain.csv")
    model = tree.DecisionTreeClassifier(criterion='gini')
    predictor_var = ['in_currency_amount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
                     'ratio_incoming_international', 'ratio_outgoing_international']
    X = df[predictor_var]
    outcome_var = ['label']
    y = df[outcome_var]
    model.fit(X, y)
    df1 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/csv/test/Rule4btest.csv")
    x = ['in_currency_amount', 'net_worth', 'credit_score', 'ratio_cash_deposits', 'ratio_cash_withdrawals',
         'ratio_incoming_international', 'ratio_outgoing_international']
    x_test = df1[x]
    predicted = model.predict(x_test)
    submission = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/sample.csv")
    submission['label'] = predicted
    submission['out_acc_num'] = df1['out_acc_num']
    submission['label'].replace(0, 'No', inplace=True)
    submission['label'].replace(1, 'Yes', inplace=True)
    pd.DataFrame(submission, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule4b.csv')


def create_view_date_interval(conn, sd1, ed1):

    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS rows_startdate")
    cur.execute("CREATE TABLE rows_startdate ( `out_acc_num` NUMERIC, `out_date_key` TEXT, `out_beneficiary_num` NUMERIC, `out_currency_amount` NUMERIC, `in_count_code` TEXT, `in_currency_amount` NUMERIC, `beneficiary_count_code` TEXT, `in_acc_num` NUMERIC )")
    cur.execute(
        "INSERT INTO rows_startdate SELECT * FROM TwoWayTransactions WHERE `out_date_key`> ?", (sd1,))
    cur.execute("DROP TABLE IF EXISTS rows_enddate")
    cur.execute("CREATE TABLE rows_enddate ( `out_acc_num` NUMERIC, `out_date_key` TEXT, `out_beneficiary_num` NUMERIC, `out_currency_amount` NUMERIC, `in_count_code` TEXT, `in_currency_amount` NUMERIC, `beneficiary_count_code` TEXT, `in_acc_num` NUMERIC )")
    cur.execute(
        "INSERT INTO rows_enddate SELECT * FROM TwoWayTransactions WHERE `out_date_key`< ?", (ed1,))
    cur.execute("DROP TABLE IF EXISTS date_interval")
    cur.execute("CREATE TABLE date_interval ( `out_acc_num` NUMERIC, `out_date_key` TEXT, `out_beneficiary_num` NUMERIC, `out_currency_amount` NUMERIC, `in_count_code` TEXT, `in_currency_amount` NUMERIC, `beneficiary_count_code` TEXT, `in_acc_num` NUMERIC )")
    cur.execute(
        "INSERT INTO date_interval SELECT * FROM rows_startdate INTERSECT SELECT * FROM rows_enddate")


def combine_all_rules(conn):

    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS supicious_accounts")
    cur.execute("CREATE TABLE supicious_accounts (Account_No INTEGER)")
    cur.execute("INSERT INTO supicious_accounts SELECT DISTINCT( rule_1a.out_acc_num) FROM rule_1a union SELECT DISTINCT( rule_1b.out_acc_num) FROM rule_1b union SELECT DISTINCT( rule2.out_acc_num) FROM rule2 union SELECT DISTINCT( rule3a.out_acc_num) FROM rule3a union SELECT DISTINCT( rule3b.out_acc_num) FROM rule3b union SELECT DISTINCT( rule4a.out_acc_num) FROM rule4a union SELECT DISTINCT( rule4b.out_acc_num) FROM rule4b")


def score():
    df1a = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule1a.csv")
    df1a.rename({"Unnamed: 0": "a"}, axis="columns", inplace=True)
    df1a.drop(["a"], axis=1, inplace=True)
    rslt_df1a = df1a[df1a['label'] == 'Yes']

    df2 = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule2.csv")
    df2.rename({"Unnamed: 0": "b"}, axis="columns", inplace=True)
    df2.drop(["b"], axis=1, inplace=True)
    rslt_df2 = df2[df2['label'] == 'Yes']
    rslt_df1a = rslt_df1a.append(rslt_df2, ignore_index=True)

    df3a = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule3a.csv")
    df3a.rename({"Unnamed: 0": "c"}, axis="columns", inplace=True)
    df3a.drop(["c"], axis=1, inplace=True)
    rslt_df3a = df3a[df3a['label'] == 'Yes']

    rslt_df1a = rslt_df1a.append(rslt_df3a, ignore_index=True)

    df3b = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule3b.csv")
    df3b.rename({"Unnamed: 0": "d"}, axis="columns", inplace=True)
    df3b.drop(["d"], axis=1, inplace=True)
    rslt_df3b = df3b[df3b['label'] == 'Yes']

    rslt_df1a = rslt_df1a.append(rslt_df3b, ignore_index=True)

    pd.DataFrame(rslt_df1a, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/scoring/Outscore.csv')

    df1b = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule1b.csv")
    df1b.rename({"Unnamed: 0": "a"}, axis="columns", inplace=True)
    df1b.drop(["a"], axis=1, inplace=True)
    rslt_df1b = df1b[df1b['label'] == 'Yes']

    df4a = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule4a.csv")
    df4a.rename({"Unnamed: 0": "c"}, axis="columns", inplace=True)
    df4a.drop(["c"], axis=1, inplace=True)
    rslt_df4a = df4a[df4a['label'] == 'Yes']

    rslt_df1b = rslt_df1b.append(rslt_df4a, ignore_index=True)

    df4b = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule4b.csv")
    df4b.rename({"Unnamed: 0": "d"}, axis="columns", inplace=True)
    df4b.drop(["d"], axis=1, inplace=True)
    rslt_df4b = df4b[df4b['label'] == 'Yes']
    rslt_df1b = rslt_df1b.append(rslt_df4b, ignore_index=True)
    pd.DataFrame(rslt_df1b, columns=['out_acc_num', 'label']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/scoring/Outscore2.csv')


def suspicious_accounts(conn):

    cur = conn.cursor()
    read_suspicious_accounts = pd.read_csv(
        r'/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/scoring/Outscore.csv')
    read_suspicious_accounts.rename(
        {"Unnamed: 0": "a"}, axis="columns", inplace=True)
    read_suspicious_accounts.drop(["a"], axis=1, inplace=True)
    cur.execute("DROP TABLE IF EXISTS Outscore")
    cur.execute(
        "CREATE TABLE Outscore ( `out_acc_num` INTEGER, `suspicious_score` INTEGER )")
    read_suspicious_accounts.to_sql(
        'Outscore', conn, if_exists='replace', index=False)
    df1a = pd.read_csv(
        "/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output/OutputRule1a.csv")
    cur.execute("DROP TABLE IF EXISTS CountA")
    cur.execute(
        "CREATE TABLE CountA ( `out_acc_num` INTEGER, `suspicious_score` INTEGER )")
    cur.execute("INSERT INTO CountA select Outscore.out_acc_num, count( Outscore.label) as suspicious_score from Outscore group by Outscore.out_acc_num")


def suspicious_transactions(conn):

    cur = conn.cursor()
    read_suspicious_transactions = pd.read_csv(
        r'/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/scoring/Outscore2.csv')
    read_suspicious_transactions.rename(
        {"Unnamed: 0": "a"}, axis="columns", inplace=True)
    read_suspicious_transactions.drop(["a"], axis=1, inplace=True)
    cur.execute("DROP TABLE IF EXISTS Outscore2")
    cur.execute(
        "CREATE TABLE Outscore2 ( `out_acc_num` INTEGER, `no_of_suspicious_transactions` INTEGER )")
    read_suspicious_transactions.to_sql(
        'Outscore2', conn, if_exists='replace', index=False)
    cur.execute("DROP TABLE IF EXISTS CountB")
    cur.execute(
        "CREATE TABLE CountB ( `out_acc_num` INTEGER, `no_of_suspicious_transactions` INTEGER )")
    cur.execute("INSERT INTO CountB select Outscore2.out_acc_num, count( Outscore2.label) as no_of_susoicious_transactions from Outscore2 group by Outscore2.out_acc_num")


def final_score(conn, min_threshold):

    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS FinalScore")
    cur.execute("CREATE TABLE FinalScore ( `out_acc_num` INTEGER, `suspicious_score` INTEGER, `no_of_suspicious_transactions` INTEGER)")
    cur.execute("INSERT INTO FinalScore select CountA.out_acc_num, CountA.suspicious_score, CountB.no_of_suspicious_transactions from CountA Left join CountB ON CountA.out_acc_num = CountB.out_acc_num UNION select CountB.out_acc_num, CountA.suspicious_score, CountB.no_of_suspicious_transactions from CountB left join CountA ON CountB.out_acc_num = CountA.out_acc_num")
    cur.execute(
        "UPDATE FinalScore SET no_of_suspicious_transactions = '0' WHERE no_of_suspicious_transactions IS null")
    cur.execute(
        "UPDATE FinalScore SET suspicious_score = '0' WHERE suspicious_score IS null")
    db_df = pd.read_sql_query("SELECT * FROM FinalScore", conn)
    db_df.to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/scoring/FinalScore.csv', index=False)
    db_df['red_flags'] = db_df['suspicious_score'] + \
        db_df['no_of_suspicious_transactions']
    pd.DataFrame(db_df, columns=['out_acc_num', 'suspicious_score', 'no_of_suspicious_transactions', 'red_flags']).to_csv(
        '/Users/sudhanshutarale/Desktop/git_fyp/final-year-project/scoring/FinalScore.csv')
    avg = db_df['no_of_suspicious_transactions'].mean(axis=0)
    avg = round(avg, 0)
    db_df2 = db_df[(db_df['suspicious_score'] >= min_threshold)
                   & (db_df['no_of_suspicious_transactions'] >= avg)]
    db_df2 = db_df2.rename(columns={'out_acc_num': 'Account Number', 'suspicious_score': 'Risk Score',
                                    'no_of_suspicious_transactions': 'No. of Suspicious Transactions', 'red_flags': 'No. of Red Flags'})
    filename = datetime.now()
    date_time = str(filename.strftime("%d-%m-%Y_%H:%M:%S"))
    path = "///Users/sudhanshutarale/Desktop/git_fyp/final-year-project/output:" + date_time+".csv"
    pd.DataFrame(db_df2, columns=['Account Number', 'Risk Score',
                                  'No. of Suspicious Transactions', 'No. of Red Flags']).to_csv(path)


if __name__ == '__main__':
    app.run(debug=True)
