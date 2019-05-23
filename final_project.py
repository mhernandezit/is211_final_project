import requests
import os
from requests.auth import HTTPDigestAuth
import json
import pandas as pd
from flask import g, session, flash, request, redirect, render_template, Flask
import sqlite3 as lite
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, PasswordField

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'cross site forgery prevention key'

def get_db():
    if 'db' not in g:
        g.db = lite.connect('vuln.db')
        g.db.row_factory = lite.Row
    return g.db

def get_vendors():
    """ Runs an API call to the CVE online database to get a list of the 
    active vendors """

    url = "https://cve.circl.lu/api/browse"

    myResponse = requests.get(url, verify=True)
    engine = get_db()
    if(myResponse.ok):
        
        vendors_df = pd.read_json(myResponse.content)
        vendor_df = vendors_df.drop('product', axis=1)
        vendor_df.rename(columns={'vendor':'name'}, inplace=True)
        vendor_data = df_dedupe(vendor_df, 'vendors', engine, dup_cols=['name'])
        vendor_data.to_sql('vendors', engine, if_exists='append', index=False)
        return vendor_data.to_dict()
    else:
        myResponse.raise_for_status()

def get_devices(vendor):
    """ Runs an API call to the CVE online database to get the active models
    for a vendor """
    engine = get_db()
    url = "https://cve.circl.lu/api/browse/{}".format(vendor)

    myResponse = requests.get(url, verify=True)
    sql_args = """ select vendorid from vendors where name == ? """
    # vendor_id = engine.execute(sql_args, (vendor,)).fetchone()
    vendor_id = pd.read_sql_query(sql_args, engine, params=[vendor])

    if not vendor_id.empty:
        if(myResponse.ok):
            device_df = pd.read_json(myResponse.content)
            device_df.rename(columns={'vendor':'name'}, inplace=True)
            device_data = df_dedupe(device_df, 'devices', engine, dup_cols=['product'])
            device_data['vendorid'] = vendor_id.iat[0,0]
            device_data.drop('name', axis=1, inplace=True)
            device_data.to_sql('devices', engine, if_exists='append', index=False)
            return device_data.to_dict()
        else:
            myResponse.raise_for_status()

def df_dedupe(df, tablename, engine, dup_cols=[]):
    """
    Remove rows from a dataframe that already exist in a database
    Required:
        df : dataframe to remove duplicate rows from
        engine: SQLAlchemy engine object
        tablename: tablename to check duplicates in
        dup_cols: list or tuple of column names to check for duplicate row values
    Returns
        Unique list of values from dataframe compared to database table
    """
    args = 'SELECT %s FROM %s' %(', '.join(['"{0}"'.format(col) for col in dup_cols]), tablename)
    df = pd.merge(df, pd.read_sql(args, engine), how='left', on=dup_cols, indicator=True)
    df = df[df['_merge'] == 'left_only']
    df.drop(['_merge'], axis=1, inplace=True)
    return df


def build_refs(dataframe):
    engine = get_db()
    refcolumns = ['id','references']
    ref = dataframe.loc[:, refcolumns]
    ref = list_to_dataframe(dataframe, refcolumns)
    ref.rename(columns={'id':'cve_id', 'references': 'url'}, inplace=True)
    ref_data = df_dedupe(ref, 'refs', engine, dup_cols=['cve_id'])
    ref_data.to_sql('refs', engine, if_exists='append', index=False)
    return ref_data


def get_vulnerability(vendor, device):
    """ Retrieves the active vulnerabilities for a particular device """
    url = "https://cve.circl.lu/api/search/{}/{}".format(vendor, device)
    engine = get_db()

    myResponse = requests.get(url, verify=True)
    sql_args = """ select deviceid from devices where product == ? """
    device_id = engine.execute(sql_args, (device,)).fetchone()

    if(myResponse.ok):
        vulncolumns = ['id', 'cvss']
        df = pd.read_json(myResponse.content)
        vuln = df.loc[:, vulncolumns]
        vuln['device_id'] = device_id[0]
        vuln.rename(columns={'id':'cve_id'}, inplace=True)
        vuln_data = df_dedupe(vuln, 'vuln', engine, dup_cols=['cve_id'])
        vuln_data.to_sql('vuln', engine, if_exists='append', index=False)
        build_refs(df)
        return vuln_data

    else:
        myResponse.raise_for_status()

def list_to_dataframe(dataframe, columns):
    result = dataframe.loc[:, columns]
    refs = result.references.apply(pd.Series)
    merged = refs.merge(result, left_index = True, right_index = True)
    pre_melt = merged.drop(["references"], axis = 1)
    melted = pre_melt.melt(id_vars = ['id'], value_name = "references")
    pre_na = melted.drop(['variable'], axis=1)
    final = pre_na.dropna()

    return final


@app.route('/',  methods=['GET'])
def home_pg():
    if 'logged_in' not in session:
        return redirect('/login')
    else:
        data = get_vendors()
        return render_template('dash/dashboard.html', vendor_data=data)

@app.route('/register',  methods=['GET', 'POST'])
def register():
    if 'logged_in' in session:
        return redirect('/dashboard')

    elif request.method == 'POST':

        password = request.form['password']
        username = request.form['username']

        database = get_db()

        if database.execute('SELECT username from users where username == ?', (username,)).fetchone():
            flash('Username exists, please use a different username')

        database.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password)))
        database.commit()
        flash('User added successfully')
        return redirect('/login')

    elif request.method == 'GET':
        return render_template('auth/register.html')

@app.route('/login',  methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect('/')

    elif request.method == 'POST':
        error = None
        username = request.form['username']
        password = request.form['password']
        
        database = get_db()
        user = database.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect/Invalid email.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        else:
            session.clear()
            session['logged_in'] = True
            session['user_id'] = user[0]
            return redirect('/device/add')

        error = 'logged in'
        return render_template('/auth/login.html', error=error)

    if request.method == 'GET':
        return render_template('/auth/login.html')

@app.route('/device/add', methods=['GET', 'POST'])
def add_device():
    if request.method == 'GET':
        return render_template('/dash/add_device.html')
    elif request.method == 'POST':
        vendor = request.form['vendor']
        product = request.form['product']

        database = get_db()
        devicesql = 'select deviceid from devices where product == ?'
        result = database.execute(devicesql, (vendor,)).fetchone()
        deviceid = result[0]
        insert_sql = 'insert into inventory select userid, deviceid where userid == ? and deviceid == ?'
        if deviceid:
            database.execute(insert_sql, (deviceid, session['user_id']))
            get_vulnerability(vendor, product)
        else:
            get_devices(vendor)
            deviceid = database.execute(deviceid, (vendor,)).fetchone()
            database.execute(insert_sql, (deviceid, session['user_id']))
            get_vulnerability(vendor, product)
        return render_template('/dash/add_device.html')

@app.route('/vulnerability/view', methods=['GET'])
def view_vulnerability():
    database = get_db()
    vuln_list = []
    vuln_sql = """
        SELECT  devices.product, 
                vendors.name, 
                cveid, 
                cvss, 
                ref.id 
        FROM    inventory i 
                inner join vuln v 
                        ON i.deviceid = v.deviceid 
                left join vendors ven 
                        ON i.deviceid = ven.deviceid 
        WHERE   i.userid == ?;  """
    vuln_list = database.execute(vuln_sql, (session['user_id'],))
    return render_template('/dash/dashboard.html', vuln_list=vuln_list)

@app.route('/vendor/view')
def view_vendor():
    database = get_db()
    vendor_list = []
    vendor_sql = """
    select vendors.name,
    devices.product
    from devices join vendors on devices.vendorid = vendors.vendorid
    """
    return render_template('/dash/vendor.html', vendor_list=vendor_list)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect('/login')

if __name__ == "__main__":
    app.run(debug=1)