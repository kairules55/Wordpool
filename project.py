#Imports 
from flask import Flask,render_template, request, redirect, url_for, jsonify
from flask_cors import CORS, cross_origin
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import User, Base, Word, SavedWord
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import random, string, httplib2, json, requests, time

#Api Credentials
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "WordPool"

#Connect to database and create database session

engine = create_engine('sqlite:///wordpooldatabase.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind = engine)
session = DBSession()


#Create Flask App
app = Flask(__name__)
CORS(app, support_credentials=True)

#Login Route
@app.route('/login')
def showLogin():
    if 'username' not in login_session:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', STATE = state)
    else:
        return redirect('/success')

#Login Code For Google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = 'login'
    return output

#Google Disconnect
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v4.0/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v4.0/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v4.0/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = 'login'
    return output

#Disconnect Facebook id
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"         

#Disconnect User based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        return "You have successfully been logged out."
    else:
        return "You were not logged in"


#Success Route
@app.route('/success')
def success():
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    if 'username' in login_session:
        email = login_session['email']
        id = getUserID(email)
        user = session.query(User).filter_by(id = id).one()
        return render_template('success.html',USER = user)
    else:
        return redirect('/login')


#Create User Python Helper
def createUser(login_session):
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    seconds = time.time()
    newUser = User(name = login_session['username'], email=login_session['email'],picture = login_session['picture'], time = seconds)
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

#Get User Info
def getUserInfo(user_id):
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user

#Check User
def getUserID(email):
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None    

#Index Page for public and logged in user
@app.route('/')
@app.route('/home')
def home():
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    rand = random.randrange(1,80)
    print(rand)
    words = session.query(Word).limit(5).offset(rand)
    print(words)
    for word in words:
        print(word)
        print(word.word)

    if 'username' not in login_session:
        return render_template('publicindex.html',WORD = words)
    else:
        print login_session['user_id']
        return render_template('index.html',user_id = login_session['user_id'], WORD = words)    

#Add Word
@app.route('/add/<int:user_id>/<int:word_id>', methods = ['GET', 'POST'])
def addWord(user_id,word_id):
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    if 'username' in login_session and user_id == login_session['user_id']:
        if request.method == 'POST':
            savedWord = SavedWord(user_id = user_id, word_id = word_id)
            session.add(savedWord)
            session.commit()
            return redirect(url_for('displayWord',user_id = user_id))
        else:
            return render_template('addWord.html',user_id = user_id, word_id = word_id)  
    else:
        return "You are not autherized for this action"

#Display Word
@app.route('/display/<int:user_id>/')
def displayWord(user_id):
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    if 'username' in login_session and user_id == login_session['user_id']:
        words = session.query(SavedWord).filter_by(user_id = user_id)
        return render_template('displayWord.html', WORD = words, user_id = user_id)
    else:
        return "You are not autherized to view this page"

#Delete Word
@app.route('/delete/<int:user_id>/<int:word_id>', methods = ['GET', 'POST'])
def deleteWord(user_id,word_id):
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    if 'username' in login_session and user_id == login_sesison['user_id']:
        if request.method == 'POST':
            word = session.query(SavedWord).filter_by(user_id = user_id, word_id = word_id).one()
            session.delete(word)
            session.commit()
            return redirect(url_for('displayWord', user_id = user_id))
        else:
            return render_template('deleteWord.html', user_id = user_id, word_id = word_id)
    else:
        return "You are not autherized for this action"            

#Main Method
if __name__ == '__main__':
    #Need to change this code
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)        