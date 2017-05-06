import os
from flask import Flask, g, session, redirect, request, url_for, jsonify, render_template
from requests_oauthlib import OAuth2Session
import requests
from env import *


API_BASE_URL = os.environ.get('API_BASE_URL', 'https://discordapp.com/api')
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

app = Flask(__name__)
app.config['SECRET_KEY'] = OAUTH2_CLIENT_SECRET




def token_updater(token):
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    redirect_url = url_for('authorized', _external=True)
    if 'http://' in redirect_url:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    return OAuth2Session(
        client_id=OAUTH2_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=redirect_url,
        auto_refresh_kwargs={
            'client_id': OAUTH2_CLIENT_ID,
            'client_secret': OAUTH2_CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater)

@app.before_request
def before_request():
    if 'oauth2_token' in session:
        discord = make_session(token=session.get('oauth2_token'))
        req = discord.get(API_BASE_URL + '/users/@me')
        if req.status_code == 200:
            g.user = req.json()
        else:
            session.pop('oauth2_token', None)
            session['redirect'] = request.url_rule.endpoint
            redirect(url_for('login'))
    else:
        g.user = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/guild')
def guild():
    if 'oauth2_token' not in session:
        session['redirect'] = 'guild'
        return redirect(url_for('login'))

    return render_template('guild.html')


@app.route('/login')
def login():
    if 'oauth2_token' in session:
        redirect_url = url_for(session.pop('redirect', 'index'))
        return redirect(redirect_url)
    scope = request.args.get('scope', 'identify')
    discord = make_session(scope=scope.split(' '))
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)


@app.route('/logout')
def logout():
    session.pop('oauth2_token', None)
    return redirect(url_for('index'))


@app.route('/authorized')
def authorized():
    if request.values.get('error'):
        return request.values['error']
    discord = make_session(state=session.get('oauth2_state'))
    token = discord.fetch_token(
        TOKEN_URL,
        client_secret=OAUTH2_CLIENT_SECRET,
        authorization_response=request.url)
    session['oauth2_token'] = token
    redirect_url = url_for(session.pop('redirect', 'index'))
    return redirect(redirect_url)


@app.route('/me')
def me():
    headers = {'User-Agent': 'CrystBot (http://cryst.gg/, 0.0.1)'}
    bot_headers = headers.copy()
    bot_headers['Authorization'] = OAUTH2_BOT_TOKEN
    discord = make_session(token=session.get('oauth2_token'))
    user = discord.get(API_BASE_URL + '/users/@me', headers=headers).json()
    # guilds = discord.get(API_BASE_URL + '/users/@me/guilds', headers=headers).json()
    # connections = discord.get(API_BASE_URL + '/users/@me/connections', headers=headers).json()
    # guild = requests.get(API_BASE_URL + '/guilds/253508508912189450', headers=bot_headers).json()
    # member = requests.get(API_BASE_URL + '/guilds/253508508912189450/members/{}'.format(user['id']),
    #                       headers=bot_headers).json()
    return jsonify(user)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
