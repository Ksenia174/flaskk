from flask import Flask, render_template, url_for, request, redirect, flash, get_flashed_messages, session
from db import *
import hashlib
from random import choice, randint
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dfiosdhosfdiopsk09sruspttu0sk'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

def WhatNav():
    if session.get("auth"):
        arr = [{"url":"/", "name": "Главная"},{"url":"/user", "name": session.get("login")}, {"url":"/logout", "name": "Выход"}]
    else:
        arr = [{"url": "/", "name": "Главная"}, {"url": "/registr", "name": "Регистрация"}]
    return arr

def WhatTypes(arr):

    if session.get("auth"):
        types = []
        for i in arr:

            types.append({"id_type": i[0], "type": i[1]})
    else:

        types = [{"id_type": 1, "type": "Публичная"}]

    return types

if not getTypes():
    types = ["Публичная", "Общего доступа", "Приватная"]
    setTypes(types)

@app.route('/')
def index():
    if session.get("auth") == None:
        session["auth"] = False
    arr = getTypes()
    return render_template('index.html', nav=WhatNav(), types=WhatTypes(arr))

@app.route('/auth')
def auth():
    return render_template('auth.html', nav = WhatNav())

@app.route('/user')
def user():
    arr = getTypes()
    links = getLinksByUser(session.get("user_id"))
    return render_template('user.html', nav = WhatNav(), links = links, types = WhatTypes(arr))

@app.route('/registr')
def reg():
    return render_template('registr.html', nav = WhatNav())


@app.route('/insert', methods=['POST'])
def insert():
    if request.method == 'POST':

        login = request.form['login']
        cpassw = request.form['cpass']
        passw = request.form['pass']

        if(getLogin(login) == None):
            if cpassw == passw:
                hashas = hashlib.md5(request.form["pass"].encode())
                password = hashas.hexdigest()
                insertUser(login,password)
                id_user = getLogin(login)
                session["user_id"] = id_user[0]
                session["login"] = login
                session["auth"] = True

                return redirect('/', code = 302)
            else:

                flash("Пароли не совподают")
                return redirect('/registr', code = 302)
        else:
            flash("Логин уже занят")
            return redirect('/registr', code=302)


@app.route('/logout')
def logout():
    session.pop('login', None)
    session.pop('auth', None)
    session.pop('link', None)
    return redirect('/', code = 302)

@app.route('/home', methods=['POST'])
def home():
    if request.method == 'POST':

        login = request.form['login']
        passw = request.form['pass']
        print(getLogin(login))
        if(getLogin(login) != None):
            hashas = hashlib.md5(request.form["pass"].encode())
            password = hashas.hexdigest()
            passwUser = getPass(login, password)

            if passwUser != None and passwUser[0] == password:
                session["login"] = login
                session["auth"] = True
                id_user = getLogin(login)
                session["user_id"] = id_user[0]
                if(session.get("link") != None):
                    return redirect(session.get("link"))
                else:
                    return redirect('/', code = 302)
            else:
                flash("Пароль не тот")
                return redirect('/auth', code = 302)
        else:
            flash("Логин не найден")
            return redirect('/auth', code = 302)



@app.route('/create_link', methods=['POST'])
def createlink():
    if request.method == 'POST':
        host_url = request.host_url
        link = request.form['link']
        type = request.form['type']
        if link != "":
            if request.form.getlist('ispsevd') :
                psevd = request.form['psevd']
                link_psevd = host_url + "qwerty/" + psevd
                if getPsev(link_psevd) != None:
                    flash("Псевдоним занят", category="errors")
                else:
                    short_link = host_url + "qwerty/" + psevd
                    if session.get("auth"):
                        insertLink(link, session.get("user_id"), type, short_link)
                    else:
                        insertLinkNotAuth(link, type, short_link)
                    flash(link, category="link")
                    flash(short_link, category="url")
            else:
                short_link = host_url + "qwerty/" + ''.join(choice(string.ascii_letters+string.digits) for _ in range(randint(8, 12)))
                if session.get("auth"):
                    insertLink(link, session.get("user_id"), type, short_link);

                else:
                    insertLinkNotAuth(link, type, short_link)
                flash(link, category="link")
                flash(short_link, category="url")
        else:
            flash("Введите ссылку", category="errors")
    return redirect("/", code=302)


if __name__ == '__main__':
    app.run(debug=True)
