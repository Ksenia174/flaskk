import sqlite3

connect = sqlite3.connect("db.db")
cursor = connect.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS  "users" (
    "id"	Integer not null, 
    "login" Text not null, 
    "password"	Text not null, 
    PRIMARY KEY("id" AUTOINCREMENT));
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS  "type_links" (
    "id"	Integer not null, 
    "name" Text not null, 
    PRIMARY KEY("id" AUTOINCREMENT));
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS "links" (
    "id" Integer not null, 
    "link" Text not null, 
    "user_id",
    "type_id" Integer not null,
    "short_link" Text not null,
    "count" Integer,
    PRIMARY KEY("id" AUTOINCREMENT)
    FOREIGN KEY (user_id)  REFERENCES users (id),
    FOREIGN KEY (type_id)  REFERENCES link_types (id)
);
''')

def setTypes(arr):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    for i in arr:
        cursor.execute('''INSERT INTO type_links('name') VALUES(?);''', (i,))
        print(i)
    connect.commit()

def getTypes():
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT * FROM type_links').fetchall()


def setTypes(arr):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    for i in arr:
        cursor.execute('''INSERT INTO type_links('name') VALUES(?);''', (i,))
        print(i)
    connect.commit()
    connect.close()
def getTypes():
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT * FROM type_links').fetchall()

def getLogin(login):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT id FROM users WHERE login = ?',(login,)).fetchone()

def getPsev(psev):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT link FROM links WHERE short_link = ?',(psev,)).fetchone()

def getLinksByUser(us_id):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT link, count, type_links.name as type, short_link as short, links.id, type_id FROM links INNER JOIN type_links ON type_id = type_links.id WHERE user_id = ?',(us_id,)).fetchall()


def getTypebyLink(link):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT type_id FROM links WHERE short_link = ?',(link,)).fetchone()

def getUserbyLink(link):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT user_id FROM links WHERE short_link = ?',(link,)).fetchone()

def deleteLink(link_id):
    connect = sqlite3.connect('db.db')
    cursor = connect.cursor()
    cursor.execute('''DELETE FROM 'links' WHERE id = ?''', (link_id,))
    connect.commit()
    connect.close()

def updateCounOfLink(link):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    cursor.execute("UPDATE links SET count = count+1 WHERE short_link = ?", (link, ))
    connect.commit()
    connect.close()

def editTypeOfLink(type_id, link_id):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    cursor.execute("UPDATE links SET type_id = ? WHERE id = ?", (type_id, link_id, ))
    connect.commit()
    connect.close()

def editPsevOfLink(psev, link_id):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    cursor.execute("UPDATE links SET short_link = ? WHERE id = ?", (psev, link_id, ))
    connect.commit()
    connect.close()

def getPass(login, passw):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    return cursor.execute('SELECT password FROM users WHERE login = ? AND password = ?',(login, passw)).fetchone()

def insertLink(link, us_id, type_id, short_l):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    cursor.execute('''INSERT INTO links(link, user_id, type_id, short_link, count) VALUES(?,?,?,?, 0);''', (link, us_id, type_id, short_l,))
    connect.commit()
    connect.close()

def insertLinkNotAuth(link,type_id, short_l):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    cursor.execute('''INSERT INTO links(link, user_id, type_id, short_link, count) VALUES(?, NULL, ?, ?, 0);''', (link, type_id, short_l,))
    connect.commit()
    connect.close()

def insertUser(login, password):
    connect = sqlite3.connect("db.db")
    cursor = connect.cursor()
    cursor.execute('''INSERT INTO users(id, login, password) VALUES(NULL, ?,?);''', (login, password,))
    connect.commit()
    connect.close()

connect.commit()

connect.close()