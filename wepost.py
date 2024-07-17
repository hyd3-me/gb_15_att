import argparse
import sqlite3
import string
import os
import hashlib


conn  = sqlite3.connect('../store_post.db')


def make_db_or_get(_conn):
    with _conn:
        _conn.execute('''
CREATE TABLE IF NOT EXISTS Users (
username VARCHAR(64) PRIMARY KEY,
password BLOB(64) NOT NULL,
status INTEGER DEFAULT 1
)
''')
        _conn.execute('''
CREATE TABLE IF NOT EXISTS Posts (
id INTEGER PRIMARY KEY,
body VARCHAR(512) NOT NULL
)
''')
    return 0

def validate_username(_name):
    _VALID_CHARS = string.ascii_lowercase + string.digits + '_!'
    _ERR_MSG = f'the username must be between 1 and 64 characters long'
    if len(_name) < 1:
        return 1, _ERR_MSG
    if len(_name) > 64:
        return 1, _ERR_MSG
    for ch in _name:
        if ch.lower() not in _VALID_CHARS:
            return 1, f'valid characters: {_VALID_CHARS}'
    return 0, 'ok'

def user_exists(_conn, _name):
    with _conn:
        cursor = _conn.execute("SELECT username FROM Users WHERE username = ?",(_name,))
        _data = cursor.fetchall()
    return 0, _data

def insert_user(_conn, _args):
    with _conn:
        cursor = _conn.execute("INSERT INTO Users (username, password) VALUES (?, ?)", _args)
        _conn.commit()
    return 0, 'ok'

def make_key(_args):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', _args[1].encode(), salt, 128)
    return 0, key

def add_user(_conn, _args):
    err, resp = validate_username(_args[0])
    if err:
        return err, resp
    err, resp = make_key(_args)
    if err:
        return err, resp
    return insert_user(_conn, (_args[0], resp))

def create_user(_conn, _args):
    err, resp = user_exists(_conn, _args[0])
    if err:
        return err, resp
    if resp:
        _USER_EXISTS = f'user exists'
        print(resp)
        print(_USER_EXISTS)
        return 1, _USER_EXISTS
    else:
        err, resp = add_user(_conn, _args)
        print('process c')
        print(resp)
        return err, resp

def make_parser():
    DESC = f'the application for adding posts to the database'
    parser = argparse.ArgumentParser(description=DESC)
    DESC_C = f'usage:$ wepost.py user pwd'
    parser.add_argument('-c', type=str, nargs=2 ,help=DESC_C)
    DESC_P = f'usage:$ wepost.py user pwd post'
    parser.add_argument('-p', type=str, nargs=3 ,help=DESC_P)
    return parser

def check_args(_args, _conn):
    if _args.c:
        err, resp = create_user(_conn, _args.c)
    elif _args.p:
        print('process p')
        print(_args.p)
    else:
        print('not args')
        print(_args)
    return 0

def main():
    err = make_db_or_get(conn)
    parser = make_parser()
    args = parser.parse_args()
    err = check_args(args, conn)


if __name__ == '__main__':
    main()