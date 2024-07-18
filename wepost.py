import argparse
import sqlite3
import string
import os
import hashlib
import logging

_DB_PATH = '../store_post.db'
_LOG_PATH = '../wepost.log'


class WePost:
    _CMD_LIST = ['-p, -c, -h, -q']
    def __init__(self, _db_path, _log_path):
        self.set_conn(_db_path)
        self.set_logger(_log_path)
        self.make_db_or_get()

    def set_conn(self, _db_path):
        self.conn = sqlite3.connect(_db_path)
        return 0
    
    def set_logger(self, _log_path):
        _FORMAT = '{levelname:<8} - {asctime}: {msg}'
        logging.basicConfig(format=_FORMAT, style='{', level=logging.INFO, filename=_log_path)
        self.logger = logging.getLogger('wepost')
        return 0
    
    def make_db_or_get(self):
        with self.conn:
            self.conn.execute('''
CREATE TABLE IF NOT EXISTS Users (
username VARCHAR(64) PRIMARY KEY,
password BLOB(64) NOT NULL,
status INTEGER DEFAULT 1
)
''')
        self.conn.execute('''
CREATE TABLE IF NOT EXISTS Posts (
id INTEGER PRIMARY KEY,
body VARCHAR(512) NOT NULL
)
''')
        return 0
    
    def user_exists(self, _name):
        with self.conn:
            _Q_SELECT_BY_USERNAME = "SELECT username FROM Users WHERE username = ? LIMIT 1"
            _query = self.conn.execute(_Q_SELECT_BY_USERNAME, (_name,))
            _data = _query.fetchall()
            return 0, _data
    
    def validate_username(self, _name):
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

    def insert_user(self, _args):
        with self.conn:
            self.conn.execute("INSERT INTO Users (username, password) VALUES (?, ?)", _args)
            self.conn.commit()
        return 0, f'{_args[0]} has been added'

    def make_key(self, _args):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', _args[1].encode(), salt, 128)
        return 0, salt + key

    def add_user(self, _args):
        err, resp = self.validate_username(_args[0])
        if err:
            return err, resp
        err, resp = self.make_key(_args)
        if err:
            return err, resp
        return self.insert_user((_args[0], resp))

    def create_user(self, _args):
        err, resp = self.user_exists(_args[0])
        if err:
            return err, resp
        if resp:
            _USER_EXISTS = f'user exists'
            return 1, _USER_EXISTS
        else:
            err, resp = self.add_user(_args)
            if not err:
                _msg = f'a user has been added: {_args}'
                self.logger.info(_msg)
                print(resp)
            return err, resp
    
    def inter_mode(self):
        _HELP_MSG = '''
        -q command for quite
        -c create a user. usage: name pwd
        -p make a post
        '''
        print(self._CMD_LIST)
        STATE = 1
        while STATE:
            cmd = input('enter a command: ')
            if cmd == 'q' or cmd == '-q':
                STATE = 0
            elif cmd == 'c' or cmd == '-c':
                name_pwd = input('enter username and password: ')
                name_pwd = name_pwd.split()
                if len(name_pwd) != 2:
                    print(f'usage: username pwd')
                else:
                    err, resp = self.create_user(name_pwd)
            elif cmd == 'h' or cmd == '-h':
                print(_HELP_MSG)
            else:
                print('invalid command')
                print(self._CMD_LIST)
        return 0, 'ok'
    
    def check_args(self, _args):
        if _args.c:
            err, resp = self.create_user(_args.c)
        elif _args.p:
            print('process p')
            print(_args.p)
            # err, resp = self.create_post(_args.p)
        else:
            print('not args')
            print(_args)
            err, resp = self.inter_mode()
        return 0


def make_parser():
    DESC = f'the application for adding posts to the database'
    parser = argparse.ArgumentParser(description=DESC)
    DESC_C = f'usage:$ wepost.py user pwd'
    parser.add_argument('-c', type=str, nargs=2 ,help=DESC_C)
    DESC_P = f'usage:$ wepost.py user pwd post'
    parser.add_argument('-p', type=str, nargs=3 ,help=DESC_P)
    return parser

def main():
    wepost = WePost(_DB_PATH, _LOG_PATH)
    args = make_parser().parse_args()
    wepost.check_args(args)


if __name__ == '__main__':
    main()