import bcrypt
from werkzeug.security import safe_str_cmp
from models.user import UserModel

def authenticate(username, password):
    user = UserModel.find_by_username(username)
    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return user

    # if user and safe_str_cmp(user.password, password):
        # return user

def identity(payload):
    user_id = payload['identity']
    return UserModel.find_by_id(user_id)
