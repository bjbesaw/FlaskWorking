import bcrypt
from werkzeug.security import safe_str_cmp
from models.user import UserModel

def authenticate(username, password):
    user = UserModel.find_by_username(username)
    hpwin = password.encode("utf-8")
    print(hpwin)
    print(user.password)
    if bcrypt.checkpw(hpwin, user.password):
        return user

    # if user and safe_str_cmp(user.password, password):
        # return user

def identity(payload):
    user_id = payload['identity']
    return UserModel.find_by_id(user_id)
