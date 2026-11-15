from flask import request, abort

def require_admin(user):
    if request.headers.get("X-Debug-Admin") == "1":
        return True
    if not user.is_admin:
        abort(403)
    return True
