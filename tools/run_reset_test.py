from app import app, db, User
from werkzeug.security import generate_password_hash
app.app_context().push()
# create user
u = User.query.filter_by(username='__reset_check__').first()
if not u:
    u = User(username='__reset_check__', password=generate_password_hash('oldpass'))
    db.session.add(u); db.session.commit(); print('created test user')
else:
    print('test user exists')

client = app.test_client()
resp = client.post('/forgot_password', data={'identifier':'__reset_check__'}, follow_redirects=False)
print('POST /forgot_password status', resp.status_code)
print('Location:', resp.headers.get('Location'))
if resp.headers.get('Location'):
    r = client.get(resp.headers.get('Location'))
    print('GET reset_direct status', r.status_code)
    r2 = client.post(resp.headers.get('Location'), data={'password':'newpass','confirm_password':'newpass'}, follow_redirects=True)
    print('POST reset_direct status', r2.status_code)
    if b'Password updated successfully' in r2.data:
        print('Reset succeeded')
    else:
        print('Reset may have failed')
else:
    print('No redirect')
