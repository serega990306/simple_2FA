from typing import Annotated
from uuid import uuid4

import pyotp
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

app = FastAPI()

totp_sync_template = """
<!DOCTYPE html>
<html>
<body>
<canvas id="qr"></canvas>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
<script>
  (function () {
    var qr = new QRious({
      element: document.getElementById('qr'),
      value: '%s'
    });
  })();
</script>
<p>Просканируйте QR-код с помощью TOTP-приложения и введите код</p>
<form method="post" action="/sync/%s">
    <input required name="code">
    <button type="submit">Синхронизация</button>
</form>
</body>
</html>
"""

# Имитируем хранилище с секретами для пользователей
users_secrets: dict[str, str] = dict()
# Имитируем хранилище пользователей, которые подключили TOTP-приложение
verifier_users: set[str] = set()


@app.get('/', response_class=HTMLResponse)
def sync():
    # Для простоты генерируем пользователя
    user_id = str(uuid4())
    # Генерация секретного ключа, на его основе будут создавать коды
    secret = pyotp.random_base32()
    users_secrets[user_id] = secret
    # Создаём инстанс генератора кодов на основе секрета
    totp = pyotp.TOTP(secret)
    # Ссылка для передачи секретного кода TOTP-приложению. В ссылке можно передать название приложения и имя пользователя
    provisioning_url = totp.provisioning_uri(name=user_id + '@praktikum.ru', issuer_name='Awesome Praktikum app')
    tmpl = totp_sync_template % (provisioning_url, user_id)
    return tmpl


@app.post('/sync/{user_id}')
def sync_check(user_id: str, code: Annotated[str, Form()]):
    # После сканирования QR-кода пользователь отправляет код, сгенерированный в TOTP-приложения
    # Сгенерированный код действителен в течение 30 секунд
    # Достаём из хранилища секретный ключ
    secret = users_secrets[user_id]
    totp = pyotp.TOTP(secret)
    # Верифицируем полученный от пользователя код
    if not totp.verify(code):
        return 'Неверный код'

    verifier_users.add(user_id)
    return RedirectResponse(f'/check/{user_id}')


check_totp_tmpl = """
<!DOCTYPE html>
<html>
<body>
<p>{message}</p>
<p>Введите код из TOTP-приложения</p>
<form method="post" action="/check/{user_id}">
    <input required name="code">
    <button type="submit">Синхронизация</button>
</form>
</body>
</html>
"""


# После успешного подключения TOTP-приложения пользователю больше не надо сканировать QR-код
# Можем смело запрашивать код при авторизации
# Самое классное, что TOTP-приложение не требует соединения с интернетом
# Такой способ аутентификации очень удобен, если вы в роуминге, интернет отсутствует, а входящие СМС — платные.
@app.get('/check/{user_id}', response_class=HTMLResponse)
def render_check_page(user_id: str):
    if user_id not in verifier_users:
        return RedirectResponse('/')
    return check_totp_tmpl.format(message='', user_id=user_id)


@app.post('/check/{user_id}', response_class=HTMLResponse)
def check(user_id: str, code: Annotated[str, Form()]):
    if user_id not in verifier_users:
        return RedirectResponse('/')
    secret = users_secrets[user_id]
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        return check_totp_tmpl.format(message='неверный код', user_id=user_id)
    return check_totp_tmpl.format(message='верный код', user_id=user_id)


if __name__ == '__main__':
    uvicorn.run(
        'main:app', host='0.0.0.0', port=8000, reload=True,
    )
