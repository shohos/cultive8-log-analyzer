import io
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client(database):
    # Don't run lifespan: API tests should not load/invoke a model.
    return TestClient(app)


@pytest.mark.parametrize("name,body",[("bad.csv",b"text"),("bad.log",b"\xff\xfe"),("empty.txt",b" \n"),("binary.log",b"a\x00b")])
def test_invalid_upload(client,name,body):
    assert client.post('/api/jobs',files={"file":(name,body)}).status_code == 400
    assert client.get('/api/jobs').json() == []


def test_upload_start_pause_resume_export(client):
    r=client.post('/api/jobs',files={"file":("../../x.log",b'{"client_ip":"10.0.0.1","path":"/"}\n')})
    assert r.status_code == 201
    j=r.json(); assert j["name"]=="x.log" and j["total_lines"]==1
    path='/api/jobs/'+j['id']
    assert client.post(path+'/start').json()['status']=='queued'
    assert client.post(path+'/start').json()['status']=='queued'
    assert client.post(path+'/pause').json()['status']=='paused'
    assert client.post(path+'/start').json()['status']=='queued'
    assert client.get(path+'/report').json()['complete'] is False
    assert client.get('/api/jobs/missing').status_code==404


def test_cross_origin_writes_blocked(client):
    assert client.post('/api/sample',headers={'origin':'https://attacker.test'}).status_code==403
    assert client.get('/',headers={'host':'attacker.test'}).status_code==403


def test_oversize_upload(client):
    assert client.post('/api/jobs',files={'file':('big.log',b'x'*(5*1024*1024+1))}).status_code in (400,413)


def test_chunked_body_limit_before_multipart_parser(client):
    def body():
        yield b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="large.log"\r\n\r\n'
        for _ in range(96):
            yield b'x'*65536
        yield b'\r\n--boundary--\r\n'
    response=client.post('/api/jobs',content=body(),headers={'content-type':'multipart/form-data; boundary=boundary'})
    assert response.status_code==413
    assert client.get('/api/jobs').json()==[]


def test_static_security_headers(client):
    response=client.get('/')
    assert response.status_code==200
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    assert client.get('/static/app.js').status_code==200
