import mlsip

def test_simple_header():
    header = mlsip.Contact.from_header('<sip:pytest@127.0.0.1:7000>')
    assert not header['name']
    assert dict(header['params']) == {}
    assert dict(header['uri']) == {'scheme': 'sip',
                                   'user': 'pytest',
                                   'password': None,
                                   'host': '127.0.0.1',
                                   'port': 7000,
                                   'params': None,
                                   'headers': None}
    assert str(header) == '<sip:pytest@127.0.0.1:7000>'


def test_header_with_name_and_params():
    header = mlsip.Contact.from_header('Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8')
    assert header['name'] == "Anonymous"
    assert dict(header['params']) == {'tag': 'hyh8'}
    assert dict(header['uri']) == {'scheme': 'sip',
                                   'user': 'c8oqz84zk7z',
                                   'password': None,
                                   'host': 'privacy.org',
                                   'port': None,
                                   'params': None,
                                   'headers': None}
    assert str(header) == '"Anonymous" <sip:c8oqz84zk7z@privacy.org>;tag=hyh8'


def test_add_tag():
    header = mlsip.Contact.from_header('<sip:pytest@127.0.0.1:7000>')
    assert dict(header['params']) == {}

    header.add_tag()
    assert 'tag' in header['params']
