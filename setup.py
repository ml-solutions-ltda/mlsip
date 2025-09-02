#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# Abrindo arquivos de README e HISTORY, se existirem
with open('README.rst', encoding='utf-8') as f:
    readme = f.read()

try:
    with open('HISTORY.rst', encoding='utf-8') as f:
        history = f.read().replace('.. :changelog:', '')
except FileNotFoundError:
    history = ''

requirements = [
    'multidict>=2.0',
    'pyquery',
    'aiodns',
    'websockets',
    'async_timeout'
]

test_requirements = [
    'pytest',
    'pytest-asyncio'
]

setup(
    name='mlsip',  # seu pacote agora se chama mlsip
    version='0.1.2',  # versão inicial do seu pacote
    description='SIP support for AsyncIO - custom package',
    long_description=readme + '\n\n' + history,
    author='ML Solutions',
    author_email='ti@mlsolutions.net.br',  # coloque seu e-mail
    url='https://github.com/ml-solutions-ltda/mlsip',  # seu repositório
    packages=['mlsip'],
    package_dir={'mlsip': 'mlsip'},
    include_package_data=True,
    install_requires=requirements,
    license="Apache 2",
    zip_safe=False,
    keywords=['asyncio', 'sip', 'telephony'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: AsyncIO',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Topic :: Communications',
        'Topic :: Communications :: Internet Phone',
        'Topic :: Communications :: Telephony',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
