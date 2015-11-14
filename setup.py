from setuptools import setup

setup(name='pyCert',
      version='0.1',
      description='PKI Certificate python library',
      long_description=open('README.md').read(),
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
        'Intended Audience :: Developers',
      ],
      keywords='PKI pem asn1 SSL TLS certificate x509',
      url='https://github.com/alxnik/pyCert',
      author='Alexandros Nikolopoulos',
      author_email='alxnik@gmail.com',
      license='LGPL',
      packages=['pyCert'],
      install_requires=[
          'pyasn1',
      ],
      zip_safe=True)
