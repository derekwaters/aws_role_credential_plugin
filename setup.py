#!/usr/bin/env python

from setuptools import setup

requirements = ["boto3", "botocore"]  # add Python dependencies here
# e.g., requirements = ["PyYAML"]

setup(
    name='aws_role_credential_plugin',
    version='0.1',
    author='Derek Waters',
    author_email='dwaters@redhat.com',
    description='',
    long_description='',
    license='Apache License 2.0',
    keywords='ansible',
    url='http://github.com/derekwaters/aws_role_credential_plugin',
    packages=['aws_role_credential_plugin'],
    include_package_data=True,
    zip_safe=False,
    setup_requires=[],
    install_requires=requirements,
    entry_points = {
        'awx.credential_plugins': [
            'aws_role_credential_plugin = aws_role_credential_plugin:aws_role_credential_plugin',
        ]
    }
)