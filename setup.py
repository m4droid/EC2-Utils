from setuptools import setup


setup(
    name='server_utils',
    version='0.0.1',
    author='Francisco Madrid',
    packages=['server_utils'],
    entry_points={
        'console_scripts': [
            'gh_org_keys = server_utils.gh_org_keys:main',
        ]
    },
    install_requires=[
        'requests>=2.9.1',
    ],
)
