import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="encrypted-dns",
    version="1.2.0",
    author="Xiaoyang Liu",
    author_email="siujoeng.lau@gmail.com",
    description="DNS-over-HTTPS and DNS-over-TLS server and forwarder.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Berkeley-Reject/Encrypted-DNS",
    install_requires=['dnspython', 'requests'],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'encrypted-dns=encrypted_dns.main:start'
        ],
    },
    keywords='dns doh dot tls https',
    license='Apache 2.0',
)
