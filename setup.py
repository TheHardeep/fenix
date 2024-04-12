import setuptools
import codecs
import os.path


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setuptools.setup(
    name="fenix",
    version=get_version("fenix/__init__.py"),
    keywords="fenix, aliceblue, angelone, choice, finvasia, fivepaisa, fyers, iifl, kotak, kotakneo, kunjee, mastertrust, motilaloswal, paper, symphony, upstox, vpc, zerodha, finance, broker, trader, XTS, kite, algorithmic, algotrading, api, arbitrage, real-time, realtime, backtest, backtesting, etc, framework, invest, investing, investor, library, market, market data, ohlcv, order, orderbook, order book, strategy, ticker, tickers, toolkit, trade, trader, trading, volume, websocket, websockets, web socket, web sockets, ws",
    author="Hardeep Singh",
    author_email="hardeep.hd13@gmail.com",
    description="A Python library for trading in the Indian Finance Sector with support for multiple broker APIs.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license="GPLv3",
    url="https://fenix.hardeep.tech",
    packages=setuptools.find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=42.0.5",
        "numpy>=1.24.4",
        "pandas>=2.0.3",
        "pycryptodome>=3.20.0",
        "PyJWT>=2.8.0",
        "pyotp>=2.9.0",
        "requests>=2.31.0",
        "requests-oauthlib>=1.4.0",
        "selenium>=4.18.1",
        "urllib3>=2.2.1",
        "webdriver-manager>=4.0.1",
        "undetected-chromedriver>=3.5.5",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Financial and Insurance Industry",
        "Intended Audience :: Information Technology",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Office/Business :: Financial :: Investment",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    project_urls={
        "Documentation": "https://github.com/TheHardeep/fenix/fenix/wiki",
        "Source Code": "https://github.com/TheHardeep/fenix.git",
    },
)
