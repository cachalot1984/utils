#!/usr/bin/python3

from urllib.request import urlopen
from bs4 import BeautifulSoup
import os, re, subprocess, time
from selenium import webdriver

startUrl = 'http://www.52tps.com/xz/xajh219h_460/audio_1.html'
saveDir = './download'


page = urlopen(startUrl)
pageBs = BeautifulSoup(page, "lxml")
driver = webdriver.PhantomJS(executable_path='/usr/bin/phantomjs')

while True:
    frameLink = pageBs.find('div', {'class': 'fz14'}).find('iframe').attrs['src']
    #print(frameLink)
    driver.get(frameLink)
    frameBs = BeautifulSoup(driver.page_source, 'lxml')
    #print(frameBs)
    currentLink = frameBs.find('div', {'class': 'content_down'}).find('a', id="download").attrs['href']
    print(">> Download link: " + currentLink)
    outfile = saveDir + '/' + re.search('/([^/]+)\?', currentLink).group(1)
    if not os.access(outfile, os.F_OK):
        subprocess.call('wget -nv --show-progress -O ' + outfile + ' ' + currentLink, shell=True)
        time.sleep(3)

    navLink = pageBs.find('div', {'class': 'fz14'}).find('a', text=re.compile('.*下一集.*'))
    if navLink:
        nextLink = navLink.attrs['href']
        print(">> Next link: " + nextLink)
        page = urlopen(nextLink)
        pageBs = BeautifulSoup(page, "lxml")
    else:
        print('>> Download completed!')
        break

    print("\n")

