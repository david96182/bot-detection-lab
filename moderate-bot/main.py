import random
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service as FirefoxService
import json


def get_clothes():
    browser.find_element(By.ID, 'category-3').click()
    clothes = browser.find_elements(By.CLASS_NAME, 'product-description')
    clothes_data = []
    for i in range(len(clothes)):
        cloth = clothes[i].text.split('\n')
        clothes_data.append({
            'name': cloth[0],
            'price': cloth[1]
        })
    with open('products.json', 'r') as json_file:
        json_file_data = json.load(json_file)
        json_file_data['clothes'] = clothes_data

    with open('products.json', 'w') as json_file:
        json.dump(json_file_data, json_file)
    time.sleep(random.randint(5, 10))


def get_accessories():
    browser.find_element(By.ID, 'category-6').click()
    accs = browser.find_elements(By.CLASS_NAME, 'product-description')
    accs_data = []
    for i in range(len(accs)):
        acc = accs[i].text.split('\n')
        accs_data.append({
            'name': acc[0],
            'price': acc[1]
        })
    with open('products.json', 'r') as json_file:
        json_file_data = json.load(json_file)
        json_file_data['accesories'] = accs_data

    with open('products.json', 'w') as json_file:
        json.dump(json_file_data, json_file)
    time.sleep(random.randint(7, 12))


def get_art():
    browser.find_element(By.ID, 'category-9').click()
    arts = browser.find_elements(By.CLASS_NAME, 'product-description')
    art_data = []
    for i in range(len(arts)):
        art = arts[i].text.split('\n')
        art_data.append({
            'name': art[0],
            'price': art[1]
        })
    with open('products.json', 'r') as json_file:
        json_file_data = json.load(json_file)
        json_file_data['art'] = art_data

    with open('products.json', 'w') as json_file:
        json.dump(json_file_data, json_file)
    time.sleep(random.randint(7, 11))


def get_discount():
    browser.find_element(By.CLASS_NAME, 'logo').click()
    browser.find_element(By.CLASS_NAME, 'all-product-link').click()
    time.sleep(random.randint(6, 13))


def login():
    browser.find_element(By.CLASS_NAME, 'user-info').click()
    browser.find_element(By.ID, 'field-email').send_keys('puertadavid96@email.com')
    browser.find_element(By.ID, 'field-password').send_keys('Qwe1234567@rs*')  # 12345678
    browser.find_element(By.ID, 'submit-login').click()
    time.sleep(10)


if __name__ == '__main__':
    service = FirefoxService()
    firefox_options = webdriver.FirefoxOptions()
    # firefox_options.headless = True
    browser = webdriver.Firefox(options=firefox_options, service=service)
    browser.get('http://172.26.0.3')
    print('Current page: %s' % browser.current_url)
    login()

    browser.implicitly_wait(10)
    while True:
        get_clothes()
        get_accessories()
        get_art()
        get_discount()
        time.sleep(random.randint(10, 30))
