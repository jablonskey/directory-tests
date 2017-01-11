from __future__ import absolute_import
import random

from locust import HttpLocust, TaskSet, task
from bs4 import BeautifulSoup

from tests import get_relative_url, get_absolute_url, settings


USERS = (
    ('load_tests1@example.com', 'passwordpassword'),
    ('load_tests2@example.com', 'passwordpassword'),
    ('load_tests3@example.com', 'passwordpassword'),
    ('load_tests4@example.com', 'passwordpassword'),
    ('load_tests5@example.com', 'passwordpassword'),
    ('load_tests6@example.com', 'passwordpassword'),
    ('load_tests7@example.com', 'passwordpassword'),
    ('load_tests8@example.com', 'passwordpassword'),
    ('load_tests9@example.com', 'passwordpassword'),
    ('load_tests10@example.com', 'passwordpassword'),
    ('load_tests11@example.com', 'passwordpassword'),
    ('load_tests12@example.com', 'passwordpassword'),
    ('load_tests13@example.com', 'passwordpassword'),
    ('load_tests14@example.com', 'passwordpassword'),
    ('load_tests15@example.com', 'passwordpassword'),
    ('load_tests16@example.com', 'passwordpassword'),
    ('load_tests17@example.com', 'passwordpassword'),
    ('load_tests18@example.com', 'passwordpassword'),
    ('load_tests19@example.com', 'passwordpassword'),
    ('load_tests20@example.com', 'passwordpassword'),
    ('load_tests21@example.com', 'passwordpassword'),
    ('load_tests22@example.com', 'passwordpassword'),
    ('load_tests23@example.com', 'passwordpassword'),
    ('load_tests24@example.com', 'passwordpassword'),
    ('load_tests25@example.com', 'passwordpassword'),
)


class PublicPagesBuyerUI(TaskSet):
    @task
    def landing_page(self):
        self.client.get(get_relative_url('ui-buyer:landing'))

    @task
    def start_registration(self):
        self.client.get(get_relative_url('ui-buyer:register'))


class AuthenticatedPagesBuyerUI(TaskSet):

    def _get_login_data(self):
        user, password = random.choice(USERS)
        return {"login": user, "password": password}

    def on_start(self):
        data = self._get_login_data()
        login_url = get_absolute_url('sso:login')
        response = self.client.post(login_url, data=data)
        try:
            cookie = response.history[0].headers['Set-Cookie']
        except IndexError:
            raise Exception("Login failed!")
        self.headers = {'Cookie': cookie}

    def _get_csrf_token(self, url):
        response = self.client.get(url, headers=self.headers)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('input')[0].attrs['value']

    @task
    def company_profile(self):
        self.client.get(
            get_relative_url('ui-buyer:company-profile'),
            headers=self.headers
        )

    def _upload_logo(self, path_to_img):
        url = get_relative_url('ui-buyer:upload-logo')
        img = open(path_to_img, 'rb')
        data = {
            'csrfmiddlewaretoken': self._get_csrf_token(url),
            'supplier_company_profile_logo_edit_view-current_step': 'logo'
        }
        self.client.post(
            url, data=data, files={'logo-logo': img}, headers=self.headers)

    @task
    def upload_logo(self):
        self._upload_logo('tests/fixtures/images/sphynx-814164_640.jpg')

    @task
    def upload_large_logo(self):
        self._upload_logo('tests/fixtures/images/pallas-cat-275930.jpg')

    @task
    def confirm_company_address_valid_code(self):
        url = get_relative_url('ui-buyer:confirm-company-address')
        step = 'supplier_company_address_verification_view-current_step'
        data = {
            'csrfmiddlewaretoken': self._get_csrf_token(url),
            step: 'address',
            'address-code': '000000000000',
        }
        self.client.post(url, data=data, headers=self.headers)

    @task
    def confirm_company_address_invalid_code(self):
        url = get_relative_url('ui-buyer:confirm-company-address')
        step = 'supplier_company_address_verification_view-current_step'
        data = {
            'csrfmiddlewaretoken': self._get_csrf_token(url),
            step: 'address',
            'address-code': '1111',
        }
        self.client.post(url, data=data, headers=self.headers)


class RegularUserBuyerUI(HttpLocust):
    host = settings.DIRECTORY_UI_BUYER_URL
    task_set = PublicPagesBuyerUI
    stop_timeout = settings.LOCUST_TIMEOUT
    min_wait = settings.LOCUST_MIN_WAIT
    max_wait = settings.LOCUST_MAX_WAIT


class AuthenticatedUserBuyerUI(HttpLocust):
    host = settings.DIRECTORY_UI_BUYER_URL
    task_set = AuthenticatedPagesBuyerUI
    stop_timeout = settings.LOCUST_TIMEOUT
    min_wait = settings.LOCUST_MIN_WAIT
    max_wait = settings.LOCUST_MAX_WAIT


class PublicPagesSupplierUI(TaskSet):
    @task
    def landing_page(self):
        self.client.get(get_relative_url('ui-supplier:landing'))

    @task
    def register_interest(self):
        data={
            'email_address': 'test@example.com',
            'full_name': 'Mr Test',
            'sector': 'GLOBAL_SPORTS_INFRASTRUCTURE',
            'terms': True,
        }
        self.client.post(
            get_relative_url('ui-supplier:landing'),
            data=data
        )

    @task
    def suppliers(self):
        self.client.get(get_relative_url('ui-supplier:suppliers'))

    @task
    def suppliers_detail(self):
        self.client.get(get_relative_url('ui-supplier:suppliers-detail'))

    @task
    def industries(self):
        self.client.get(get_relative_url('ui-supplier:industries'))

    @task
    def industries_health(self):
        self.client.get(get_relative_url('ui-supplier:industries-health'))

    @task
    def industries_tech(self):
        self.client.get(get_relative_url('ui-supplier:industries-tech'))

    @task
    def industries_creative(self):
        self.client.get(get_relative_url('ui-supplier:industries-creative'))

    @task
    def industries_food(self):
        self.client.get(get_relative_url('ui-supplier:industries-food'))

    @task
    def case_study(self):
        self.client.get(get_relative_url('ui-supplier:case-study'))


class RegularUserSupplierUI(HttpLocust):
    host = settings.DIRECTORY_UI_SUPPLIER_URL
    task_set = PublicPagesSupplierUI
    stop_timeout = settings.LOCUST_TIMEOUT
    min_wait = settings.LOCUST_MIN_WAIT
    max_wait = settings.LOCUST_MAX_WAIT
