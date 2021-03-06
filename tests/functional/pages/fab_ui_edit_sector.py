# -*- coding: utf-8 -*-
"""FAB - Edit Company's Sector page"""
import logging
import random

from requests import Response, Session

from tests import get_absolute_url
from tests.functional.utils.context_utils import Actor, Company
from tests.functional.utils.request import Method, check_response, make_request
from tests.settings import COUNTRIES, SECTORS

URL = get_absolute_url("ui-buyer:company-edit-sectors")
EXPECTED_STRINGS = [
    "Your company sector", "What industry is your company in?",
    "Select the countries you would like to export to:",
    "China", "Germany", "India", "Japan", "United States", "Other", "Save"
] + SECTORS


def go_to(session: Session) -> Response:
    """Go to "Edit Company's sector & countries to export to" page.

    This requires:
     * Supplier to be logged in

    :param session: Supplier session object
    """
    headers = {"Referer": get_absolute_url("ui-buyer:company-profile")}
    response = make_request(
        Method.GET, URL, session=session, headers=headers)

    should_be_here(response)
    return response


def should_be_here(response):
    """Check if User is on the correct page.

    :param response: response object
    """
    check_response(response, 200, body_contains=EXPECTED_STRINGS)
    logging.debug("Supplier is on the Select Sector page")


def update(
        actor: Actor, company: Company, *, update_sector: bool = True,
        sector_name: str = None, update_countries: bool = True,
        country_names: str = None) -> (Response, str, str):
    """Change Company's Sector of Interest.

    :param actor: a namedtuple with Actor details
    :param company: a namedtuple with Company details
    :param update_sector: update Sector if True or use the current one if False
    :param sector_name: use specific Sector.
            Must be one of sectors specified in `tests.settings.SECTORS`
    :param update_countries: update Countries to Export if True
                             or use the current one if False
    :param country_names: use specific Country/Countries.
    :return: a tuple consisting of Response object, new sector & new countries
    """
    session = actor.session
    token = actor.csrfmiddlewaretoken

    if update_sector:
        new_sector = sector_name or random.choice(SECTORS)
    else:
        new_sector = company.sector

    if update_countries:
        new_countries = country_names or COUNTRIES[random.choice(list(COUNTRIES))]
    else:
        new_countries = company.export_to_countries

    other = ""
    headers = {"Referer": URL}
    data = {
        "csrfmiddlewaretoken": token,
        "supplier_classification_edit_view-current_step": "classification",
        "classification-sectors": new_sector,
        "classification-export_destinations": new_countries,
        "classification-export_destinations_other": other
    }

    response = make_request(
        Method.POST, URL, session=session, headers=headers, data=data)

    return response, new_sector, new_countries
