# -*- coding: utf-8 -*-
"""Helpers added to the behave's `context` object."""
import logging
from collections import namedtuple
from types import MethodType

from requests import Session

ScenarioData = namedtuple(
    'ScenarioData',
    [
        'actors', 'unregistered_companies'
    ]
)
Actor = namedtuple(
    'Actor',
    [
        'alias', 'email', 'password', 'session', 'csrfmiddlewaretoken',
        'email_confirmation_link', 'company_alias'
    ]
)
UnregisteredCompany = namedtuple(
    'UnregisteredCompany',
    [
        'alias', 'title', 'number', 'details'
    ]
)


def initialize_scenario_data():
    """Will initialize the Scenario Data.

    :return an empty ScenarioData named tuple
    :rtype ScenarioData
    """
    actors = {}
    unregistered_companies = {}
    scenario_data = ScenarioData(actors, unregistered_companies)
    return scenario_data


def add_actor(self, actor):
    """Will add Actor details to Scenario Data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param actor: an instance of Actor Named Tuple
    :type actor: tests.functional.features.ScenarioData.Actor
    """
    assert isinstance(actor, Actor), ("Expected Actor named tuple but got '{}'"
                                      " instead".format(type(actor)))
    self.scenario_data.actors[actor.alias] = actor
    logging.debug("Successfully added actor: %s to Scenario Data", actor.alias)


def get_actor(self, alias):
    """Get actor details from context Scenario Data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param alias: alias of sought actor
    :type alias: str
    :return: an Actor named tuple
    :rtype actor: tests.functional.features.ScenarioData.Actor
    """
    return self.scenario_data.actors[alias]


def set_actor_csrfmiddlewaretoken(self, alias, token):
    if alias in self.scenario_data.actors:
        actors = self.scenario_data.actors
        actors[alias] = actors[alias]._replace(csrfmiddlewaretoken=token)
        logging.debug("Successfully set csrfmiddlewaretoken=%s for Actor: "
                      "%s", token, alias)
    else:
        logging.debug("Could not find an actor aliased '%s'", alias)


def set_actor_email_confirmation_link(self, alias, link):
    if alias in self.scenario_data.actors:
        actors = self.scenario_data.actors
        actors[alias] = actors[alias]._replace(email_confirmation_link=link)
        logging.debug("Successfully set email_confirmation_link=%s for "
                      "Actor: %s", link, alias)
    else:
        logging.debug("Could not find an actor aliased '%s'", alias)


def reset_actor_session(self, alias):
    """Reset `requests` Session object.

    Can be useful when interacting with multiple domains.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param alias: alias of sought actor
    :type alias: str
    """
    if alias in self.scenario_data.actors:
        actors = self.scenario_data.actors
        actors[alias] = actors[alias]._replace(session=Session())
        logging.debug("Successfully reset %s's session object", alias)
    else:
        logging.debug("Could not find an actor aliased '%s'", alias)


def add_unregistered_company(self, company):
    """Will add an Unregistered Company to Scenario Data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param company: an instance of UnregisteredCompany Tuple
    :type company: test.functional.features.ScenarioData.UnregisteredCompany
    """
    assert isinstance(company, UnregisteredCompany), (
        "Expected UnregisteredCompany named tuple but got '{}' instead"
        .format(type(company)))
    self.scenario_data.unregistered_companies[company.alias] = company
    logging.debug("Successfully added Unregistered Company: %s - %s to "
                  "Scenario Data as '%s'", company.title, company.number,
                  company.alias)


def get_unregistered_company(self, alias):
    """Get the details of an Unregistered Company from context Scenario Data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param alias: alias of sought Unregistered Company
    :type alias: str
    :return: an UnregisteredCompany named tuple
    :rtype tests.functional.features.ScenarioData.UnregisteredCompany
    """
    return self.scenario_data.unregistered_companies[alias]


def patch_context(context):
    """Will patch the Behave's `context` object with some handy functions.

    Adds methods that allow to easily get & add data from/to Scenario Data.

    :param context: behave `context` object
    :type context: behave.runner.Context
    """
    context.add_actor = MethodType(add_actor, context)
    context.get_actor = MethodType(get_actor, context)
    context.reset_actor_session = MethodType(reset_actor_session, context)
    context.set_actor_csrfmiddlewaretoken = MethodType(
        set_actor_csrfmiddlewaretoken, context)
    context.set_actor_email_confirmation_link = MethodType(
        set_actor_email_confirmation_link, context)
    context.add_unregistered_company = MethodType(
        add_unregistered_company, context)
    context.get_unregistered_company = MethodType(
        get_unregistered_company, context)
