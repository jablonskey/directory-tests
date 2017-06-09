# -*- coding: utf-8 -*-
"""Contains named tuple that are used to create the Scenario Data."""
import logging
import types

from collections import namedtuple


ScenarioData = namedtuple('ScenarioData', ['actors'])
Actor = namedtuple('Actor', ['alias', 'http_client'])


def initialize_scenario_data():
    """Will initialize the Scenario Data.

    :return an empty ScenarioData named tuple
    :rtype ScenarioData
    """
    actors = []
    scenario_data = ScenarioData(actors=actors)
    return scenario_data


def add_actor(self, actor):
    """Will add Actor to Scenario Data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param actor: an instance of Actor Named Tuple
    :type actor: features.ScenarioData.Actor
    """
    assert isinstance(actor, Actor), ("Expected Actor named tuple but got '{}' "
                                      "instead".format(type(actor)))
    self.scenario_data.actors.append(actor)
    logging.debug("Successfully added actor: {} to Scenario Data"
                  .format(actor.alias))


def get_actor(self, alias):
    """Get actor details from context scenario data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param alias: alias of sought actor
    :type alias: str
    :return: an Actor named tuple
    """
    res = None
    for actor in self.scenario_data.actors:
        if actor.alias == alias:
            res = actor
            logging.debug("Found actor: '{}' in Scenario Data".format(alias))
    assert res is not None, ("Couldn't find actor '{}' in Scenario Data"
                             .format(alias))
    return res


def get_actor_client(self, alias):
    """Get actor's HTTP client from context scenario data.

    :param self: behave `context` object
    :type self: behave.runner.Context
    :param alias: alias of sought actor
    :type alias: str
    :return: Actor's HTTP client
    """
    actor = self.get_actor(alias)
    assert actor.http_client is not None, ("{}'s HTTP client is not set!"
                                           .format(alias))
    return actor.http_client


def patch_context(context):
    """Will patch the Behave's `context` object with some handy functions.

    This will add methods that allow to easily access Scenario Data.

    :param context: Behave context object
    """
    context.add_actor = types.MethodType(add_actor, context)
    context.get_actor = types.MethodType(get_actor, context)
    context.get_actor_client = types.MethodType(get_actor_client, context)

