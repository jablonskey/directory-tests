# -*- coding: utf-8 -*-
"""Behave configuration file."""
import logging

from tests.functional.features.context_utils import (
    initialize_scenario_data,
    patch_context
)
from tests.functional.features.db_cleanup import (
    delete_expired_django_sessions,
    delete_supplier_data
)
from tests.functional.features.utils import init_loggers


def before_step(context, step):
    logging.debug('Step: %s %s', step.step_type, str(repr(step.name)))


def after_step(context, step):
    logging.debug(context.scenario_data)
    if step.status == "failed":
        logging.debug('Step "%s %s" has failed. Reason: "%s"', step.step_type,
                      step.name, step.exception)
        if hasattr(context, "response"):
            print("\nHere's the content of last recorded response:\n",
                  context.response.content.decode("utf-8"))
            logging.error("Here's the content of last recorded response:\n%s",
                          context.response.content.decode("utf-8"))


def before_scenario(context, scenario):
    logging.debug('Starting scenario: %s', scenario.name)
    # re-initialize the scenario data
    context.scenario_data = initialize_scenario_data()


def after_scenario(context, scenario):
    logging.debug("Deleting supplier data from FAB & SSO DBs")
    actors = context.scenario_data.actors
    for actor in actors.values():
        delete_supplier_data("DIRECTORY", actor.email)
    for actor in actors.values():
        delete_supplier_data("SSO", actor.email)
    # clear the scenario data after every scenario
    context.scenario_data = None
    logging.debug('Finished scenario: %s', scenario.name)


def before_all(context):
    init_loggers(context)
    # this will add some handy functions to the `context` object
    patch_context(context)


def after_all(context):
    delete_expired_django_sessions()
