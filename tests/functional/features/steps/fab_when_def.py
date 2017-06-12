# -*- coding: utf-8 -*-
"""FAB Given step definitions."""
from behave import when

from tests.functional.features.steps.fab_when_impl import select_random_company


@when("the supplier randomly selects an active company without a profile "
      "identified by an alias '{alias}'")
def step_impl(context, alias):
    select_random_company(context, alias)
