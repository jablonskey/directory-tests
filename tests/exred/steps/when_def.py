# -*- coding: utf-8 -*-
"""When step definitions."""
from behave import when

from steps.then_impl import triage_should_be_classified_as
from steps.when_impl import (
    articles_go_back_to_article_list,
    articles_open_any,
    articles_open_any_but_the_last,
    export_readiness_open_category,
    guidance_open_category,
    guidance_read_through_all_articles,
    personalised_journey_create_page,
    start_triage,
    triage_are_you_incorporated,
    triage_change_answers,
    triage_create_exporting_journey,
    triage_do_you_export_regularly,
    triage_have_you_exported_before,
    triage_say_what_do_you_want_to_export,
    triage_say_whether_you_use_online_marketplaces,
    triage_should_see_answers_to_questions,
    triage_what_is_your_company_name
)


@when('"{actor_alias}" decides to continue in Exporting journey section')
@when('"{actor_alias}" decides to get started in Exporting journey section')
def when_actor_starts_triage(context, actor_alias):
    start_triage(context, actor_alias)


@when('"{actor_alias}" goes to the "{category}" Guidance articles via "{location}"')
def when_actor_goes_to_guidance_articles(
        context, actor_alias, category, location):
    guidance_open_category(context, actor_alias, category, location)


@when('"{actor_alias}" creates a personalised journey page for herself')
def when_actor_creates_personalised_journey_page(context, actor_alias):
    personalised_journey_create_page(context, actor_alias)


@when('"{actor_alias}" says what does he wants to export')
@when('"{actor_alias}" says what does she wants to export')
def when_actor_says_what_he_wants_to_export(context, actor_alias):
    triage_say_what_do_you_want_to_export(context, actor_alias)


@when('"{actor_alias}" says that he "{has_or_has_never}" exported before')
@when('"{actor_alias}" says that she "{has_or_has_never}" exported before')
def when_actor_answers_whether_he_exported_before(
        context, actor_alias, has_or_has_never):
    triage_have_you_exported_before(context, actor_alias, has_or_has_never)


@when('"{actor_alias}" says that exporting is "{regular_or_not}" part of her business')
@when('"{actor_alias}" says that exporting is "{regular_or_not}" part of his business')
def when_actor_tells_whether_he_exports_regularly_or_not(
        context, actor_alias, regular_or_not):
    triage_do_you_export_regularly(context, actor_alias, regular_or_not)


@when('"{actor_alias}" says that her company "{is_or_not}" incorporated')
@when('"{actor_alias}" says that his company "{is_or_not}" incorporated')
def when_actor_says_whether_company_is_incorporated(
        context, actor_alias, is_or_not):
    triage_are_you_incorporated(context, actor_alias, is_or_not)


@when('"{actor_alias}" "{decision}" her company name')
@when('"{actor_alias}" "{decision}" his company name')
def when_actor_decide_to_enter_company_name(context, actor_alias, decision):
    triage_what_is_your_company_name(context, actor_alias, decision)


@when('"{actor_alias}" sees the summary page with answers to the questions he was asked')
@when('"{actor_alias}" sees the summary page with answers to the questions she was asked')
def when_actor_sees_answers_to_the_questions(context, actor_alias):
    triage_should_see_answers_to_questions(context, actor_alias)


@when('"{actor_alias}" decides to create her personalised journey page')
@when('"{actor_alias}" decides to create his personalised journey page')
def when_actor_decides_to_create_personalised_page(context, actor_alias):
    triage_create_exporting_journey(context, actor_alias)


@when('"{actor_alias}" can see that he was classified as a "{classification}" exporter')
@when('"{actor_alias}" can see that she was classified as a "{classification}" exporter')
def when_actor_is_classified_as(context, actor_alias, classification):
    triage_should_be_classified_as(context, actor_alias, classification)


@when('"{actor_alias}" says that she "{decision}" used online marketplaces')
def when_actor_says_whether_he_used_online_marktet_places(
        context, actor_alias, decision):
    triage_say_whether_you_use_online_marketplaces(
        context, actor_alias, decision)


@when('"{actor_alias}" decides to change her answers')
@when('"{actor_alias}" decides to change his answers')
def when_actor_decides_to_change_the_answers(context, actor_alias):
    triage_change_answers(context, actor_alias)


@when('"{actor_alias}" goes to the Export Readiness Articles for "{category}" Exporters via "{location}"')
def when_actor_goes_to_exred_articles(context, actor_alias, category, location):
    export_readiness_open_category(context, actor_alias, category, location)


@when('"{actor_alias}" decides to read through all Articles from selected list')
def when_actor_reads_through_all_guidance_articles(context, actor_alias):
    guidance_read_through_all_articles(context, actor_alias)


@when('"{actor_alias}" opens any Article but the last one')
def when_actor_opens_any_article_but_the_last_one(context, actor_alias):
    articles_open_any_but_the_last(context, actor_alias)


@when('"{actor_alias}" decides to read through all remaining Articles from selected list')
def when_actor_reads_through_all_remaining_articles(context, actor_alias):
    guidance_read_through_all_articles(context, actor_alias)


@when('"{actor_alias}" opens any article on the list')
def given_actor_opens_any_article(context, actor_alias):
    articles_open_any(context, actor_alias)


@when('"{actor_alias}" goes back to the Article List page')
def when_actor_goes_back_to_article_list(context, actor_alias):
    articles_go_back_to_article_list(context, actor_alias)
