# -*- coding: utf-8 -*-
"""FAB Given step definitions."""
import logging

from behave.runner import Context
from requests import Response
from retrying import retry

from tests.functional.features.pages import (
    fab_ui_build_profile_basic,
    fab_ui_edit_online_profiles,
    fab_ui_profile,
    fab_ui_try_other_services,
    fas_ui_profile,
    profile_ui_landing,
    sso_ui_verify_your_email
)
from tests.functional.features.utils import (
    check_hash_of_remote_file,
    extract_csrf_middleware_token,
    extract_logo_url,
    get_verification_link
)


def reg_sso_account_should_be_created(response: Response, supplier_alias: str):
    """Will verify if SSO account was successfully created.

    Note:
    It's a very crude check, as it will only check if the response body
    contains selected phrases.

    :param response: response object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    sso_ui_verify_your_email.should_be_here(response)
    logging.debug("Successfully created new SSO account for %s", supplier_alias)


@retry(wait_fixed=5000, stop_max_attempt_number=18)
def reg_should_get_verification_email(context: Context, alias: str):
    """Will check if the Supplier received an email verification message.

    NOTE:
    The check is done by attempting to find a file with the email is Amazon S3.

    :param context: behave `context` object
    :param alias: alias of the Actor used in the scope of the scenario
    """
    logging.debug("Searching for an email verification message...")
    actor = context.get_actor(alias)
    link = get_verification_link(actor.email)
    context.set_actor_email_confirmation_link(alias, link)


def bp_should_be_prompted_to_build_your_profile(
        context: Context, supplier_alias: str):
    fab_ui_build_profile_basic.should_be_here(context.response)
    logging.debug(
        "%s is on the 'Build and improve your profile' page", supplier_alias)
    token = extract_csrf_middleware_token(context.response)
    context.set_actor_csrfmiddlewaretoken(supplier_alias, token)


def prof_should_be_on_profile_page(response: Response, supplier_alias: str):
    fab_ui_profile.should_be_here(response)
    logging.debug("%s is on the company profile page", supplier_alias)


def prof_should_be_told_about_missing_description(
        response: Response, supplier_alias: str):
    fab_ui_profile.should_see_missing_description(response)
    logging.debug("%s was told about missing description", supplier_alias)


def fas_should_be_on_profile_page(context, supplier_alias, company_alias):
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    fas_ui_profile.should_be_here(context.response, number=company.number)
    logging.debug(
        "%s is on the %s company's FAS page", supplier_alias, company_alias)


def fas_check_profiles(context: Context, supplier_alias: str):
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    # Step 1 - go to company's profile page on FAS
    response = fas_ui_profile.go_to(actor.session, company.number)
    context.response = response
    # Step 2 - check if links to online profile are visible
    fas_ui_profile.should_see_online_profiles(company, response)
    logging.debug("%s can see all expected links to Online Profiles on "
                  "FAS Company's Directory Profile Page", supplier_alias)


def reg_supplier_is_not_appropriate_for_fab(
        context: Context, supplier_alias: str):
    fab_ui_try_other_services.should_be_here(context.response)
    logging.debug("%s was told that her/his business is not appropriate "
                  "to feature in the Find a Buyer service", supplier_alias)


def reg_supplier_has_to_verify_email_first(
        context: Context, supplier_alias: str):
    sso_ui_verify_your_email.should_be_here(context.response)
    logging.debug("%s was told that her/his email address has to be verified "
                  "first before being able to Sign In", supplier_alias)


def sso_should_be_signed_in_to_sso_account(
        context: Context, supplier_alias: str):
    response = context.response
    assert response.cookies.get("sessionid") is not None
    assert "Sign out" in response.content.decode("utf-8")
    logging.debug("%s is logged in to the SSO account".format(supplier_alias))


def prof_should_be_told_about_invalid_links(
        context: Context, supplier_alias: str):
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)

    facebook = True if company.facebook else False
    linkedin = True if company.linkedin else False
    twitter = True if company.twitter else False

    fab_ui_edit_online_profiles.should_see_errors(
        context.response, facebook=facebook, linkedin=linkedin,
        twitter=twitter)
    logging.debug(
        "%s was not able to set Company's Online Profile links using invalid "
        "URLs to: %s %s %s", supplier_alias, "Facebook" if facebook else "",
        "LinkedIn" if linkedin else "", "Twitter" if twitter else "")


def fab_should_see_all_case_studies(context: Context, supplier_alias: str):
    """Check if Supplier can see all case studies on FAB profile page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    actor = context.get_actor(supplier_alias)
    case_studies = context.get_company(actor.company_alias).case_studies
    fab_ui_profile.should_see_case_studies(case_studies, context.response)


def fas_should_see_all_case_studies(context: Context, supplier_alias: str):
    """Check if Supplier can see all case studies on FAS profile page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    actor = context.get_actor(supplier_alias)
    case_studies = context.get_company(actor.company_alias).case_studies
    fas_ui_profile.should_see_case_studies(case_studies, context.response)
    logging.debug("%s can see all %d Case Studies on FAS Company's "
                  "Directory Profile Page", supplier_alias, len(case_studies))


def prof_should_see_logo_picture(context: Context, supplier_alias: str):
    """Will check if Company's Logo visible on FAB profile page is the same as
    the uploaded one.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    logo_url = company.logo_url
    logo_hash = company.logo_hash
    logo_picture = company.logo_picture

    logging.debug("Fetching logo image visible on the %s's FAB profile page",
                  company.title)
    check_hash_of_remote_file(logo_hash, logo_url)
    logging.debug("The Logo visible on the %s's FAB profile page is the same "
                  "as uploaded %s", company.title, logo_picture)


def fas_should_see_logo_picture(context: Context, supplier_alias: str):
    """Will check if Company's Logo visible on FAS profile page is the same as
    the one uploaded on FAB.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    actor = context.get_actor(supplier_alias)
    session = actor.session
    company = context.get_company(actor.company_alias)
    logo_hash = company.logo_hash
    logo_url = company.logo_url
    logo_picture = company.logo_picture

    # Step 1 - Go to the FAS profile page & extract URL of visible logo image
    response = fas_ui_profile.go_to(session, company.number)
    context.response = response
    visible_logo_url = extract_logo_url(response)

    # Check if FAS shows the correct Logo image
    assert visible_logo_url == logo_url
    logging.debug("Fetching logo image visible on the %s's FAS profile page",
                  company.title)
    check_hash_of_remote_file(logo_hash, logo_url)
    logging.debug("The Logo visible on the %s's FAS profile page is the same "
                  "as uploaded %s", company.title, logo_picture)


def prof_all_unsupported_files_should_be_rejected(
        context: Context, supplier_alias: str):
    """Check if all unsupported files were rejected upon upload as company logo.

    NOTE:
    This require `context.rejections` to be set.
    It should be a list of bool values.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    assert hasattr(context, "rejections")
    assert all(context.rejections), (
        "Some of the uploaded files that should be marked as unsupported were "
        "actually accepted. Please check the logs for more details")
    logging.debug("All files of unsupported types uploaded by %s were rejected"
                  .format(supplier_alias))


def fab_should_see_online_profiles(context: Context, supplier_alias: str):
    """Check if Supplier can see all online Profiles on FAB Profile page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    response = context.response
    fab_ui_profile.should_see_online_profiles(company, response)


def fab_no_links_to_online_profiles_are_visible(
        context: Context, supplier_alias: str):
    """Supplier should't see any links to Online Profiles on FAB Profile page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    response = context.response
    fab_ui_profile.should_not_see_online_profiles(response)
    logging.debug(
        "%s cannot see links to Online Profiles on FAB Profile page",
        supplier_alias)


def fas_no_links_to_online_profiles_are_visible(
        context: Context, supplier_alias: str):
    """Supplier should't see any links to Online Profiles on FAS Profile page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    response = context.response
    fas_ui_profile.should_not_see_online_profiles(response)
    logging.debug(
        "%s cannot see links to Online Profiles on FAS Profile page",
        supplier_alias)


def fab_profile_is_verified(context: Context, supplier_alias: str):
    """Check if Supplier was told that Company's profile is verified.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    response = context.response
    fab_ui_profile.should_see_profile_is_verified(response)
    logging.debug("%s was told that the profile is verified.", supplier_alias)


def fab_should_see_company_details(context: Context, supplier_alias: str):
    """Supplier should see all expected Company details of FAB profile page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    response = context.response
    fab_ui_profile.should_see_details(company, response, context.table)
    logging.debug("%s can see all expected details are visible of FAB "
                  "Company's Directory Profile Page", supplier_alias)


def profile_supplier_should_be_on_landing_page(
        context: Context, supplier_alias: str):
    """Check if Supplier is on Profile Landing page.

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    """
    response = context.response
    profile_ui_landing.should_be_here(response)
    logging.debug("%s got to the SSO landing page.", supplier_alias)
