Feature: SUD (Profile) pages


    @ED-2265
    @sso
    @account
    @no-sso-email-verification-required
    Scenario: Users should be able to view SUD Landing page without authentication
      Given "Peter Alder" is an unauthenticated supplier

      When "Peter Alder" goes to "SUD Landing" page

      Then "Peter Alder" should see "SUD Landing" page


    @ED-2266
    @sso
    @account
    @no-sso-email-verification-required
    Scenario Outline: Users who visited SUD landing page should not be able to view "<other SUD>" page without authentication
      Given "Peter Alder" is an unauthenticated supplier

      When "Peter Alder" goes to "SUD Landing" page
      And "Peter Alder" goes to "<other SUD>" page

      Then "Peter Alder" should see "SSO Login" page

      Examples: SUD pages
        |other SUD                  |
        |SUD Export Opportunities   |
        |SUD Find a Buyer           |
        |SUD Selling Online Overseas|


    @ED-2266
    @sso
    @account
    @bug
    @ED-2268
    @fixme
    @no-sso-email-verification-required
    Scenario Outline: Users who visit "<SUD>" page for the first time should be redirected to SSO Login page
      Given "Peter Alder" is an unauthenticated supplier

      When "Peter Alder" goes to "<SUD>" page

      Then "Peter Alder" should see "SSO Login" page

      Examples: SUD pages
        |SUD                        |
        |SUD Export Opportunities   |
        |SUD Find a Buyer           |
        |SUD Selling Online Overseas|


    @ED-2267
    @sso
    @account
    @fake-sso-email-verification
    Scenario: Authenticated Users should be able to view SUD sub-pages
      Given "Peter Alder" has a verified standalone SSO/great.gov.uk account

      When "Peter Alder" goes to specific pages
        |page name                  |
        |SUD Export Opportunities   |
        |SUD Find a Buyer           |
        |SUD Selling Online Overseas|

      Then "Peter Alder" should be able to see all selected pages
