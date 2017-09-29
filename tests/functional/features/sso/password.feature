Feature: SSO password management


    @ED-2146
    @sso
    @account
    @manage
    @password
    Scenario: Suppliers without FAB profile should receive a message with password reset link
      Given "Peter Alder" has a verified standalone SSO/great.gov.uk account
      And "Peter Alder" is signed out from SSO/great.gov.uk account

      When "Peter Alder" resets the password

      Then "Peter Alder" should be told that password was reset
      And "Peter Alder" should receive a password reset email
