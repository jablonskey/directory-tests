Feature: Promoted industries

  @ED-2013
  @industries
  @no-sso-email-verification-required
  Scenario: Buyers should be able to view page with promoted Industries
    Given "Annette Geissinger" is a buyer

    When "Annette Geissinger" goes to "FAS Industries" page

    Then "Annette Geissinger" should see sections with selected industries
      | industry       |
      | Health         |
      | Tech           |
      | Creative       |
      | Food and drink |


  @ED-2015
  @industries
  @no-sso-email-verification-required
  Scenario Outline: Buyers should be able to find out more about every promoted industry - visit "<selected>" page
    Given "Annette Geissinger" is a buyer

    When "Annette Geissinger" goes to "<selected>" page

    Then "Annette Geissinger" should see "<selected>" page

    Examples:
      | selected                            |
      | FAS Health Industry                 |
      | FAS Tech Industry                   |
      | FAS Creative Industry               |
      | FAS Food and drink Industry         |
      | FAS Health Industry Summary         |
      | FAS Tech Industry Summary           |
      | FAS Creative Industry Summary       |
      | FAS Food and drink Industry Summary |


  @ED-2016
  @industries
  @no-sso-email-verification-required
  Scenario Outline: Buyers should be able to find UK Suppliers by industries associated with promoted Case Study on "<selected>" page
    Given "Annette Geissinger" is a buyer
    And "Annette Geissinger" is on the "<selected>" page

    When "Annette Geissinger" follows all the links to industries associated with the case study from the Company Showcase

    Then "Annette Geissinger" should see search results filtered by appropriate sectors

    Examples:
      | selected                            |
      | FAS Health Industry                 |
      | FAS Tech Industry                   |
      | FAS Creative Industry               |
      | FAS Food and drink Industry         |
      | FAS Health Industry Summary         |
      | FAS Tech Industry Summary           |
      | FAS Creative Industry Summary       |
      | FAS Food and drink Industry Summary |
