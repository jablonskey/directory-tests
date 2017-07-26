@wip
@skip
Feature: Search


  @ED-1746
  @fas
  @case-study
  @profile
  @verified
  @published
  @two-actors
  Scenario: Buyers should be able to find Supplier by uniquely identifying words present on Supplier's case study
    Given "Annette Geissinger" is a buyer
    And "Peter Alder" is an unauthenticated supplier
    And "Peter Alder" has created and verified profile for randomly selected company "Y"

    When "Peter Alder" adds a complete case study called "no 1" with unique keywords

    Then "Annette Geissinger" should be able to find company "Y" on FAS using words from case study "no 1"
      | search using case study's |
      | title                     |
      | summary                   |
      | description               |
      | caption 1                 |
      | caption 2                 |
      | caption 3                 |
      | testimonial               |
      | source name               |
      | source job                |
      | source company            |
      | website                   |
      | keywords                  |


  @ED-1746
  @fas
  @case-study
  @profile
  @verified
  @published
  Scenario: Buyers should be able to find Supplier by uniquely identifying words present on any of Supplier's case studies
    Given "Annette Geissinger" is a buyer
    And "Peter Alder" is an unauthenticated supplier
    And "Peter Alder" has created and verified profile for randomly selected company "Y"

    When "Peter Alder" adds a complete case study called "no 1" with unique keywords
    And "Peter Alder" adds a complete case study called "no 2" with unique keywords
    And "Peter Alder" adds a complete case study called "no 3" with unique keywords

    Then "Annette Geissinger" should be able to find company "Y" on FAS by using any unique word present on case study "no 1"
    And "Annette Geissinger" should be able to find company "Y" on FAS by using any unique word present on case study "no 2"
    And "Annette Geissinger" should be able to find company "Y" on FAS by using any unique word present on case study "no 3"


  @ED-1746
  @fas
  @case-study
  @profile
  @unverified
  @unpublished
  Scenario: Buyers should NOT be able to find unverified Supplier by uniquely identifying words present on Supplier's case study
    Given "Annette Geissinger" is a buyer
    And "Peter Alder" is an unauthenticated supplier
    And "Peter Alder" has created and unverified profile for randomly selected company "Y"

    When "Peter Alder" adds a complete case study called "no 1" with unique keywords

    Then "Annette Geissinger" should NOT be able to find company "Y" on FAS by using any unique word present on case study "no 1"
