<h1 id='table-of-contents'>Table of Contents</h1>

- [OWASP](#owasp)
  - [OWASP TOP 10: What's New](#owasp-top-10-whats-new)
  - [Data Sources for the Top 10](#data-sources-for-the-top-10)
  - [Understanding Category Metrics](#understanding-category-metrics)
    - [Common Weaknesses Enumeration (`CWE`) Mapped](#common-weaknesses-enumeration-cwe-mapped)
    - [Max Incidence Rate](#max-incidence-rate)
    - [Average Incidence Rate](#average-incidence-rate)
    - [Average Weighted Exploit](#average-weighted-exploit)
    - [Average Weighted Impact](#average-weighted-impact)
    - [Max Coverage](#max-coverage)
    - [Average Coverage](#average-coverage)
    - [Total Occurrences](#total-occurrences)
    - [Total `CVEs` (Common Vulnerabilities Enumeration)](#total-cves-common-vulnerabilities-enumeration)
  - [Top 10 Categories](#top-10-categories)
    - [1st - Broken Access Control](#1st---broken-access-control)
    - [2nd - Cryptographic Failures](#2nd---cryptographic-failures)
    - [3rd - Injection](#3rd---injection)
    - [4th - Insecure Design](#4th---insecure-design)
    - [5th - Security](#5th---security)

# OWASP

## OWASP TOP 10: What's New

What is the difference between Top 10 2017 and 2021?

- Data collection
  - Comes from application security organizations
  - 8 categories chosen base on data (logs)
    - Historical data
  - 2 Categories based on survey
    - Forward looking

## Data Sources for the Top 10

Previous course `Play by Play: OWASP Top 10 2017`

**Category Metrics**

Metrics in the 2017 top 10

- Scored out of 3

  - Exploitability
  - Prevalence
  - Detectability
  - Technical Impact

Metrics in the 2021 top 10

- More accurate
- More useful to some rules

## Understanding Category Metrics

### Common Weaknesses Enumeration (`CWE`) Mapped

These are the common ways a software can be consider weak

- Weakness can lead to vulnerabilities
- Average of 20 `CWEs` per category
  - Maximum of 40 weakness
  - Minimum of 1 weakness

The `CWEs` show you the root cause for vulnerabilities, that make it easier to find the vulnerabilities and gives a much deeper understanding of the problems faced

- Deeper understanding of the category
- Effort required to defend

### Max Incidence Rate

- Helps decide if a category is in the top 10
- Incidence rate

  - `%` of tested applications with a vulnerability
  - Not the number of instances

  > That's a count of the number of vulnerable applications and not a count of the individual instances of a vulnerability.

- Maximum incidence

  - Highest % from an organisation
  - Broken access control - **55.97%**
  - Server-side request forgery (`SSRF`) - **2.72%**

  > The maximum incidence rate is therefore the highest incidence rate that was present in the data from a single organisation supplying that data.

### Average Incidence Rate

The average indication rate is a better judge of how often applications are likely to have a vulnerability found in them

- A better guide than maximum
- Average incident across data providers
- Average incidence
  - Vulnerable and outdated components = **8.77%**
  - Software and data integrity failures - **2.05%**

### Average Weighted Exploit

The weight exploit comes from the `Common Vulnerability Scoring System` (`CVSS`)

`CVSS` is a method of scoring a vulnerability to access the risk it presents, and some of the data that goes into the calculation helps to access how easy it might be to exploit it.

- Assess the risk of a vulnerability
- Contains exploitability elements
- Vulnerabilities are linked to `CWEs`

  - `CWEs` are linked with categories

    - Gives a score out of 10
      - Sever-side request forgery - **8.28**
      - Vunerable and outdated components - **5.0**

    > 10 being the worst

> The exploit data is taken from documented vulnerabilities

### Average Weighted Impact

The average weighted impact is similar to the average weighted exploit.

The `CVSS` scores also have data relating to the impact a vulnerability

- `CVSS` impact elements
  - Confidentiality
  - Integrity
  - Availability

This data is used the same way to get a score out of 10

- Software and Data Integrity Failures - **7.94**
- Security Logging and Monitoring Failures - **4.99**

### Max Coverage

Coverage is all about how often application were tested for specific `CWEs`

Tests on application aren't always performed in the same way and some tests rely on automation, which may be great at checking for some common weaknesses, but can't test for others.

This metric is an indication of how common it is to test for `CWEs` in a category.

The maximum coverage is therefore the largest figure of coverage that came from a single data provider.

- Are application tested for `CWEs`?
- How common is it to test for them?
- Max coverage
  - Largest coverage from a single data provider

Data isn't presented per `CWE`, simply per category, which covers multiple `CWEs`, but rumor has it that data per `CWE` will be made available at some point.

- Broken access control - **94.55%**
- Vulnerable and outdated components - **51.78%**

### Average Coverage

The maximum coverage is giving us data for a potential outlier, so the average coverage is going to give us a much better view of how often the `CWEs` in a category are tested for.

- Max coverage is potentially an outlier
- Average coverage gives a better view

  - An average from all data suppliers

- Server-side request forgery (`SSRF`) - **67.72%**
- Vulnerable and outdated components - **22.47%**

### Total Occurrences

Total occurrences is the number of tested applications that were found to have `CWEs` from that category.

From the data, out of all applications tested by companies providing the data:

- Broken access control - **318,487** applications
- Server-side request forgery (`SSRF`) - **9,503** applications

### Total `CVEs` (Common Vulnerabilities Enumeration)

- Common Vulnerabilities Enumeration (`CVE`)
- `CVEs` mapped to `CWEs`

Total `CVEs` is from the `Common Vulnerabilities Enumeration`, which lists publicly known vulnerabilities found in applications.

This shows the number of `CVEs` that are mapped to `CWEs` in this category. It gives an idea of how common the `CWEs` in a category are.

- Injection - **32,078**
- Vulnerable and outdated components - **0**

## Top 10 Categories

### 1st - Broken Access Control

- Previous placed 5th (2017)
- Access control is all about controlling what a user has access to.

**Horizontal access**

- Stops user from accessing belonging to other users.

**Vertical access**

- Stop users from accessing data and functionality belonging to users at different permission levels such as admin access.
- This is mapped to an above average `34 CWEs` (average 19.6), and as a result by far the most total occurrences, with over **381,000** of the tested applications having a broken access control.

### 2nd - Cryptographic Failures

- It was previously known as `Sensitive Data Exposure`
- That was deemed to be exposure of data which largely came from cryptographic Failures
- Those failures can be varied, as we've got `29 CWEs` (average 19.6)
- The `CWEs` for this mostly come into three distinct categories:
  - In transit failures, so failings around using secure connections such as `TLS`, and the potential failures that can happen around that, like downgrade attacks and weak ciphers.
  - Passwords, `CWEs` like use of one-way hash without a salt and reversible one-way, so ensuring passwords are stored suitable ways to protect them
  - Implementation of cryptography, and covers areas like insufficient entropy and not using random initialization vector, which can be a common implementation problems.

### 3rd - Injection

- Injection has been the number one problem since 2010
- Today is the number 3, which is a reflection of improvements in tooling and education around this subject.
- Often people largely associate this category with SQL injection, the ability of an attacker to modify commands sent to a database, but there's a lot more to it than that.
  - SQL injection is just one of the 33 common `CWEs`
  - Others include operating system command injection, allowing an attacker to send their own commands to the operating system
  - Lightweight directory access protocol (`LDAP`), meaning commands can be sent to services like `Microsoft's Active Directory`
- Cross-site scripting (`XSS`)

  - Cross-site scripting allows an attacker to manipulate and scripting to a web page.

- Total occurrences at **274,000** (average 157,103), and the highest number of `CVEs` at **32.000** (average 6,332)

### 4th - Insecure Design

- It has the most `CWEs` associated with it, coming in at `40 CWEs` (average 19.6)
- It has a lot of failures in the design process often just means little or no thought to design, which can happen for a variety of reasons

### 5th - Security

- Misconfiguration was at number 6 in 2017
- It's got `20 CWEs` (average 19.6) mapped to it, which is the average of all the categories.
- Historically, we've seen a push to have secure defaults on software being used, so they should default to a relatively secure configuration.
- Configuration can be complex
- Improper Restrictions of XML External Entities (`XXE`)
- Password in Configuration File, this entry has the highest average weighted exploit with 8.12
