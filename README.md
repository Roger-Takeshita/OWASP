<h1 id='table-of-contents'>Table of Contents</h1>

- [Open Web Application Security Project - OWASP](#open-web-application-security-project---owasp)
  - [Links](#links)
- [OWASP Top 10: API Security Playbook](#owasp-top-10-api-security-playbook)
  - [OWASP TOP 10: What's New](#owasp-top-10-whats-new)
  - [Data Sources for the Top 10](#data-sources-for-the-top-10)
  - [Understanding Category Metrics](#understanding-category-metrics)
    - [Common Weaknesses Enumeration (CWE) Mapped](#common-weaknesses-enumeration-cwe-mapped)
    - [Max Incidence Rate](#max-incidence-rate)
    - [Average Incidence Rate](#average-incidence-rate)
    - [Average Weighted Exploit](#average-weighted-exploit)
    - [Average Weighted Impact](#average-weighted-impact)
    - [Max Coverage](#max-coverage)
    - [Average Coverage](#average-coverage)
    - [Total Occurrences](#total-occurrences)
    - [Total CVEs (Common Vulnerabilities Enumeration)](#total-cves-common-vulnerabilities-enumeration)
  - [Top 10 Categories](#top-10-categories)
    - [1st - Broken Access Control](#1st---broken-access-control)
    - [2nd - Cryptographic Failures](#2nd---cryptographic-failures)
    - [3rd - Injection](#3rd---injection)
    - [4th - Insecure Design](#4th---insecure-design)
    - [5th - Security](#5th---security)
    - [6th - Vulnerable and Outdated Components](#6th---vulnerable-and-outdated-components)
    - [7th - Identification and Authentication Failures](#7th---identification-and-authentication-failures)
    - [8th - Software and Data Integrity Failures](#8th---software-and-data-integrity-failures)
    - [9th - Security Logging and Monitoring Failures](#9th---security-logging-and-monitoring-failures)
    - [10th - Server-Side Request Forgery (SSRF)](#10th---server-side-request-forgery-ssrf)
    - [Beyond Top 10 (3 Additional)](#beyond-top-10-3-additional)
      - [Code Quality Issues](#code-quality-issues)
      - [Denial of Service (DoS)](#denial-of-service-dos)
      - [Memory Management Errors](#memory-management-errors)
  - [New Categories in the Top 10](#new-categories-in-the-top-10)
    - [Understanding Insecure Design](#understanding-insecure-design)
      - [Impact](#impact)
      - [Defense](#defense)
    - [Software and Data Integrity Failures](#software-and-data-integrity-failures)
      - [Impact](#impact-1)
      - [Defense](#defense-1)
    - [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
      - [Impact](#impact-2)
      - [Defense](#defense-2)
  - [The Effect on Security Roles](#the-effect-on-security-roles)
    - [Security Architecture and Engine](#security-architecture-and-engine)
      - [Insecure Design](#insecure-design)
      - [Software and Data Integrity Failures](#software-and-data-integrity-failures-1)
      - [Server-Side Request Forgery](#server-side-request-forgery)
    - [Risk Management](#risk-management)
      - [Governance](#governance)
      - [Risk](#risk)
      - [Compliance](#compliance)
    - [Defense](#defense-3)
      - [Insecure Design](#insecure-design-1)
      - [Software and Data Integrity Failures](#software-and-data-integrity-failures-2)
      - [Server-Side Request Forgery](#server-side-request-forgery-1)
    - [Penetration Testing](#penetration-testing)
      - [offensive Security](#offensive-security)
      - [Web Application Penetration Testing](#web-application-penetration-testing)
      - [Network Penetration Testing](#network-penetration-testing)
    - [Red Teaming](#red-teaming)
- [OWASP Top 10: API Security Playbook](#owasp-top-10-api-security-playbook-1)
  - [Broken Object Level Authorization](#broken-object-level-authorization)
    - [Attacking](#attacking)
    - [Defense 1](#defense-1)
    - [Defense 2](#defense-2)
  - [Broken User Authentication](#broken-user-authentication)
    - [Understanding Broken Authorization](#understanding-broken-authorization)
      - [Authentication Components](#authentication-components)
    - [Insecure Password Storage](#insecure-password-storage)
    - [Credential Stuffing](#credential-stuffing)
    - [JSON Web Token (JWT)](#json-web-token-jwt)
    - [API Keys](#api-keys)
  - [Excessive Data Exposure](#excessive-data-exposure)
    - [Attack](#attack)
    - [Defense](#defense-4)
  - [Lack of Resources and Rate Limiting](#lack-of-resources-and-rate-limiting)
    - [Attack](#attack-1)
    - [Rate Limiting Risks](#rate-limiting-risks)
    - [Rate Limiting Defense](#rate-limiting-defense)
  - [Broken Function Level Authorization](#broken-function-level-authorization)
    - [Attack](#attack-2)
    - [Defense](#defense-5)
  - [Mass Assignment](#mass-assignment)
    - [Attack](#attack-3)
    - [Defense](#defense-6)
  - [Security Misconfiguration](#security-misconfiguration)
    - [CORS](#cors)
    - [Common Security Misconfiguration](#common-security-misconfiguration)
  - [Injection](#injection)
    - [Attack](#attack-4)
    - [Injection Risks](#injection-risks)
    - [Injection Defenses](#injection-defenses)
  - [Improper Assets Management](#improper-assets-management)
    - [Attack](#attack-5)
    - [Defense](#defense-7)
  - [Insufficient Logging and Monitoring](#insufficient-logging-and-monitoring)
    - [Effects of Insufficient Logging](#effects-of-insufficient-logging)
    - [Defense](#defense-8)

# Open Web Application Security Project - OWASP

## Links

- [OWASP Top 10: What's New](https://app.pluralsight.com/library/courses/owasp-top-ten-whats-new/table-of-contents)
- [OWASP Top 10: What's New Badge](https://app.pluralsight.com/achievements/share/c1d4ca60-3733-4e15-a0ce-18ebecb37669)

- [OWASP Top 10: API Security Playbook](https://app.pluralsight.com/library/courses/owasp-top-ten-api-security-playbook)
- [OWASP Top 10: API Security Playbook Badge](https://app.pluralsight.com/achievements/share/aa661f13-b290-426b-9da6-3df3bacb402e)

# OWASP Top 10: API Security Playbook

## OWASP TOP 10: What's New

What is the difference between Top 10 2017 and 2021?

- Data collection
  - Comes from application security organizations
  - 8 categories chosen base on data (logs)
    - Historical data
  - 2 Categories based on survey
    - Forward looking

Focuses on underlying Issues

- This should be reflected in software development

Metrics

- Creates a better understanding of issues

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

### Common Weaknesses Enumeration (CWE) Mapped

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
  - Server-Side Request Forgery (`SSRF`) - **2.72%**

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

- Server-Side Request Forgery (`SSRF`) - **67.72%**
- Vulnerable and outdated components - **22.47%**

### Total Occurrences

Total occurrences is the number of tested applications that were found to have `CWEs` from that category.

From the data, out of all applications tested by companies providing the data:

- Broken access control - **318,487** applications
- Server-Side Request Forgery (`SSRF`) - **9,503** applications

### Total CVEs (Common Vulnerabilities Enumeration)

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

### 6th - Vulnerable and Outdated Components

- Comes from community survey (not data)
  - That means the security community see it as important even though the historical data doesn't match the sentiment.
- This category is also a bit of an odd one out from the data perspective, although that's reasonable given it came from the community survey. This is the only entry with no `CVE` mappings. Really, that means that while using vulnerable and outdated components is clearly a problem, `CVE` data reflects individual vulnerabilities. `0 CVE` (average 6,332)
- It doesn't reflect usage of vulnerable components, which is why we see no `CVEs`. That also means that the figures for exploitability and impact are defaulted to **5**, which means there's no data to form a basis for them.
- There is only `3CWEs` (average 19.6) mapped to it, which is well below the average, and there are no `CVEs` directly mapped to those.
- This category focuses on keeping software and components up to date, especially when there are publicly known vulnerabilities associated to them.

### 7th - Identification and Authentication Failures

- It was previously know as `Broken Authentication`
- This focuses on pretty much anything to do with authentication. That's not just the process of logging in, but also weak password requirements, password recovery mechanisms, session fixation, session expiry, hard-coded credentials, and lots more.
- There are `22 CWEs` (average 19.6) common weakness mapped here in total.
- This is one also mentions the number 2 entry, `Crytographic Failures`, where poorly stored password also form part of authentication weaknesses. From the data perspective, it comes fairly close to average in all the categories, with the average incident rate, where it comes second bottom with **2.55%** of incident rate (average 4.18%)

### 8th - Software and Data Integrity Failures

- It was previously known as `Insecure Deserialization`
- Integrity violations are generally about trusting and data that comes from outside of a trust boundary, so we're thinking about entrusted sources of code, which can be third-party or open source applications. It also includes serialized data that could be manipulated by an attacker, but is trusted by default by the server.

### 9th - Security Logging and Monitoring Failures

- It was previously known as `insufficient Logging and Monitoring`
- Comes from the community survey (not data)
- The point of it was that by having insufficient logging and monitoring, you are more likely to miss an attack happening
  - That's known as a detective control
  - It helps you to understand what's happening after it happened. As an attacker, it's not something you could intentionally exploit.
- The new version now includes `CWEs` for improper output neutralization for logs, so could an attacker potentially inject something malicious into those logs.
- There's also insertion of sensitive information into a log, which can mean leaking sensitive information.
- I has the lowest average weighted impact with 4.99 (average 6.44), and is difficult to test for, giving the second lowest average coverage of **39.97%** (average 43.91).
- It also has the lowest number of `CVEs` at 242.

### 10th - Server-Side Request Forgery (SSRF)

- `SSRF` did actually make it into the `Additional risks to considre` in 2017
- It also comes from the community survey (not data)
- It's got only one associated common weakness
- `SSRF` focuses on client requests that then trigger requests from the server.
  - This potentially gives an attacker the ability to make arbitrary requests from the server, and that can mean gaining access to resources that can't be directly reached across the internet, but can be reached by the server.

### Beyond Top 10 (3 Additional)

#### Code Quality Issues

- Bad / insecure coding patterns, e.g.:
- Time of check / time of use (`TOCTOU`)
  - Where validation is performed on a value. If something alters the value after the validation but before the value is actually used, then the validation can be bypassed.
- It also covers memory error such as use after free, where a program keeps a pointer to memory that it's no longer using.
  - If an attacker can use that memory, they can execute their own code.

> Luckily, a lot of these problems can at least be easily highlighted by using `static code analysis` tools that look through code for these common mistakes.

#### Denial of Service (DoS)

- Can an attacker do something that will cause all or part of your website to no longer be usable?
- With enough load any website can fail
- Look at resources intensive areas
  - E.g. is a search function normally slow? Then this would be a good indication that it could be used to mount an attack.
  - Could that slow down the entire website?
- Perform load test to identify weaknesses

#### Memory Management Errors

- We're thinking about problems like buffer overflows that are traditionally associated with all the languages like C++, where it's far easier to make memory management mistakes.
- What about `.net`, `java`, `node.js` etc?
  - They are not perfect
  - There are often compiler flags that can weaken or strengthen them
  - Static code analysis that will highlight problems.

## New Categories in the Top 10

### Understanding Insecure Design

- Number 4 of the top 10
- 40 `CWEs`
- Not the cause of the other categories
- Design and architectural decisions
  - Insecure design is all about design an even architectural decisions made for a web application and its key components.
- Other categories are implementation issues
  - E.g. using a SQL database is by design
  - SQL injection is an implementation problem

**Insecure Design - Metrics**

| Item                     | Value   |
| ------------------------ | ------- |
| `CWEs` mapped            | 40      |
| Max incidence rate       | 24.19%  |
| Average incidence rate   | 3.00%   |
| Average weighted exploit | 6.46    |
| Average weighted impact  | 6.78    |
| Max coverage             | 77.25%  |
| Average coverage         | 42.51%  |
| Total occurrences        | 262,407 |
| Total `CVEs`             | 2,691   |

**Insecure Design - `CWEs`**

- `CWE-311` Missing encryption of sensitive data
  - Passwords stores in database not encrypted
  - Passwords sorted in cookies as plain text
- `CWE-522` Insufficient protected credentials
  - Credentials in configuration files
- `CWE-434` Unrestricted upload of files with dangerous type
  - Upload any file type
  - Could files be malicious?
- `CWE-598` Use of `GET` request method with sensitive query strings
- `CWE-602` Client-side enforcement of server-side security
- `CWE-656` Reliance on security through obscurity

#### Impact

It's very difficult to pin down exactly what the impact of getting this wrong would be.

- Large number of `CWEs` makes this complex
- It may take a lot of effort to fix

#### Defense

How do we ensure we have a secure design?

- Understand and use secure patterns
- Threat modeling
  - Assessing threats
  - Understanding defenses
- User stories
  - Consider if there's a security impact
- **Shift left**

### Software and Data Integrity Failures

- Various risky points for integrity
- Risks to Code
  - Code is being created and checked into a repository and there are lots of bad things that could happen to it, it's very common to need third-party libraries or plugins. You could write that functionality yourself, but that would take a lot of effort.
  - Free/open source/paid libraries, any of this could be compromised by an attacker before you start using it and it could be quiet difficult to known that.
  - Code being checked into your own repository could be given back doors or intentional vulnerabilities if members of the development team chose to act maliciously or perhaps their credentials were stolen.
    - CI/CD can be used to autonomously or semi-autonomously deploy web applications.
- Installing dependencies
- Dependency confusion

**Software and Data Integrity Failures - Metrics**

| Item                     | Value  |
| ------------------------ | ------ |
| `CWEs` mapped            | 10     |
| Max incidence rate       | 16.67% |
| Average incidence rate   | 2.05%  |
| Average weighted exploit | 6.94   |
| Average weighted impact  | 7.94   |
| Max coverage             | 75.04% |
| Average coverage         | 45.35% |
| Total occurrences        | 47,972 |
| Total `CVEs`             | 1,152  |

**Software and Data Integrity Failures - CWEs**

- `CWE-502` Deserialization of untrusted data
  - External `XML` entities (`XXE`)
- `CWE-345` Insufficient verification of data authenticity
  - Is data trusted?
- `CWE-829` Inclusion of functionality from untrusted control sphere
  - Content delivery network (`CND`)
  - Dependency confusion
- Do we trust data / third-party code?

#### Impact

- Highest average weighted Impact
- Often means remote code execution

#### Defense

- Digital signatures
  - Digital signatures are good for ensuring third-party software hasn't changed.
  - This works for installed software and is good for JavaScript packages too.
- Enforce code review
- Secure CI/CD environments
- Dependency check
  - Tools such as `OWASP Dependency-Check` are important to check for known vulnerabilities in libraries being used.
- Trusting third-party code is challenging
  - Every update is a potential risk, and all of these defenses help.
  - Waiting a period of time before using a new release could allow time for malicious code to be revealed, but then that goes against the advice to stay up to date.
  - Review every update yourself?

### Server-Side Request Forgery (SSRF)

The attacker can induce the application server to make a request that it wasn't intended to make.

**SSRF- Metrics**

| Item                     | Value  |
| ------------------------ | ------ |
| `CWEs` mapped            | 1      |
| Max incidence rate       | 2.72%  |
| Average incidence rate   | 2.72%  |
| Average weighted exploit | 8.28   |
| Average weighted impact  | 6.72   |
| Max coverage             | 67.72% |
| Average coverage         | 67.72% |
| Total occurrences        | 9,503  |
| Total `CVEs`             | 385    |

#### Impact

- Forged requests from the server
- Confidentiality breach
- Bypass controls e.g. firewalls
- Internal resources may have less controls

#### Defense

- Multi-layered approach
  - Is this the best design?
  - Input validation
    - Use an allow list
- Don't return the raw response
- Secure the server-side network

## The Effect on Security Roles

### Security Architecture and Engine

Security team looking at OWASP top 10

- Architecture and engineering
  - The staff here look at ensuring best practices are used across various aspects of the company's infrastructure.
- Governance, risk and compliance (`GRC`)
  - This team helps Globomantics to make sure it meets any regulatory and compliance needs, managing risks to the business and steering it through all of the associated complexities of cybersecurity.
- Offense
  - The offensive security team are responsible for testing that all of their software, on-premise infrastructure, and cloud infrastructure are as secured as they can be.
- Defense
  - The defensive area takes care of the business's environments, ensuring that malicious files, phishing attempts, and any other types of attacks are handle quickly and decisively.

Globomantics are the driving force behind creating technical solutions with security built in from the start.

They secure the company's IT and also work with development teams to create secure environments and develop security best practices.

#### Insecure Design

- Shift left
  - A lot of the cure for this problem is shifting left
    - Move secure design earlier in the process
    - Prevent wasted effort
    - Decrease complexity
- Threat modelling
  - Assess threats
  - Implement controls
- Move further left?
  - Use existing patterns
  - Create reproduceable components

#### Software and Data Integrity Failures

- Look at infrastructure
  - E.g. CI/CD pipelines
- What damage could an attacker do?
- Checks on third-party libraries?
  - Limited sources?
  - Consider an allow list of sources
- Dependency checking
  - Run in CI/CD, or regularly
- Check hashes
  - If the file hash of a DLL or JavaScript changes

#### Server-Side Request Forgery

- Web infrastructure needs increased focus
  - Web applications are becoming increasingly important. It needs suitable security to provide layered defenses
- Treat cloud environments like internal I.T.
  - Antivirus
  - SIEM (login)
  - Network segregation
  - Strong passwords
  - Multi-factor
- Ensure software is up to date
- Minimum surface area

### Risk Management

#### Governance

- Less focused on specific entries
- Focus on the top 10 as a whole
  - Impact on business strategy

#### Risk

- Assess likelihood of vulnerabilities
  - Average incidence
  - Total occurrences
- Assess exploitability
- Assess potential impact
- Where should attention be focused?
- Assist with risk calculations
- Coverage
- potentially more detail coming

#### Compliance

- Lots of standards, laws and regulations
- Some link with the `OWASP` top 10

**PCI Compliance**

- Processing credit card payments
- Payment card industry data security standard (`PCI-DSS`)
  - `OWASP` guide
- Vulnerability management program
- Strong access control
- Monitoring

**PCI PA-DSS** Payment Card Industry Payment Application Data Security Standard

- `PCI PA-DSS` is aimed at software developers.
- Also mentions `OWASP`
- Reiterates `PCI-DSS` points

> Secure coding techniques to avoid common coding vulnerabilities (for example, vendor guidelines, `OWASP` top 10...)

**Not a Standard**

- `OWASP` top 10 is not a standard
- Not all of it is testable
- Application Security Verification Standard (`ASVS`)
  - Also from `OWASP`
  - Is testable
  - Not tied to the top 10

**ISO 27001**

- Doesn't mention `OWASP`
- Continual improvements
  - Keep up to date
  - Awareness of updates
  - Apply information from them

**What Else?**

- Considerations differ per industry
- Important recognize changes
- See other coursers on compliance

### Defense

- Incident responders
- Treat hunters
- Security analysis
- Security logging and monitoring failures

#### Insecure Design

- It's a wide subject
- Common patterns of attack
  - Picked up by web applications firewalls (`WAFs`)
  - E.g. traversal - `../`
  - Large number of requests
- More common in less security mature teams
- Some issues hard to pick up with automation
- Rely on generic controls
  - Logging
  - Input validation
  - Noticing repeated failures

#### Software and Data Integrity Failures

- A problem before the live environment
- Dependency confusion:
  - Which libraries?
  - Which web application use them?
  - Likely malware infection
  - Outbound HTTP traffic
  - Should there only be inbound HTTP?
- Client-side JavaScript
  - Content security policy (`CSP`)
  - `CSP` sub-resource integrity (hashes)

#### Server-Side Request Forgery

- Typically follow a specific pattern
- Can be more complex to spot:
  - IP V4 - `127.0.0.1`
  - IP V6 - `::1`
  - Name - `localhost`
  - Decimal - `2130706433`
  - Hex - `0x7f000001`
  - `file:///etc/passwd`
- Logging is important
- Primarily a confidentiality breach

### Penetration Testing

#### offensive Security

- Web application penetration testing
  - `OWASP` top 10 is aimed to web applications
- Network penetration testing
  - Less focus on the `OWASP` top 10
- Red teaming
  - Elements of network and web application testing

#### Web Application Penetration Testing

- Testing checklist
  - Based on the 2017 `OWASP` top 10
- `CWEs` listed for each top 10 category
  - 196 common weakness in total
- Penetration test results
  - Top 10 has remediation advice
  - Useful references

#### Network Penetration Testing

- Security misconfiguration
- Vulnerable and outdated components
- Software and data integrity failures
  - CI/CD pipelines
  - What are they connected to?
- Server-Side Request Forgery
  - Networks behind servers?
  - Includes cloud-based network e.g. `VPC`

### Red Teaming

- A specific goal for engagements
  - To gain access and control over a network or get information from employees
  - Advanced tactics
- Knowing the common weaknesses is useful

**Red Teaming - Attacks**

- Software and data integrity failures
  - Presents a good opportunity
  - CI/CD pipelines
  - Dependency confusion
  - Developer credentials
- Server-Side Request Forgery (`SSRF`)
  - Access to corporate network?

# OWASP Top 10: API Security Playbook

**`OWASP` Top 10 vs `OWASP` API Security Top 10**

- OWASP Top 10
  - Web application specific
- OWASP API Security Top 10
  - Application Programming Interface
    - Mobile applications
    - Web applications
    - IoT
  - Overlap in vulnerabilities

**Goal of the `OWASP` API Top 10**

- Education
  > ... educate those involved in API development and maintenance
- Security throughout development lifecycle
  - Problems caught earlier
- Who is it aimed at?
  > ... developers, designers, architects, managers, or organizations

**Risk Factors - Exploitability**

| Attack Vectors | Security Weakness                           | Impacts          |
| -------------- | ------------------------------------------- | ---------------- |
| Exploitability | Weakness Prevalence, Weakness Detectability | Technical Impact |

- **Exploitability**

  - Available tools
    - Some vulnerabilities have tools to help
    - Some tools might help an attacker a little while others might automate the complete exploitation process.

- **User Interaction**

  - The need for user interaction can alter how exploitable some issues are.
  - Some vulnerabilities they are just waiting to be exploited, while others need a user to perform actions

- **Repeatability**

  - It might need circumstances outside of the control of the attacker to work.

- **Privileges**

  - Privilege might also be required.
  - The attacker might need a login to an API in order to exploit the vulnerability

- **Prevalence**

  - This shows us how common a vulnerability is.
  - Things that might impact prevalence is:
    - Lack of awareness
    - Complicated concepts
      - Something that is complicated has a much greater chance to be implemented incorrectly
  - Immature tools
    - Perhaps they don't have secure default settings or just haven't been around long enough for people to notice the issues they have.
  - Lack of time
    - If security features take time to implement, then they are less likely to get done.

- **Detectability**

  - Tells us how easy it is to find a vulnerability.
  - Vulnerabilities that are harder to detect might still have tools, or generate false positives, meaning they might have to be verified often manually.
    - This means less detectable vulnerabilities are likely to need brainpower to find them. The more skilled the attacker, the more likely they are to find the vulnerability.

- **Technical Impact**

  - CIA triad

    - Confidentiality
    - Integrity
    - Availability

  - Technical impacts are typically grouped into confidentiality, integrity and availability, also known as the `CIA` triad. Confidentiality and integrity typically refer to data, and the impact on confidentiality means information that wasn't intended to be shared has been exposed. An example is one user having access to data belonging to another user. An impact on integrity means that data has been changed when the change shouldn't have been allowed.
  - An impact on availability means that something has been made unavailable.

## Broken Object Level Authorization

This means that the authorization applied to data isn't being done as it should. This leads to access being granted when it shouldn't be.

What does it mean `Broken Object Level Authorization`?

- Broken Object Level Authorization has in the past known as Insecure direct object reference (`IDOR`)
- Object
  - A value or group of values

### Attacking

- 1st - Exploitability

  - Easy to exploit
    - It's generally easy to exploit this vulnerability once it's been found. All an attacker needs to do is change an identifier in a request, and they've potentially got access to objects they shouldn't be accessing.

- 2nd - Prevalence

  - Very common
    - This is a very common vulnerability
  - Linked to API functionality
  - Why so Prevalent?
    - The first big reason is that the security control simply hasn't been implemented.
    - Lack of authorization
      - No code exists to perform Checks
    - Human error
      - People make mistakes E.g. in an API mixing sensitive and non-sensitve data

- 3rd - Detectability

  - Difficult for tools
    - Automated tools wouldn't normally find this, as it tends to take a least a little bit of brain power.
  - Easy for humans
  - Steps:
    1. Find the ID
       - URL
       - Body
       - Headers
       - Name?
    2. Interpret response
       - Authorzed
       - Not authorized
       - Not found
  - Technical impact
    - If object level authorization is broken, then a lot of bad things can happen
  - `Burp Suite` tool that can help to rapidly make API calls with guesses for what object IDs are.

### Defense 1

- The first defense is to use unpredictable IDs.

- Predictable IDs

  - Consecutive integers
  - Predictable patterns
  - File names

- Unpredictable IDs
  - GUIDs
    - fd31faasd-fas13fd-fa3sd-fasd31-f13asd21
    - Hard to guess
    - Not sequential

### Defense 2

- Check authorization
  - User entered ID
  - Don't trust user input
  - Confirm authorized access
- Automated testing
  - Check it works
  - Notify when broken

## Broken User Authentication

### Understanding Broken Authorization

- Common vulnerabilities

  - Logging in
  - Password storage
  - JSON Web Tokens (JWTs)
  - API keys

- **What is authentication**

  - Logging in
  - Other factors, E.g. Mobile devices

- **Authentication**

  - Who you are

- **Authorization**
  - What you're allowed to do

#### Authentication Components

- Account creation

  - Password storage
  - Leak existing usernames

- Logging in
- Credential recovery
- Multi-factor
- Access token

- Risk Factors
  - Exploitability: Large surface area
  - Prevalence: Complicated implementation, even if using a third-party
  - Detectability: Client and server side. Often needs a little thought
  - Impact: Information exposure to account takeover

### Insecure Password Storage

- Should be a secret

  - Hidden on client entry
  - Encrypted in transit using TLS (https)
  - Securely stored

- Storing Passwords Badly

  - Plain text
  - Staff can see it
  - External attackers
    - Use another vulnerability

- Defense - Hashing

  - Cryptographic hash

    - String that represents the password
    - Can't be reversed
    - We don't know the secret

  - Not encryption
    - Encryption can be reversed
    - We know the secret

### Credential Stuffing

The attacker takes advantage of whatever that vulnerability is and uses it to retrieve all the stored credentials.

- Defense

  - Additional information
    - Multi-factor authentication (`MFA`)
      - Something yo know
      - Something you have
      - Something you are
    - Defeat automation
      - CAPTCHA

### JSON Web Token (JWT)

- Result of success login
- Temporary credentials
- Short expiry

- Failures

  - Expiry time (exp)
  - They often expire after 10 or 20 minutes

- JWT Signratures

  - Created by the API
  - Header + payload
    - Server-side secret

- Defense
  - Validate expiry time (exp)
  - Validate algorithm (alg)
  - Re-generate and check signature

### API Keys

- Attacks

  - Key exposure
  - Weak storage
    - Hard coded in source
    - Hard coded in config
  - Exposed in client application
  - Risk in application dependent
    - Analytics API is acceptable
    - Payments API is bad

- Defense
  - Not in source code
  - Not in client applications
  - Message singing

## Excessive Data Exposure

Useful or excessive?

- Excess records

  - Get users
  - Users belongs to an organization
  - Get users in my organization

- `PII` (Personal Identifiable Information)
  - Confidential

### Attack

- **Exploitability**

  - Data is `invisible` to the user
  - That data can be seen
    - Browser developer tools
    - Slightly more effort on mobile
  - All you have to do is look

- **Prevalence**

  - Very common
  - Assumption no-one will look
  - Tooling enables rapid development
    - Added fields would be exposed
  - Done intentionally
    - Might be useful in the future
    - Save on development time

- **Detectability**

  - Not easy for automated tools
  - Very easy for people

- **Technical Impact**

  - Exposed data
  - Account takeover
  - Laws and regulations
  - `PII` (Personal Identifiable Information)
    - Identity theft
    - Fraud

### Defense

- Control data leaving the server

  - What data can be used when
    - `PII` (Personal Identifiable Information)
    - Sensitive
    - Confidential
  - Additional code

- **Returning Objects**

  - Not just removing / blanking data
  - Schema for each endpoint
  - Filtering fields on the server

## Lack of Resources and Rate Limiting

- Throttling requests
- Simultaneous requests are expected
- Each API request uses resources
- Too many requests cause problems

### Attack

- **Exploitability**

  - Making requests is enough
  - Usually from authenticated users
  - Load test tools
    - E.g. `JMeter`
    - From a single machine
    - From multiple machines

- **Large File Upload**

  - Upload feature
  - Strain on resources
  - Disk space
  - Memory (`RAM`)

- **Password Brute Force**

  - Incorrect password
    - Several tries
    - Is it really the user?
  - Unlimited guesses
    - Automated tools
    - Common password lists

- **Query Parameter Tampering**

  - Request large amount of records
  - Filter records
  - Page size
  - Complex database queries = poor performance

### Rate Limiting Risks

- **Prevalence**

  - Occurs in a variety of ways
  - Load testing
    - Put API under load
    - Highlight potential problems

- **Detectability**

  - Common failure points
    - Invalid passwords
    - File uploads
    - Data queries
  - Slow response

- **Technical Impact**

  - Denial of service (`DoS`)
  - Slow responses
  - Overwhelmed database
  - Denial of wallet

### Rate Limiting Defense

- Request throttling
  - Limit requests in a time period
  - Error if exceeded - HTTP `429`
- Request throttling in the cloud
  - Azure API management
  - AWS API gateway
- Authenticated users are easily throttled
- Anonymous users can be harder

- **Defense - Authentication**

  - Anonymous access to authentication
  - Limit number of login attempts
    - 3-5 guesses before locking
  - Lock account
    - Minimum should be minutes
    - Maximum should be contact admin

- **Defense**

  - File upload defense
    - Config to limit request size
    - Use caution if increasing
  - Page query defense
    - Works only when trusting user input
    - NEVER trust input
    - Validate maximum page size
  - Input validation on all fields from client

## Broken Function Level Authorization

What is broken function level authorization?

- Similar to broken object level authorization
- Function level

  - API endpoints
  - Consists of a name and verb
  - `GET` user

### Attack

- **Exploitability**

  - May not be simple
  - Understand what a request looks like
    - `JSON`
    - Query parameters
  - Get records
    - No content for a list
    - ID for single record
  - Create records
    - Need to know field names

- **Prevalence**

  - Can be missing completely
  - Authorization checks
    - Hard coded
    - Configured
  - Complexity causes problems

- **Detectability**

  - Normally RESTful
    - What each verb does
    - Common URL format
    - `GET` / user
    - `GET` / user / 123456
  - Easier to guess
    - `/admin`
    - Tools to help

- **Technical Impact**

  - Depends on the endpoints
    - `/admin` is a common target
    - allows a user more:
  - Control of data
    - functionality

### Defense

- Hiding endpoints doesn't work
- Role based access

  - Admin, user, etc...
  - Assign roles to users
  - Roles access endpoints

- **Subject-object-action**

  - Subject: `Admin`
  - Object: `User`
  - Action: `Create`, `Update`, `Delete`

- **Implementing Role Based Access**

  - Subject-object-action
    - Multiple records for each role
    - Access denied without a record
  - Secure Coding: Preventing Broken Access Control
  - Automated testing
    - New endpoints automatically included
    - Granted access should work
    - All others should fail

## Mass Assignment

What is mass assignment?

- Endpoints you can access
- API calls include data
- Data converted to objects in API
  - Automatic binding
- Attacker can add fields to data
  - Object might contain additional fields

### Attack

- **Exploitability**

  - Find valid fields
  - Endpoints we can already access
  - Which fields?
    - Something the API uses
    - Not just stored
  - How to find them
    - Guess using tools
    - Documentation
    - Ask the API

- **Prevalence**

  - Automatic binding is very common
  - Simple, re-usable code
    - Still need thought to security
    - Binding single object on multiple endpoints

- **Detectability**

  - Not easy to detect
  - Need to try additional fields
  - Effect might not be obvious

- **Technical Impact**

  - Add or update properties
  - API dependent

### Defense

- Block field names
  - Block `role`
  - Update on new fields
- Allowed field names
  - Secure by default
- Differ per endpoint, e.g.

  - Create is admin only, allows role
  - Admin update allow role
  - Regular user update doesn't allow role

- Class defines endpoints object
  - Specific to the endpoint
  - Binding only those fields
- More effort to manage object

## Security Misconfiguration

What is security misconfiguration?

- Something is vulnerable
- Software can be:
  - Insecure to start
    - Should be secure by default
    - Features disabled
  - Made insecure
  - Become vulnerable
- Configuration can be complicated

- **Areas of Risk**

  - Any level of an application stack
    - Network services
    - Operating system
    - Web server
    - Frameworks
    - Database
    - Virtual machines
    - Containers
    - Etc

- **Exploitability**

  - Large surface area

- **Prevalence**

  - Very common

- **Detectability**

  - May be tools to assist

- **Impact**

  - Information exposure to server compromise

### CORS

- Cross origin resource sharing
- Used by browsers
- JavaScript requests
- Same origin policy

- **CORS Headers**

  - Make a hole in the SOP
  - Access-Control-Allow-Origin
    - Allow access to other domains
    - Can be `*`
  - Access-Control-Allow-Credentials
    - `True` / `False`
    - Is request allowed with credentials

- **CORS Failure**

  - Allowing access to other domains
  - Access-Control-Allow-Origin: `*`
    - Not allowed with credentials
  - Request
    - Origin header
  - Response
    - Access-Control-Allow-Origin: `{Origin}`

- **Attack**

  - Malicious website
    - User must be logged in to API
    - Make an API request
    - Attach credentials
    - View response content

- **Defense**

  - Don't use source origin header
  - Implement an allowed domain list
    - Maintain a list of domains
    - Consult on each request
    - Add to Access-Control-Allow-Origin
  - Requires code

### Common Security Misconfiguration

- **Unused Components**

  - Installed by default
  - No longer useful
  - Adds to security surface area
  - Increased complexity to Maintain

  - Which components?
    - Operating system
      - FTP, Telnet, SSH
    - Additional software
      - web servers, databases, remote desktop services
    - Code dependencies
      - Packages, libraries, open-source libraries

- **Missing Security Patches**

  - Patch management process
    - Inventory of versions and components of all the software that you use
    - Monitor for vulnerabilities
    - Move away from unmaintained software
  - Not always simple
    - Not everything can update itself
    - Simplify where possible
    - Remove anything unused

- **TLS**

  - Transport layer security
    - Secure sockets layer (`SSL`)
    - Encrypts web traffic
    - Various versions
  - Potential Problems
    - Can be missing
    - Lots to configure

- **Verbose Errors**

  - Uncaught errors
  - Verbose output
    - Connection strings
    - Stack traces
  - Can be useful in development
  - Disable in production
    - Enable generic errors
    - Handle them correctly

- **Security Headers**

  - Contained in API responses
  - Information headers (recommended to remove)
    - server: `Microsoft-ISS/10.0`
    - `x-powered-by: ASP.NET`
  - Security headers
    - CORS
    - Strict-Transport-Security

## Injection

> Injection is an attacker's attempt to send data to an application in a way that will change the meaning of the command being sent to an interpreter

What is injection?

- What is an interpreter?
  - Executes instructions
  - Specific syntax
- A browser interprets instructions
  - HTML
  - CSS
  - JavaScript
- Web pages allow interaction
  - Control over the HTML from the server
  - Form the basis of an attack

### Attack

- **Exploitability**

  - Malicious requests to interpreter via API
  - Usually from authenticated users
  - What software the interpreter uses
  - What version is running
  - Vulnerability might not be in the API

- **SQL Injection**

  - Using the SQL language
  - Code creates a SQL command for the database

- **NoSQL Injection**

  - Becoming a lot more common
  - No standing syntax
  - Often support scripting

- **HTML Injection**

  - APIs don't usually respond with HTML
  - JavaScript calls the API
  - Inserts response into the page

### Injection Risks

- **Prevalence**

  - Database injections
    - SQL
    - NoSQL
  - Operating system command injection
  - HTML injection
  - XML injection

- **Detectability**

  - Can be detected by a human
  - Much easier using automation
    - Inject common strings
    - Asses lots of fields and endpoints
  - Injection might cause errors
    - API then return errors
    - Detailed errors help attackers
  - Database injection
    - Return excess data
    - Pause operation

- **Technical Impact**

  - Can do what the interpreter can
  - Database queries
    - Data from any table
    - Delete tables
    - Run operating system commands
  - OS command injection calls the OS
  - HTML injection might allow account access

### Injection Defenses

- **Input Validation**

  - Validate all inputs
  - Focus on strings
    - Check length
    - What characters should be allowed?
    - Create an allow list of characters

- **Sanitize Input**

  - Replace characters or strings
    - `<script>`
    - Replace part or all of it
  - Which interpreter is this aimed at?
  - Use a library

- **Encoding**

  - Injected HTML
    - `<a href="malicious.url"></a>`
  - Encoding
    - `&lt;a href="malicious.url"&gt;&lt;/a&gt;`
    - Not valid HTML
    - Other content not altered
  - Various types of encoding
    - URL, CSS, JSON, etc

- **SQL Injection**

  - Don't concatenate string
    - Manually creating SQL increases risks
  - Elements of a query
    - Query syntax
    - Parameters
  - Parameterized queries

- **SQL Defenses**

  - Object relational mapper (`ORM`)
    - Returns data as objects
    - Queries handle parameters for you
  - Store procedures
    - Declared in the database
    - Calling a method with parameters

- **Web Application Firewall (`WAF`)**

  - Designed to prevent injection
  - API traffic goes to `WAF`
    - Rejected if malicious
    - Forwarded to your server
  - Not perfect

## Improper Assets Management

What is assets do you have?

- Environments

  - Copies of the environments
    - Dev
    - QA / test
    - Demo
    - Pre-Production
    - Etc
  - Versions of the API

- **Potential Assets**

  - Shared resources
    - Network
    - Database
      - Production data
    - Credentials
  - Across environments
  - Across versions

### Attack

- **Environments**

  - Best security in the newest environment
    - Stronger defenses e.g. firewall
  - Weaker environments
    - Information gathering
    - Access to shared resources

- **API Versions**

  - Newer versions have better security
    - More recently tested
    - Fixed vulnerabilities

- **Prevalence - Environments**

  - Multiple API environments are common
  - A common way to work
  - Environments can cost very little
  - Small cost can beman lack of security
  - Environments can share components

- **Prevalence - API Versions**

  - New API versions introduce new functionality
  - Old versions still work
    - Lots of customers
    - Difficult to move them to new API
  - Pressure to keep old versions
  - Reluctance to maintain old versions

- **Detectability - Environments**

  - Using sub-domains is common
    - `test.globmantics.com`
    - `dev.globmantics.com`
  - Where to find environments
    - Documentation
    - Code that calls the API
    - Web pages
  - Internet repositories
    - DNS records
    - TLS records

- **Detectability - API Versions**

  - Versions can be easier to find
    - Version number in URL
    - May be in request header

- **Impact**

  - Might allow:
    - Gathering information
    - Bypass defenses like firewalls
    - Access via old, vulnerable code
  - Server compromise
  - Database breach

### Defense

- Know your surface area
  - Environments
  - API versions
- Assess risks

  - Data
  - Resources
  - Existing controls

- **Environments**

  - Don't share production data
  - Don't share resources
  - Production will require access from the internet
  - Other environments might not
    - Host internally?
    - Restrict access by IP address
  - Do you need all the environments?

- **API Versions**

  - Get rid of old versions
  - If you do keep them
    - Maintain them
    - Consider security
    - Apply patches
    - Match current version where possible

## Insufficient Logging and Monitoring

What is Insufficient Logging and Monitoring?

- Detective controls
  - Happen often actions
  - Help you to look at the actions
- Doesn't stop attacks
- Enables response to attacks

- **Logging**

  - When: `Date and time`
  - Where: `The application, code location, API endpoint, etc`
  - Who: `User identity, source (e.g. IP address)`
  - What: `Description, flags to allow grouping`

- **Monitoring**

  - Identify malicious activity
  - Centralized repository
  - Start with a baseline
  - Identify increases above baseline
  - Create alert

### Effects of Insufficient Logging

- **Exploitability**

  - No real attack
  - Attacks won't be noticed
    - Leads to more problems
  - Noticing attacks allows you to:
    - Slow them down
    - Make them less impactful
    - Stop them

- **Prevalence**

  - Logging can be complicated
    - Too much is hard to use and expensive
    - Too little skips valuable information
    - Just right takes experience
  - Sometimes there's no monitoring

- **Breach Detection**

  - Time in days to detect a breach by industry

- **Detectability**

  - How does an attacker know?
  - Would need access to logs

- **Impact**

  - Attacks go unnoticed
  - Hard to see what attackers have done

### Defense

- Know when we're under attack
- Log the right things
  - `OWASP` API Top 10 entries
- Assess what happened in an attack

- **Areas to Log**

  - Authentication

    - Success and failure
    - We want to log when people log in correctly and when they fail
    - Increases in these might indicate credential stuffing or credential guessing attacks
    - Forgotten password, would be useful too

  - Access control
    - Failures
    - Can be used to highlight attacks where someone is trying to identify API endpoints that might missing protections
  - Input validation
    - Server-side
      - Can hightlight an attacker trying to probe for injection-type vulnerabilities
  - Sessions
    - Token modification
    - Here an attacker might try to modify cookies or JSON Web Token
    - If invalid session are presented, this is a good thing to log
  - High value
    - If your API has a concept of high-value transactions
    - Someone making payments
    - Admin being Created

- **Test the Solution**

  - Penetration tests
    - Perform realistic attacks
  - Check logging and monitoring
  - Get some hacking skills
