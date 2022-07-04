<h1 id='table-of-contents'>Table of Contents</h1>

- [Open Web Application Security Project - OWASP](#open-web-application-security-project---owasp)
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
- [OWASP Top 10: API Security Playbook](#owasp-top-10-api-security-playbook)

# Open Web Application Security Project - OWASP

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
