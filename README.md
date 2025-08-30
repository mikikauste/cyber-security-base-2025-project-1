# Cyber Security Base 2025 Project I

This is the [first project](https://cybersecuritybase.mooc.fi/module-3.1) of University of Helsinki's Cyber Security Base course series. The idea of the project is to construct software with security flaws, point out the flaws and provide fixes to them. The project is implemented using Python & Django.

## Instructions
1. Follow the instuctions on https://cybersecuritybase.mooc.fi/installation-guide to install necessary dependencies
2. Clone this repository
3. To run the migrations and start the development server, cd to the the project root and run the following commands in this order:
- `python manage.py makemigrations`
- `python manage.py migrate`
- `python manage.py runserver`
4. Access the application by navigating to `http://localhost:8000` in your browser


## Flaws selected to the project
This project covers 4 flaws selected from [OWASP 2021 top ten list](https://owasp.org/www-project-top-ten/) and CSRF flaw, which is not found on the OWASP list. The suggested fixes to the flaws are commented in the source code and can also be found in the screenshots folder.

### Flaw 1 - A03:2021-Injection
https://owasp.org/Top10/A03_2021-Injection/

### Flaw 2 - A05:2021-Security Misconfiguration
https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

### Flaw 3 - A07:2021-Identification and Authentication Failures
https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

### Flaw 4 - A09:2021-Security Logging and Monitoring Failures
https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/

### Flaw 5 - Cross Site Request Forgery (CSRF)
Not on the OWASP list, but allowed as a flaw due to its fundamental nature