# Free URL-Shortner ✂️

# Flask URL Shortener

This is a simple URL shortener web application built using Flask, SQLAlchemy, and WTForms. It allows users to register, log in, shorten URLs, and view their shortened URLs. The application also logs requests and sends them to a Discord webhook for monitoring.

## Features

- User registration and authentication
- URL shortening
- Logging of user requests
- Integration with Discord webhook for monitoring

## Prerequisites

Before you begin, ensure you have met the following requirements:
- Python 3 installed on your local machine
- Git installed on your local machine
- A Discord account to create a webhook

## Installation

To install and run this project locally, follow these steps:

1. Clone the repository to your local machine:<br />
   `git clone https://github.com/your_username/flask-url-shortener.git`
2. Navigate to the project directory:<br />
   ``cd URL-Shortner``

3. Install the required Python packages:<br />
   ``pip install -r requirements.txt``


4. Set up a Discord webhook and copy the URL.

5. Create a `config.json` file in the project directory with the following content, replacing `<webhook_url>` with your Discord webhook URL:

```json
{
    "app.register.info": "discord-webhook",
    "app.logger.info": "discord-webhook",
    "app.URLShortened.info": "discord-webhook"

}
```
## Usage
Run the Flask application:<br />
`python app.py`

Open your web browser and navigate to http://localhost:5000 to access the application.

Register an account or log in if you already have one.

Shorten URLs using the form provided.

View your shortened URLs and copy them for sharing.



## Contributing
Contributions are welcome! If you would like to contribute to this project, please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature/new-feature).
Make your changes.
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature/new-feature).
Create a new Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contact
If you have any questions or suggestions, feel free to contact me at Mahbodfl1@gmail.com

``good luck (; 🌙``<br />
``for life``<br />
``fl``



