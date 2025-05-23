# Keyword-Tracker
A simple Python app to organize and analyze app store reviews. Quickly sort feedback into categories, find keyword trends, and generate detailed Excel reports, all with just a few clicks. Easy to use, offline, and built to save you time.

## Features

- Keyword-based classification of app reviews
- Automatic frequency analysis of repeated keywords
- Simple and intuitive GUI interface for input
- Clean Excel export with structured categories
- Deduplicates and cleans keyword inputs
- Supports dynamic categories and phrases
- Designed for marketing, QA, and product teams

## Technologies Used

- Python 3
- pandas
- openpyxl
- tkinter (GUI)

## Installation
- Clone the repository
- Create a virtual environment (optional but recommended)
- Install the required packages

## Steps to Use
- Copy the <a href="https://github.com/CoX2682/Movie-Data-Analysis-Dashboard/blob/main/Data.xlsx">Script</a>
- You will see multiple input fields for various review categories (e.g., Appreciation, Complaint, Support, Pricing).
- Enter keyword phrases for each category (separated by commas).
-- For example: expensive, poor, bad support.
- Extend or replace the keyword cleaning logic as needed.
- After filling out your categories, run the script.
- A GUI window will appear.
- Copy reveiews from playstore in bulk and paste.
- The output Excel file will be saved in the same folder as output.xlsx.

## Customization
- You can easily customize:
- Keyword categories in the categories list
- Response templates in RESPONSE_MAP
- General categories in GENERAL_CATEGORIES

## Report includes:
- Review analysis with categorization
- Found keywords by category
- Unmatched keywords
- Keyword frequency analysis

## Requirements
- Python 3.6+
- pandas
- tkinter (usually included with Python)

## Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes.

## Contact
Have suggestions or feedback? Feel free to open an issue or reach out via GitHub discussions.

