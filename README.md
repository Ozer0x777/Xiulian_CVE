# Xiulian_CVE
The Xiulian_CVE script is a tool that allows you to search for active vulnerabilities for a specified operating system. It uses the National Vulnerability Database (NVD) API to fetch information about known vulnerabilities.

The script takes into account the severity of vulnerabilities and allows you to specify the number of active vulnerabilities to display. It also supports saving the results to a CSV file.
Key Features:

   Search for active vulnerabilities for a given operating system
   Filter vulnerabilities by severity
   Display a specified number of active vulnerabilities
   Save results to a CSV file
   

Before using the script, you need to sign up for an API key from the NVD website. This API key is required to access the NVD API and retrieve vulnerability data.


## Prerequisites

To use this script, you will need:

   Python 3.6 or above
   API key from the National Vulnerability Database (NVD)
   requests
   argparse
   python-dotenv
   csv

### Installation

   Clone the repository:

    git clone https://github.com/your-username/Xiulian_CVE.git

   Navigate to the project directory:

    cd Xiulian_CVE

Install the required dependencies:

    pip install -r requirements.txt

### Usage

python Xiulian_CVE "Operating System Name" severity [--count N] [--output CSVFile]

   Operating System Name: Name of the operating system to search vulnerabilities for (e.g., "Windows 10", "Ubuntu 20.04", etc.).
   severity: Severity level of vulnerabilities to display. Valid values: "low", "medium", "high", "critical", "all".
   --count N (optional): Number of vulnerabilities to display (default: 10).
   --output CSVFile (optional): Path to the CSV file to save the results.
    
## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository.

## License

[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](http://www.wtfpl.net/about/)
    
